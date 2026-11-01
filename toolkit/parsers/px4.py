"""PX4 ULog flight log parser.

Extracts a normalized timeline (ARM/DISARM, flight-mode changes, status
text) and a GPS-referenced flight path from PX4 `.ulg` logs via pyulog.

A few PX4-specific realities shape this implementation (discovered by
inspecting a real sample log, not assumed):

- PX4 ULog message timestamps are microseconds. Whether they are
  wall-clock ("UTC") or boot-relative depends on whether the flight
  controller had a UTC time reference (GPS fix or synced RTC) at log
  time — recorded in `ULog.msg_info_dict["time_ref_utc"]`. When that is
  0 (no reference — e.g. an indoor/bench log with no GPS fix, as in this
  project's sample), there is no way to recover true wall-clock time
  from the file alone. This mirrors an existing, accepted limitation in
  `toolkit/parsers/ardupilot.py`'s `_iso()`, which has the identical
  problem for dataflash logs without GPS-derived epoch time — we still
  emit ISO-8601 strings (seeded at the Unix epoch) so events remain
  sortable/displayable, and flag the missing reference in `warnings`
  rather than silently presenting boot-relative time as if it were real.
- Not every PX4 log carries a georeferenced GPS/global position topic
  (this project's sample does not: no `vehicle_gps_position`, and
  `vehicle_local_position`'s `xy_global`/`ref_lat` are never valid in
  it — likely an indoor/no-GPS-fix flight). `flight_path` is only
  populated from samples where the local-to-global reference is
  actually valid; when none are, it comes back empty with a warning,
  rather than fabricating coordinates from unreferenced local NED data.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path

import pyulog

from toolkit.core.timeline import TimelineEvent
from toolkit.parsers.base import BaseParser, ParserError, ParserResult

EARTH_RADIUS_M = 6371000.0

# PX4 commander nav_state values -> names. PX4's NAVIGATION_STATE_*
# enum numbering has changed across firmware versions historically
# (entries added/removed), so only the handful of low values that have
# stayed stable across versions are asserted here; unrecognized values
# fall back to "MODE_<n>" rather than guessing at a full enum table.
NAV_STATES = {
    0: "MANUAL", 1: "ALTCTL", 2: "POSCTL", 3: "AUTO_MISSION",
    4: "AUTO_LOITER", 5: "AUTO_RTL",
}

# vehicle_status.arming_state PX4 enum (subset we rely on).
ARMING_STATE_ARMED = 2


def _haversine_m(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def _iso(ts_us) -> str:
    """Convert a PX4 ULog microsecond timestamp to an ISO-8601 UTC string.

    See module docstring: this is only true wall-clock time when the log
    has a UTC time reference; otherwise it is boot-relative time rendered
    against the Unix epoch, same limitation as ardupilot.py's `_iso`.
    """
    return datetime.fromtimestamp(ts_us / 1_000_000.0, tz=timezone.utc).isoformat()


def _local_to_latlon(ref_lat, ref_lon, x, y):
    """Flat-earth conversion of local NED (x=north, y=east) offsets in
    metres, plus a georeference lat/lon, into an approximate lat/lon.
    """
    lat = ref_lat + (x / EARTH_RADIUS_M) * (180.0 / math.pi)
    lon = ref_lon + (y / (EARTH_RADIUS_M * math.cos(math.radians(ref_lat)))) * (180.0 / math.pi)
    return lat, lon


def _dataset(ulog, name):
    try:
        return ulog.get_dataset(name)
    except (KeyError, IndexError, ValueError):
        return None


class PX4Parser(BaseParser):
    platform_name = "px4"

    def can_parse(self, evidence_path: Path) -> bool:
        return evidence_path.suffix.lower() == ".ulg"

    def parse(self, evidence_path: Path) -> ParserResult:
        try:
            size = evidence_path.stat().st_size
        except OSError as exc:
            raise ParserError(
                f"Could not open '{evidence_path.name}' as a PX4 ULog: {exc}. "
                f"File may be missing or unreadable."
            ) from exc

        if size == 0:
            raise ParserError(
                f"Could not open '{evidence_path.name}' as a PX4 ULog: file is empty."
            )

        events: list[TimelineEvent] = []
        flight_path: list[dict] = []
        warnings: list[str] = []
        flight_summary: dict = {}

        # pyulog.ULog opens the path itself when given a string and only
        # closes its internal file handle on the success path — if header
        # parsing raises partway through, that handle leaks. Pass an
        # already-open file object instead so we control closing it
        # ourselves in a finally block regardless of what pyulog does.
        fh = evidence_path.open("rb")
        try:
            ulog = pyulog.ULog(fh)
        except Exception as exc:  # noqa: BLE001 - any parse failure is non-fatal here
            warnings.append(
                "Log file could not be read as valid PX4 ULog data (corrupt or "
                f"unreadable) — no messages could be extracted: {exc}."
            )
            return ParserResult(
                platform=self.platform_name,
                events=events,
                flight_summary=flight_summary,
                flight_path=flight_path,
                warnings=warnings,
                implemented=True,
                partial=True,
            )
        finally:
            fh.close()

        try:
            firmware = ulog.get_version_info_str()
            if firmware:
                firmware = f"PX4 v{firmware.lstrip('v')}"
        except Exception:  # noqa: BLE001 - version info is best-effort
            firmware = None

        has_utc_ref = bool(ulog.msg_info_dict.get("time_ref_utc", 0))
        if not has_utc_ref:
            warnings.append(
                "PX4 ULog has no UTC time reference (no GPS/RTC time sync at log "
                "time); event timestamps are boot-relative, not true wall-clock "
                "time."
            )

        # --- Flight path (GPS/global-referenced position) ---------------
        prev_point = None
        total_distance_m = 0.0
        pos_ds = _dataset(ulog, "vehicle_local_position") or _dataset(ulog, "estimator_local_position")
        if pos_ds is not None:
            d = pos_ds.data
            n = len(d.get("timestamp", []))
            has_global_flags = "xy_global" in d and "z_global" in d
            ref_lat_arr = d.get("ref_lat", [float("nan")] * n)
            ref_lon_arr = d.get("ref_lon", [float("nan")] * n)
            ref_alt_arr = d.get("ref_alt", [None] * n)
            for i in range(n):
                ref_lat = ref_lat_arr[i]
                ref_lon = ref_lon_arr[i]
                if has_global_flags and not (d["xy_global"][i] and d["z_global"][i]):
                    continue
                if ref_lat != ref_lat or ref_lon != ref_lon:  # NaN check
                    continue
                ref_alt = ref_alt_arr[i]
                if ref_alt is not None and math.isnan(ref_alt):
                    continue
                x, y, z = d["x"][i], d["y"][i], d["z"][i]
                lat, lon = _local_to_latlon(ref_lat, ref_lon, x, y)
                alt = (ref_alt - z) if ref_alt is not None else -z
                iso_ts = _iso(d["timestamp"][i])
                flight_path.append({
                    "timestamp_utc": iso_ts, "latitude": lat,
                    "longitude": lon, "altitude_m": alt,
                })
                if prev_point is not None:
                    total_distance_m += _haversine_m(prev_point[0], prev_point[1], lat, lon)
                prev_point = (lat, lon)

        max_alt_m = max((p["altitude_m"] for p in flight_path), default=None)

        # max speed: prefer the local-position velocity vector, which is
        # real telemetry independent of whether the position has a valid
        # global (GPS) reference.
        max_speed_ms = None
        if pos_ds is not None:
            d = pos_ds.data
            if all(k in d for k in ("vx", "vy", "vz")):
                for vx, vy, vz in zip(d["vx"], d["vy"], d["vz"]):
                    speed = math.sqrt(vx * vx + vy * vy + vz * vz)
                    max_speed_ms = speed if max_speed_ms is None else max(max_speed_ms, speed)

        if not flight_path:
            warnings.append(
                "No GPS/global-referenced position found in log (vehicle may "
                "never have had a valid GPS fix, or the log only contains "
                "local-only position estimates); flight path is empty."
            )

        # --- ARM/DISARM ----------------------------------------------------
        arm_count = 0
        disarm_count = 0
        armed_ds = _dataset(ulog, "actuator_armed")
        status_ds = _dataset(ulog, "vehicle_status")
        if armed_ds is not None and "armed" in armed_ds.data:
            ts_arr = armed_ds.data["timestamp"]
            armed_arr = armed_ds.data["armed"]
            source_label = "actuator_armed.armed"
        else:
            if status_ds is not None and "arming_state" in status_ds.data:
                ts_arr = status_ds.data["timestamp"]
                armed_arr = [v == ARMING_STATE_ARMED for v in status_ds.data["arming_state"]]
                source_label = "vehicle_status.arming_state"
            else:
                ts_arr, armed_arr, source_label = [], [], None

        prev_armed = None
        for ts, armed_val in zip(ts_arr, armed_arr):
            cur = bool(armed_val)
            iso_ts = _iso(ts)
            if prev_armed is None:
                if cur:
                    arm_count += 1
                    events.append(TimelineEvent(
                        timestamp_utc=iso_ts, source="px4.ulog",
                        event_type="ARMED",
                        description=(
                            "Vehicle recorded as already armed at start of "
                            "log (log begins after arming, or the original "
                            "arm event predates the recorded log)."
                        ),
                    ))
            elif cur != prev_armed:
                if cur:
                    arm_count += 1
                    events.append(TimelineEvent(
                        timestamp_utc=iso_ts, source="px4.ulog",
                        event_type="ARMED", description="Vehicle armed",
                    ))
                else:
                    disarm_count += 1
                    events.append(TimelineEvent(
                        timestamp_utc=iso_ts, source="px4.ulog",
                        event_type="DISARMED", description="Vehicle disarmed",
                    ))
            prev_armed = cur

        if arm_count == 0:
            warnings.append("No ARM event found in log.")

        # --- Flight mode changes (nav_state) --------------------------------
        if status_ds is not None and "nav_state" in status_ds.data:
            prev_nav = None
            for ts, nav_state in zip(status_ds.data["timestamp"], status_ds.data["nav_state"]):
                nav_state = int(nav_state)
                if prev_nav is not None and nav_state != prev_nav:
                    name = NAV_STATES.get(nav_state, f"MODE_{nav_state}")
                    events.append(TimelineEvent(
                        timestamp_utc=_iso(ts), source="px4.ulog",
                        event_type="MODE_CHANGE",
                        description=f"Flight mode changed to {name}",
                        extra={"nav_state": nav_state},
                    ))
                prev_nav = nav_state

        # --- Status text -----------------------------------------------------
        for msg in ulog.logged_messages:
            events.append(TimelineEvent(
                timestamp_utc=_iso(msg.timestamp), source="px4.ulog",
                event_type="STATUS_TEXT", description=msg.message,
                extra={"log_level": msg.log_level_str()},
            ))

        events.sort(key=lambda e: e.timestamp_utc)

        start_ts = ulog.start_timestamp
        end_ts = ulog.last_timestamp
        duration_s = (end_ts - start_ts) / 1_000_000.0 if (start_ts is not None and end_ts is not None) else None

        flight_summary = {
            "firmware": firmware,
            "start_time_utc": _iso(start_ts) if start_ts is not None else None,
            "end_time_utc": _iso(end_ts) if end_ts is not None else None,
            "duration_s": duration_s,
            "max_altitude_m": max_alt_m,
            "max_speed_ms": max_speed_ms,
            "total_distance_m": round(total_distance_m, 1),
            "arm_count": arm_count,
            "disarm_count": disarm_count,
            "gps_track_points": len(flight_path),
        }

        return ParserResult(
            platform=self.platform_name,
            events=events,
            flight_summary=flight_summary,
            flight_path=flight_path,
            warnings=warnings,
            implemented=True,
        )
