"""ArduPilot dataflash / MAVLink telemetry log parser.

Supports the formats pymavlink's mavutil auto-detects by extension/content:
dataflash binary logs (.bin/.BIN), dataflash text logs (.log), and MAVLink
telemetry logs (.tlog). This is the one fully implemented, end-to-end
parser in this submission — see docs/design_document.md for what other
platforms (DJI, remote controllers, mobile companion apps) still need.
"""

from __future__ import annotations

import contextlib
import io
import math
from datetime import datetime, timezone
from pathlib import Path

from pymavlink import mavutil

from toolkit.core.timeline import TimelineEvent
from toolkit.parsers.base import BaseParser, ParserError, ParserResult

# ArduCopter flight mode numbers -> names (subset covering common modes;
# unrecognized numbers fall back to "MODE_<n>" rather than failing).
COPTER_MODES = {
    0: "STABILIZE", 1: "ACRO", 2: "ALT_HOLD", 3: "AUTO", 4: "GUIDED",
    5: "LOITER", 6: "RTL", 7: "CIRCLE", 9: "LAND", 11: "DRIFT",
    13: "SPORT", 14: "FLIP", 15: "AUTOTUNE", 16: "POSHOLD",
    17: "BRAKE", 18: "THROW", 19: "AVOID_ADSB", 20: "GUIDED_NOGPS",
    21: "SMART_RTL", 22: "FLOWHOLD", 23: "FOLLOW", 24: "ZIGZAG",
}

# ArduPilot dataflash EV (event) IDs -> names (subset; see
# ArduPilot/libraries/AP_Logger/LogStructure.h for the authoritative enum).
EVENT_NAMES = {
    7: "DATA_AP_STATE", 8: "SYSTEM_TIME_SET", 9: "INIT_SIMPLE_BEARING",
    10: "ARMED", 11: "DISARMED", 15: "AUTO_ARMED", 16: "TAKEOFF",
    17: "LAND_COMPLETE_MAYBE", 18: "LAND_COMPLETE", 19: "LOST_GPS",
    21: "FLIP_START", 22: "FLIP_END", 25: "SET_HOME",
    26: "SET_SIMPLE_ON", 27: "SET_SIMPLE_OFF", 28: "NOT_LANDED",
    29: "SET_SUPERSIMPLE_ON", 30: "AUTOTUNE_INITIALISED",
    36: "FENCE_ENABLE", 37: "FENCE_DISABLE",
}

EARTH_RADIUS_M = 6371000.0

# A sustained vertical rate beyond this (m/s) is outside any normal
# multirotor/fixed-wing climb or descent and is flagged as a timeline
# anomaly — typically GPS altitude noise/multipath, but also the signature
# of GPS spoofing/jamming, so it belongs in the forensic timeline either way
# rather than being silently smoothed over.
ANOMALOUS_VERTICAL_RATE_MS = 15.0


def _haversine_m(lat1, lon1, lat2, lon2) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class ArduPilotParser(BaseParser):
    platform_name = "ardupilot"

    def can_parse(self, evidence_path: Path) -> bool:
        return evidence_path.suffix.lower() in {".bin", ".log", ".tlog"}

    def parse(self, evidence_path: Path) -> ParserResult:
        # pymavlink's mavutil prints a "bad header 0x.. at N" debug line per
        # garbage byte it skips over when the file isn't a well-formed
        # dataflash log — harmless for a real (if noisy/truncated) log, but
        # it must never reach the CLI/GUI's actual output, and it must
        # never crash acquisition analysis outright. A completely empty or
        # unopenable file raises a clear ParserError instead of pymavlink's
        # raw internal exception.
        stdout_sink = io.StringIO()
        with contextlib.redirect_stdout(stdout_sink):
            try:
                conn = mavutil.mavlink_connection(str(evidence_path))
            except (ValueError, OSError, IndexError) as exc:
                raise ParserError(
                    f"Could not open '{evidence_path.name}' as an ArduPilot log: {exc}. "
                    f"File may be empty, truncated, or corrupted."
                ) from exc

        events: list[TimelineEvent] = []
        flight_path: list[dict] = []
        warnings: list[str] = []

        firmware = None
        frame_type = None
        gps_fix_acquired_at = None
        had_gps_fix = False
        max_alt_m = None
        max_speed_ms = None
        arm_count = 0
        disarm_count = 0
        first_ts = None
        last_ts = None
        total_distance_m = 0.0
        prev_point = None
        prev_alt_sample = None  # (timestamp, altitude_m) for anomaly detection
        altitude_anomaly_count = 0
        # MAVLink live-telemetry (.tlog) HEARTBEAT state, tracked separately
        # from the dataflash EV/MODE messages above so armed/mode changes are
        # edge-triggered rather than re-emitted on every ~1Hz heartbeat.
        prev_armed = None
        prev_mode_num = None

        def _record_gps_sample(iso_ts, ts, lat, lon, alt, speed, has_fix):
            nonlocal gps_fix_acquired_at, had_gps_fix, max_alt_m, max_speed_ms
            nonlocal total_distance_m, prev_point, prev_alt_sample, altitude_anomaly_count

            if has_fix and not had_gps_fix and (lat, lon) != (0.0, 0.0):
                had_gps_fix = True
                gps_fix_acquired_at = iso_ts
                events.append(TimelineEvent(
                    timestamp_utc=iso_ts, source="ardupilot.dataflash",
                    event_type="GPS_FIX_ACQUIRED",
                    description="3D GPS fix acquired",
                    latitude=lat, longitude=lon, altitude_m=alt,
                ))

            if has_fix and (lat, lon) != (0.0, 0.0):
                flight_path.append({
                    "timestamp_utc": iso_ts, "latitude": lat,
                    "longitude": lon, "altitude_m": alt,
                })
                if prev_point is not None:
                    total_distance_m += _haversine_m(
                        prev_point[0], prev_point[1], lat, lon
                    )
                prev_point = (lat, lon)

            if alt is not None:
                max_alt_m = alt if max_alt_m is None else max(max_alt_m, alt)

                if prev_alt_sample is not None:
                    prev_ts, prev_alt = prev_alt_sample
                    dt = ts - prev_ts
                    if dt > 0:
                        vertical_rate = (alt - prev_alt) / dt
                        if abs(vertical_rate) > ANOMALOUS_VERTICAL_RATE_MS:
                            altitude_anomaly_count += 1
                            events.append(TimelineEvent(
                                timestamp_utc=iso_ts, source="ardupilot.dataflash",
                                event_type="ALTITUDE_ANOMALY",
                                description=(
                                    f"Implausible altitude change: {prev_alt:.1f}m -> {alt:.1f}m "
                                    f"in {dt:.2f}s ({vertical_rate:+.1f} m/s). Likely GPS "
                                    f"altitude noise/multipath; also consistent with GPS "
                                    f"spoofing/jamming — flagged for examiner review, not "
                                    f"auto-classified."
                                ),
                                latitude=lat, longitude=lon, altitude_m=alt,
                                extra={"prev_altitude_m": prev_alt, "vertical_rate_ms": vertical_rate},
                            ))
                prev_alt_sample = (ts, alt)

            if speed is not None:
                max_speed_ms = speed if max_speed_ms is None else max(max_speed_ms, speed)

        try:
            with contextlib.redirect_stdout(stdout_sink):
                while True:
                    msg = conn.recv_match(blocking=False)
                    if msg is None:
                        break

                    ts = getattr(msg, "_timestamp", None)
                    if ts is None:
                        continue
                    iso_ts = _iso(ts)
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)

                    mtype = msg.get_type()

                    if mtype == "MSG":
                        text = getattr(msg, "Message", "")
                        if firmware is None and any(k in text for k in ("APM:", "ArduCopter", "ArduPlane", "ArduRover")):
                            firmware = text
                        if text.startswith("Frame:"):
                            frame_type = text.split(":", 1)[1].strip()
                        events.append(TimelineEvent(
                            timestamp_utc=iso_ts, source="ardupilot.dataflash",
                            event_type="STATUS_TEXT", description=text,
                        ))

                    elif mtype == "MODE":
                        mode_num = getattr(msg, "ModeNum", getattr(msg, "Mode", None))
                        mode_name = COPTER_MODES.get(mode_num, f"MODE_{mode_num}")
                        events.append(TimelineEvent(
                            timestamp_utc=iso_ts, source="ardupilot.dataflash",
                            event_type="MODE_CHANGE", description=f"Flight mode changed to {mode_name}",
                            extra={"mode_num": mode_num},
                        ))

                    elif mtype == "EV":
                        ev_id = getattr(msg, "Id", None)
                        name = EVENT_NAMES.get(ev_id, f"EVENT_{ev_id}")
                        if name == "ARMED":
                            arm_count += 1
                        elif name == "DISARMED":
                            disarm_count += 1
                        events.append(TimelineEvent(
                            timestamp_utc=iso_ts, source="ardupilot.dataflash",
                            event_type=name, description=f"ArduPilot event: {name} (id={ev_id})",
                        ))

                    elif mtype == "ERR":
                        events.append(TimelineEvent(
                            timestamp_utc=iso_ts, source="ardupilot.dataflash",
                            event_type="ERROR",
                            description=f"Subsystem {getattr(msg, 'Subsys', '?')} "
                                        f"error code {getattr(msg, 'ECode', '?')}",
                        ))

                    elif mtype == "CMD":
                        lat, lon, alt = getattr(msg, "Lat", None), getattr(msg, "Lng", None), getattr(msg, "Alt", None)
                        events.append(TimelineEvent(
                            timestamp_utc=iso_ts, source="ardupilot.dataflash",
                            event_type="MISSION_COMMAND",
                            description=f"Mission command id={getattr(msg, 'CId', '?')}",
                            latitude=lat, longitude=lon, altitude_m=alt,
                        ))

                    elif mtype == "GPS":
                        status = getattr(msg, "Status", 0)
                        lat, lon = getattr(msg, "Lat", 0.0), getattr(msg, "Lng", 0.0)
                        alt = getattr(msg, "Alt", None)
                        speed = getattr(msg, "Spd", None)
                        _record_gps_sample(iso_ts, ts, lat, lon, alt, speed, has_fix=status >= 3)

                    # --- MAVLink live-telemetry (.tlog) message types below.
                    # A .tlog is a recorded MAVLink command/telemetry stream,
                    # not a dataflash log, so it never emits MSG/MODE/EV/GPS
                    # records above — without this branch, can_parse() claims
                    # .tlog support (and the README documents it) but every
                    # real .tlog silently produced zero events/flight path.

                    elif mtype == "HEARTBEAT":
                        # Ignore heartbeats from anything other than the
                        # vehicle's own autopilot (e.g. the GCS's heartbeat,
                        # which is also recorded in a bidirectional .tlog).
                        if getattr(msg, "autopilot", None) == mavutil.mavlink.MAV_AUTOPILOT_INVALID:
                            continue

                        armed = bool(getattr(msg, "base_mode", 0) & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
                        if prev_armed is not None and armed != prev_armed:
                            if armed:
                                arm_count += 1
                                events.append(TimelineEvent(
                                    timestamp_utc=iso_ts, source="ardupilot.mavlink",
                                    event_type="ARMED", description="ArduPilot event: ARMED",
                                ))
                            else:
                                disarm_count += 1
                                events.append(TimelineEvent(
                                    timestamp_utc=iso_ts, source="ardupilot.mavlink",
                                    event_type="DISARMED", description="ArduPilot event: DISARMED",
                                ))
                        prev_armed = armed

                        mode_num = getattr(msg, "custom_mode", None)
                        if prev_mode_num is not None and mode_num != prev_mode_num:
                            mode_name = COPTER_MODES.get(mode_num, f"MODE_{mode_num}")
                            events.append(TimelineEvent(
                                timestamp_utc=iso_ts, source="ardupilot.mavlink",
                                event_type="MODE_CHANGE", description=f"Flight mode changed to {mode_name}",
                                extra={"mode_num": mode_num},
                            ))
                        prev_mode_num = mode_num

                    elif mtype == "STATUSTEXT":
                        text = getattr(msg, "text", "")
                        if isinstance(text, bytes):
                            text = text.decode("utf-8", errors="replace")
                        text = text.rstrip("\x00")
                        if firmware is None and any(k in text for k in ("APM:", "ArduCopter", "ArduPlane", "ArduRover")):
                            firmware = text
                        events.append(TimelineEvent(
                            timestamp_utc=iso_ts, source="ardupilot.mavlink",
                            event_type="STATUS_TEXT", description=text,
                        ))

                    elif mtype == "GPS_RAW_INT":
                        fix_type = getattr(msg, "fix_type", 0)
                        lat = getattr(msg, "lat", 0) / 1e7
                        lon = getattr(msg, "lon", 0) / 1e7
                        alt_raw = getattr(msg, "alt", None)
                        alt = alt_raw / 1000.0 if alt_raw is not None else None
                        vel_raw = getattr(msg, "vel", None)
                        speed = vel_raw / 100.0 if vel_raw is not None else None
                        _record_gps_sample(iso_ts, ts, lat, lon, alt, speed, has_fix=fix_type >= 3)
        finally:
            conn.close()

        if first_ts is None:
            warnings.append(
                "Log file could not be read as valid ArduPilot data (corrupt or "
                "unreadable) — no messages could be extracted."
            )
        if not had_gps_fix:
            warnings.append("No 3D GPS fix found in log; flight path may be empty or unreliable.")
        if arm_count == 0:
            warnings.append("No ARM event found in log.")
        if altitude_anomaly_count:
            warnings.append(
                f"{altitude_anomaly_count} altitude anomaly event(s) detected "
                f"(vertical rate > {ANOMALOUS_VERTICAL_RATE_MS:.0f} m/s) — see timeline."
            )

        duration_s = (last_ts - first_ts) if (first_ts and last_ts) else None

        flight_summary = {
            "firmware": firmware,
            "frame_type": frame_type,
            "start_time_utc": _iso(first_ts) if first_ts else None,
            "end_time_utc": _iso(last_ts) if last_ts else None,
            "duration_s": duration_s,
            "gps_fix_acquired_at": gps_fix_acquired_at,
            "max_altitude_m": max_alt_m,
            "max_speed_ms": max_speed_ms,
            "total_distance_m": round(total_distance_m, 1),
            "arm_count": arm_count,
            "disarm_count": disarm_count,
            "gps_track_points": len(flight_path),
            "altitude_anomaly_count": altitude_anomaly_count,
        }

        events.sort(key=lambda e: e.timestamp_utc)

        return ParserResult(
            platform=self.platform_name,
            events=events,
            flight_summary=flight_summary,
            flight_path=flight_path,
            warnings=warnings,
            implemented=True,
        )
