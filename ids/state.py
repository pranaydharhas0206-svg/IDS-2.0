"""Minimal vehicle state the detectors need: who the vehicle is, armed, altitude."""

from __future__ import annotations

from typing import Optional

from ids.core import Msg

MAV_MODE_FLAG_SAFETY_ARMED = 128
MAV_AUTOPILOT_INVALID = 8
MAV_TYPE_GCS = 6
AIRBORNE_ALT_M = 2.0


class VehicleState:
    def __init__(self, vehicle_src: Optional[tuple[int, int]] = None):
        # A configured identity is pinned: a rogue heartbeat can never take it over.
        self.vehicle_src: Optional[tuple[int, int]] = vehicle_src
        self.armed = False
        self.relative_alt_m = 0.0

    @property
    def airborne(self) -> bool:
        return self.armed and self.relative_alt_m > AIRBORNE_ALT_M

    @staticmethod
    def is_vehicle_claim(msg: Msg) -> bool:
        """A HEARTBEAT presenting itself as an autopilot vehicle (not a GCS, not a companion/peripheral)."""
        f = msg.fields
        return (msg.type == "HEARTBEAT" and f.get("autopilot") != MAV_AUTOPILOT_INVALID
                and f.get("type") != MAV_TYPE_GCS)

    def is_vehicle(self, msg: Msg) -> bool:
        return self.vehicle_src is not None and msg.src == self.vehicle_src

    def update(self, msg: Msg) -> None:
        f = msg.fields
        if msg.type == "HEARTBEAT":
            if not self.is_vehicle_claim(msg):
                return
            if self.vehicle_src is None:
                self.vehicle_src = msg.src
            if msg.src == self.vehicle_src:
                self.armed = bool(f.get("base_mode", 0) & MAV_MODE_FLAG_SAFETY_ARMED)
        elif msg.type == "GLOBAL_POSITION_INT" and self.is_vehicle(msg):
            self.relative_alt_m = f.get("relative_alt", 0) / 1000.0
