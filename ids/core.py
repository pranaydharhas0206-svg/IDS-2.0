"""Core types shared by every IDS component."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class AttackClass(str, Enum):
    GPS_SPOOFING = "gps_spoofing"
    COMMAND_INJECTION = "command_injection"
    TELEMETRY_MANIPULATION = "telemetry_manipulation"
    MAVLINK_ANOMALY = "mavlink_anomaly"
    DOS = "dos"
    FIRMWARE_INTEGRITY = "firmware_integrity"
    ANOMALY = "anomaly"  # unclassified, from the ML layer
    IDS_FAULT = "ids_fault"  # the IDS itself failed on an input (malformed frame or bug); never an attack label


@dataclass
class Msg:
    t: float
    type: str
    src_sys: int
    src_comp: int
    seq: int
    fields: dict = field(default_factory=dict)
    # Ground truth set only by attack injectors, for scoring. Detectors never read it.
    label: Optional[AttackClass] = None

    @property
    def src(self) -> tuple[int, int]:
        return (self.src_sys, self.src_comp)


@dataclass(frozen=True)
class Finding:
    t: float
    detector: str
    attack_class: AttackClass
    score: float
    reason: str


@dataclass
class Alert:
    t_first: float
    t_alert: float
    attack_class: AttackClass
    severity: str
    score: float
    reasons: list[str]
    detectors: list[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack_class"] = self.attack_class.value
        return d
