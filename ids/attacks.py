"""Attack injectors: transforms over a recorded MAVLink stream that also label what they touched.

Replay-mode limitation (stated in the proposal): recorded EKF output cannot react to an injected GPS
spoof, so closed-loop behaviour is exercised in SITL live mode instead.
"""

from __future__ import annotations

import math
import random
from dataclasses import replace
from typing import Iterator

from ids.core import AttackClass, Msg

VEHICLE, GCS, ROGUE = (1, 1), (255, 0), (66, 1)


def _mod(msg: Msg, label: AttackClass, **changes) -> Msg:
    return replace(msg, fields={**msg.fields, **changes}, label=label)


def _new(t, typ, src, seq, label, **fields) -> Msg:
    return Msg(t=t, type=typ, src_sys=src[0], src_comp=src[1], seq=seq % 256, fields=fields, label=label)


def _merge(stream: list[Msg], inserts: list[Msg]) -> Iterator[Msg]:
    inserts = sorted(inserts, key=lambda m: m.t)
    i = 0
    for m in stream:
        while i < len(inserts) and inserts[i].t <= m.t:
            yield inserts[i]
            i += 1
        yield m
    yield from inserts[i:]


class Attack:
    attack_class: AttackClass
    VARIANTS: tuple[str, ...] = ("default",)
    DURATION = 20.0

    def __init__(self, start: float, variant: str | None = None, duration: float | None = None, seed: int = 0):
        self.start = start
        self.variant = variant or self.VARIANTS[0]
        self.duration = self.DURATION if duration is None else duration
        self.rng = random.Random(seed)

    @property
    def end(self) -> float:
        return self.start + self.duration

    def active(self, t: float) -> bool:
        return self.start <= t < self.end

    def apply(self, msgs: list[Msg]) -> list[Msg]:
        raise NotImplementedError


class GpsSpoof(Attack):
    attack_class = AttackClass.GPS_SPOOFING
    VARIANTS = ("jump", "drift")
    DURATION = 30.0

    def apply(self, msgs):
        b = math.radians(self.rng.uniform(0, 360))
        out = []
        for m in msgs:
            f = m.fields
            if m.type == "GPS_RAW_INT" and m.src == VEHICLE and self.active(m.t) and f.get("fix_type", 0) >= 3:
                d = 150.0 if self.variant == "jump" else 3.0 * (m.t - self.start)  # drift: 3 m/s walk-off
                lat = f["lat"] / 1e7
                dlat = d * math.cos(b) / 111320.0
                dlon = d * math.sin(b) / (111320.0 * math.cos(math.radians(lat)))
                out.append(_mod(m, self.attack_class, lat=int(round(f["lat"] + dlat * 1e7)),
                                lon=int(round(f["lon"] + dlon * 1e7))))
            else:
                out.append(m)
        return out


class CommandInjection(Attack):
    attack_class = AttackClass.COMMAND_INJECTION
    VARIANTS = ("rogue_node", "spoofed_gcs")
    DURATION = 2.0

    def apply(self, msgs):
        src = ROGUE if self.variant == "rogue_node" else GCS
        seq0 = self.rng.randrange(256)
        inserts = [_new(self.start + k * 0.5, "COMMAND_LONG", src, seq0 + k, self.attack_class,
                        target_system=1, target_component=1, command=400, confirmation=0,
                        param1=0.0, param2=21196.0, param3=0.0, param4=0.0, param5=0.0, param6=0.0, param7=0.0)
                   for k in range(3)]
        return list(_merge(msgs, inserts))


class TelemetryManipulation(Attack):
    attack_class = AttackClass.TELEMETRY_MANIPULATION
    VARIANTS = ("hud", "attitude", "battery")
    DURATION = 20.0

    def apply(self, msgs):
        out = []
        for m in msgs:
            if m.src != VEHICLE or not self.active(m.t):
                out.append(m)
            elif self.variant == "hud" and m.type == "VFR_HUD":
                out.append(_mod(m, self.attack_class, alt=m.fields["alt"] + 25.0,
                                groundspeed=m.fields["groundspeed"] + 6.0))
            elif self.variant == "attitude" and m.type == "ATTITUDE":
                out.append(_mod(m, self.attack_class, roll=m.fields["roll"] + 0.35))
            elif self.variant == "battery" and m.type == "SYS_STATUS" and m.fields.get("voltage_battery", 65535) not in (0, 65535):
                out.append(_mod(m, self.attack_class, voltage_battery=m.fields["voltage_battery"] + 2000))
            else:
                out.append(m)
        return out


class MavlinkAnomaly(Attack):
    attack_class = AttackClass.MAVLINK_ANOMALY
    VARIANTS = ("replay", "rogue_heartbeat")
    DURATION = 6.0

    def apply(self, msgs):
        if self.variant == "replay":
            # re-inject 5 s of vehicle traffic captured 30 s earlier, original sequence numbers intact
            lo = self.start - 30.0
            captured = [m for m in msgs if m.src == VEHICLE and lo <= m.t < lo + 5.0]
            inserts = [replace(m, t=self.start + (m.t - lo), label=self.attack_class) for m in captured]
        else:
            inserts = [_new(self.start + k * 0.5, "HEARTBEAT", (77, 1), k, self.attack_class, type=2, autopilot=3,
                            base_mode=129, custom_mode=0, system_status=4, mavlink_version=3)
                       for k in range(int(self.duration * 2))]
        return list(_merge(msgs, inserts))


class DosFlood(Attack):
    attack_class = AttackClass.DOS
    VARIANTS = ("rogue_flood", "gcs_spoof_flood")
    DURATION = 5.0
    RATE_HZ = 300

    def apply(self, msgs):
        src = (99, 1) if self.variant == "rogue_flood" else GCS
        n = int(self.duration * self.RATE_HZ)
        seq0 = self.rng.randrange(256)
        inserts = [_new(self.start + k / self.RATE_HZ, "PARAM_REQUEST_LIST", src, seq0 + k, self.attack_class,
                        target_system=1, target_component=1) for k in range(n)]
        return list(_merge(msgs, inserts))


class FirmwareTamper(Attack):
    attack_class = AttackClass.FIRMWARE_INTEGRITY
    VARIANTS = ("banner", "param")
    DURATION = 3.0

    def apply(self, msgs):
        last_seq = 0
        for m in msgs:
            if m.src == VEHICLE and m.t <= self.start:
                last_seq = m.seq
        if self.variant == "banner":
            ins = _new(self.start, "STATUSTEXT", VEHICLE, last_seq, self.attack_class, severity=6,
                       text="APM:Copter V3.4-dev (deadbeef)")
        else:
            ins = _new(self.start, "PARAM_VALUE", VEHICLE, last_seq, self.attack_class, param_id="ARMING_CHECK",
                       param_value=0.0, param_type=2, param_count=491, param_index=0)
        return list(_merge(msgs, [ins]))


ATTACKS: dict[AttackClass, type[Attack]] = {
    AttackClass.GPS_SPOOFING: GpsSpoof,
    AttackClass.COMMAND_INJECTION: CommandInjection,
    AttackClass.TELEMETRY_MANIPULATION: TelemetryManipulation,
    AttackClass.MAVLINK_ANOMALY: MavlinkAnomaly,
    AttackClass.DOS: DosFlood,
    AttackClass.FIRMWARE_INTEGRITY: FirmwareTamper,
}


def make_attack(cls: AttackClass, start: float, index: int, seed: int = 0) -> Attack:
    kind = ATTACKS[cls]
    return kind(start, variant=kind.VARIANTS[index % len(kind.VARIANTS)], seed=seed * 1000 + index)
