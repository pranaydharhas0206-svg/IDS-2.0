"""Residual checks. Each maps one message (+ latest other messages) to a non-negative residual.

GPS checks model spoofing (GPS disagrees with physics / the fused estimate / itself); telemetry
checks model a man-in-the-middle altering what the ground station sees (redundant fields disagree).
"""

from __future__ import annotations

import math
from collections import deque
from statistics import median

from ids.core import AttackClass, Msg

EARTH_R = 6371000.0
FRESH_S = 1.0  # a cached companion message older than this is not compared


def dist_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    x = math.radians(lon2 - lon1) * math.cos(math.radians((lat1 + lat2) / 2))
    y = math.radians(lat2 - lat1)
    return EARTH_R * math.hypot(x, y)


def wrap_deg(d: float) -> float:
    return abs((d + 180.0) % 360.0 - 180.0)


def _fresh(cache: dict, typ: str, t: float):
    m = cache.get(typ)
    return m if m is not None and abs(t - m.t) <= FRESH_S else None


def _shrink(d: float, allowance: float) -> float:
    """Move d toward zero by |allowance| (deadzone), never past zero."""
    a = abs(allowance)
    return math.copysign(max(0.0, abs(d) - a), d)


def _gps_ok(msg: Msg) -> bool:
    return msg.fields.get("fix_type", 0) >= 3


class Check:
    name = ""
    attack_class = AttackClass.GPS_SPOOFING
    triggers: frozenset = frozenset()
    floor = 1.0

    def residual(self, msg: Msg, cache: dict) -> float | None:
        raise NotImplementedError


class _RunningMedian:
    """|value - median(values in the last `span_s`)| — tolerant of slow drift and fixed offsets."""

    def __init__(self, span_s: float = 30.0, min_n: int = 5):
        self.span_s, self.min_n, self.buf = span_s, min_n, deque()

    def deviation(self, t: float, value: float) -> float | None:
        while self.buf and self.buf[0][0] < t - self.span_s:
            self.buf.popleft()
        ref = median(v for _, v in self.buf) if len(self.buf) >= self.min_n else None
        self.buf.append((t, value))
        return None if ref is None else abs(value - ref)


# ---------- GPS spoofing ----------

class GpsJump(Check):
    name, attack_class, triggers, floor = "gps_jump", AttackClass.GPS_SPOOFING, frozenset({"GPS_RAW_INT"}), 30.0

    def __init__(self):
        self.ref = None

    def residual(self, msg, cache):
        if not _gps_ok(msg):
            self.ref = None
            return None
        lat, lon = msg.fields["lat"] / 1e7, msg.fields["lon"] / 1e7
        if self.ref is None:
            self.ref = (msg.t, lat, lon)
            return None
        dt = msg.t - self.ref[0]
        if dt < 0.8:
            return None
        v = dist_m(self.ref[1], self.ref[2], lat, lon) / dt
        self.ref = (msg.t, lat, lon)
        return v


class GpsFusedDiv(Check):
    name, attack_class, triggers, floor = "gps_fused_div", AttackClass.GPS_SPOOFING, frozenset({"GPS_RAW_INT"}), 10.0

    def residual(self, msg, cache):
        p = _fresh(cache, "GLOBAL_POSITION_INT", msg.t)
        if p is None or not _gps_ok(msg):
            return None
        return dist_m(msg.fields["lat"] / 1e7, msg.fields["lon"] / 1e7, p.fields["lat"] / 1e7, p.fields["lon"] / 1e7)


class GpsVelMismatch(Check):
    name, attack_class, triggers, floor = "gps_vel_mismatch", AttackClass.GPS_SPOOFING, frozenset({"GPS_RAW_INT"}), 3.0

    def __init__(self):
        self.ref = None

    def residual(self, msg, cache):
        if not _gps_ok(msg):
            self.ref = None
            return None
        f = msg.fields
        cur = (msg.t, f["lat"] / 1e7, f["lon"] / 1e7, f.get("vel", 0) / 100.0)
        if self.ref is None:
            self.ref = cur
            return None
        dt = cur[0] - self.ref[0]
        if dt < 2.0:
            return None
        derived = dist_m(self.ref[1], self.ref[2], cur[1], cur[2]) / dt
        reported = (self.ref[3] + cur[3]) / 2
        self.ref = cur
        return abs(derived - reported)


class GpsBaroAlt(Check):
    name, attack_class, triggers, floor = "gps_baro_alt", AttackClass.GPS_SPOOFING, frozenset({"GPS_RAW_INT"}), 10.0

    def __init__(self):
        self.p0 = None
        self.rm = _RunningMedian()

    def residual(self, msg, cache):
        sp = _fresh(cache, "SCALED_PRESSURE", msg.t)
        if sp is None or not _gps_ok(msg):
            return None
        p = sp.fields["press_abs"]
        if self.p0 is None:
            self.p0 = p
        baro_alt = 44330.0 * (1.0 - (p / self.p0) ** 0.1903)
        return self.rm.deviation(msg.t, msg.fields["alt"] / 1000.0 - baro_alt)


class EkfPosVar(Check):
    name, attack_class, triggers, floor = "ekf_pos_var", AttackClass.GPS_SPOOFING, frozenset({"EKF_STATUS_REPORT"}), 0.5

    def residual(self, msg, cache):
        return float(msg.fields.get("pos_horiz_variance", 0.0))


# ---------- telemetry manipulation ----------

class AttAhrs2(Check):
    """Windowed mean of the signed ATTITUDE-vs-AHRS2 roll/pitch difference.

    Two attitude estimators sampled at slightly different instants differ by tens of degrees in
    manoeuvres, but that error is zero-mean; a persistent offset (tampering) survives averaging.
    Each sample's difference is also shrunk by the physical sampling-skew bound |angular rate| x
    |message-time gap| (rates come from the ATTITUDE message itself), so a fast tumble/flip, where
    the two messages are ~0.3-0.5 s apart, is not read as tampering."""

    name, attack_class, triggers, floor = "att_ahrs2", AttackClass.TELEMETRY_MANIPULATION, frozenset({"ATTITUDE"}), 7.0
    SPAN_S, MIN_N = 3.0, 3

    def __init__(self):
        self.buf = deque()

    @staticmethod
    def _signed_wrap(d: float) -> float:
        return (d + 180.0) % 360.0 - 180.0

    def residual(self, msg, cache):
        a = _fresh(cache, "AHRS2", msg.t)
        if a is None:
            return None
        gap = abs(msg.t - a.t)
        self.buf.append((msg.t,
                         _shrink(self._signed_wrap(math.degrees(msg.fields["roll"] - a.fields["roll"])),
                                 math.degrees(msg.fields.get("rollspeed", 0.0)) * gap),
                         _shrink(self._signed_wrap(math.degrees(msg.fields["pitch"] - a.fields["pitch"])),
                                 math.degrees(msg.fields.get("pitchspeed", 0.0)) * gap)))
        while self.buf[0][0] < msg.t - self.SPAN_S:
            self.buf.popleft()
        if len(self.buf) < self.MIN_N:
            return None
        n = len(self.buf)
        return max(abs(sum(b[1] for b in self.buf) / n), abs(sum(b[2] for b in self.buf) / n))


class HudAlt(Check):
    name, attack_class, triggers, floor = "hud_alt", AttackClass.TELEMETRY_MANIPULATION, frozenset({"VFR_HUD"}), 3.0

    def __init__(self):
        self.rm = _RunningMedian()

    def residual(self, msg, cache):
        p = _fresh(cache, "GLOBAL_POSITION_INT", msg.t)
        if p is None:
            return None
        alt = msg.fields["alt"]
        offset = min(alt - p.fields["alt"] / 1000.0, alt - p.fields["relative_alt"] / 1000.0, key=abs)
        return self.rm.deviation(msg.t, offset)


class HudGroundspeed(Check):
    name, attack_class, triggers, floor = "hud_gs", AttackClass.TELEMETRY_MANIPULATION, frozenset({"VFR_HUD"}), 3.0

    def residual(self, msg, cache):
        p = _fresh(cache, "GLOBAL_POSITION_INT", msg.t)
        if p is None:
            return None
        return abs(msg.fields["groundspeed"] - math.hypot(p.fields["vx"], p.fields["vy"]) / 100.0)


class HudHeading(Check):
    """VFR_HUD heading vs GLOBAL_POSITION_INT hdg, minus the yaw the vehicle can have swept between
    the two messages (|yawspeed| x message-time gap): a fast spin is not tampering."""

    name, attack_class, triggers, floor = "hud_heading", AttackClass.TELEMETRY_MANIPULATION, frozenset({"VFR_HUD"}), 15.0

    def residual(self, msg, cache):
        p = _fresh(cache, "GLOBAL_POSITION_INT", msg.t)
        if p is None or p.fields.get("hdg", 65535) == 65535:
            return None
        att = _fresh(cache, "ATTITUDE", msg.t)
        swept = math.degrees(abs(att.fields.get("yawspeed", 0.0))) * abs(msg.t - p.t) if att else 0.0
        return max(0.0, wrap_deg(msg.fields["heading"] - p.fields["hdg"] / 100.0) - swept)


class BattVolt(Check):
    """Pack voltage, compensated for load sag, against its own recent median.

    The old consecutive-sample jump check had two root-cause defects: (1) load steps change the
    terminal voltage by 1-3 V between samples, which inflated the calibrated threshold above a
    +2 V tamper; (2) a constant offset only produces two edge samples, so it was easy to miss.
    v + R*I removes the I*R sag (R ~ 0.055 ohm, fitted on differential V/I samples of the
    calibration half; the held-out half fits 0.051) and a running median exposes a step or offset."""

    name, attack_class, triggers, floor = "batt_volt", AttackClass.TELEMETRY_MANIPULATION, frozenset({"SYS_STATUS"}), 1.0
    R_OHM = 0.055

    def __init__(self):
        self.rm = _RunningMedian(span_s=10.0, min_n=5)

    def residual(self, msg, cache):
        v = msg.fields.get("voltage_battery", 65535)
        if v in (65535, 0):
            return None
        i = msg.fields.get("current_battery", -1)
        amps = i / 100.0 if i >= 0 else 0.0
        return self.rm.deviation(msg.t, v / 1000.0 + self.R_OHM * amps)


def default_checks() -> list[Check]:
    return [GpsJump(), GpsFusedDiv(), GpsVelMismatch(), GpsBaroAlt(), EkfPosVar(),
            AttAhrs2(), HudAlt(), HudGroundspeed(), HudHeading(), BattVolt()]
