"""Protocol-layer detector: source allowlist, sequence anomalies, command policy, floods, link loss."""

from __future__ import annotations

from collections import defaultdict, deque

from ids.core import AttackClass, Finding, Msg
from ids.state import VehicleState

COMMAND_TYPES = frozenset({
    "COMMAND_LONG", "COMMAND_INT", "SET_MODE", "PARAM_SET", "MISSION_CLEAR_ALL", "MISSION_COUNT",
    "MISSION_ITEM", "MISSION_ITEM_INT", "MISSION_SET_CURRENT", "SET_POSITION_TARGET_LOCAL_NED",
    "SET_POSITION_TARGET_GLOBAL_INT", "SET_ATTITUDE_TARGET", "MANUAL_CONTROL", "RC_CHANNELS_OVERRIDE",
    "FILE_TRANSFER_PROTOCOL",
})
MAV_CMD_DO_FLIGHTTERMINATION = 185
MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN = 246
MAV_CMD_COMPONENT_ARM_DISARM = 400
SEQ_SCORE = 0.35
SPOOF_LINK_S = 5.0  # a dangerous command and a seq anomaly on one source within this = spoofed sender
NEW_SOURCE_REPEAT_S = 2.0
GPS_LOSS_S = 2.0  # continuous no-3D-fix time in flight before it counts as evidence
BAD_DATA_SCORE = 0.1
BAD_DATA_MAX_PER_WINDOW = 5  # undecodable frames are radio noise as often as attack: alone they stay below threshold
HB_LOSS_LONG_FACTOR = 4.0  # a heartbeat gap this many times hb_gap_s is sustained loss and scores full weight
PARAM_SET_TRUSTED_SCORE = 0.3  # in-flight tuning from a known source is routine; from a stranger it is still 1.0/0.6


def dangerous_command(msg: Msg) -> str | None:
    f = msg.fields
    if msg.type in ("COMMAND_LONG", "COMMAND_INT"):
        cmd, p1 = f.get("command"), f.get("param1", 0)
        if cmd == MAV_CMD_COMPONENT_ARM_DISARM and p1 == 0:
            return "disarm"
        if cmd == MAV_CMD_DO_FLIGHTTERMINATION and p1 >= 0.5:
            return "flight termination"
        if cmd == MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN:
            return "reboot/shutdown"
    if msg.type == "PARAM_SET":
        return f"PARAM_SET {str(f.get('param_id', '')).rstrip(chr(0))}"
    return None


class ProtocolDetector:
    name = "protocol"

    def __init__(self, state: VehicleState, warmup_s: float = 60.0, trusted=(), rate_factor: float = 4.0,
                 rate_margin: int = 100, hb_gap_s: float = 5.0, learn_sources: bool = True):
        self.state = state
        self.warmup_s = warmup_s
        self.learn_sources = learn_sources  # False: warm-up traffic does not extend the allowlist (`trusted` only)
        self.allow: set[tuple[int, int]] = set(trusted)
        self.claim_t: dict[tuple[int, int], float] = {}
        self.gps_lost_since: float | None = None
        self.gps_loss_report_t = -1e18
        self.rate_factor = rate_factor
        self.rate_margin = rate_margin
        self.hb_gap_s = hb_gap_s
        self.t0: float | None = None
        self.last_seq: dict[tuple[int, int], tuple[int, str]] = {}
        self.seq_anom_t: dict[tuple[int, int], float] = {}
        self.danger_t: dict[tuple[int, int], float] = {}
        self.new_src_t: dict[tuple[int, int], float] = {}
        self.rate_win: dict[tuple[int, int], deque] = defaultdict(deque)
        self.peak_rate: dict[tuple[int, int], int] = defaultdict(int)
        self.flood_t: dict[tuple[int, int], float] = {}
        self.last_vehicle_hb: float | None = None
        self.last_link_loss_report_t = -1e18
        self.bad_win: deque = deque()

    def _f(self, msg: Msg, cls: AttackClass, score: float, reason: str) -> Finding:
        return Finding(msg.t, self.name, cls, score, reason)

    def tick(self, now: float) -> list[Finding]:
        """Evaluate time-based link loss even when no further MAVLink frames arrive.

        Called by the live router using wall-clock seconds. Replay mode remains
        event-driven and does not call this method.
        """
        if (self.state.armed and self.last_vehicle_hb is not None
                and now - self.last_vehicle_hb > self.hb_gap_s
                and now - self.last_link_loss_report_t >= 1.0):
            gap = now - self.last_vehicle_hb
            self.last_link_loss_report_t = now
            score = 1.0 if gap > HB_LOSS_LONG_FACTOR * self.hb_gap_s else 0.5
            return [Finding(now, self.name, AttackClass.DOS, score,
                            f"vehicle heartbeat absent for {gap:.1f}s (timer-driven link-loss check)")]
        return []

    def feed(self, msg: Msg) -> list[Finding]:
        if self.t0 is None:
            self.t0 = msg.t
        if msg.type == "BAD_DATA":
            w = self.bad_win
            w.append(msg.t)
            while w and w[0] < msg.t - 3.0:
                w.popleft()
            if len(w) > BAD_DATA_MAX_PER_WINDOW:
                return []
            return [self._f(msg, AttackClass.MAVLINK_ANOMALY, BAD_DATA_SCORE, "undecodable MAVLink frame")]
        out: list[Finding] = []
        src = msg.src
        warm = msg.t - self.t0 < self.warmup_s

        # 1. source allowlist
        if warm and self.learn_sources:
            self.allow.add(src)
        elif src not in self.allow:
            if msg.type in COMMAND_TYPES:
                out.append(self._f(msg, AttackClass.COMMAND_INJECTION, 1.0,
                                   f"{msg.type} from unknown source {src}"))
            if msg.t - self.new_src_t.get(src, -1e18) >= NEW_SOURCE_REPEAT_S:
                self.new_src_t[src] = msg.t
                out.append(self._f(msg, AttackClass.MAVLINK_ANOMALY, 0.5, f"unknown MAVLink source {src}"))

        # 1b. a second source presenting itself as the vehicle (identity theft / rogue autopilot heartbeat);
        #     runs during warm-up too, so a rogue that speaks first cannot hide behind the learning window
        vsrc = self.state.vehicle_src
        if vsrc is not None and src != vsrc and self.state.is_vehicle_claim(msg) \
                and msg.t - self.claim_t.get(src, -1e18) >= 1.0:
            self.claim_t[src] = msg.t
            out.append(self._f(msg, AttackClass.MAVLINK_ANOMALY, 0.5,
                               f"{src} claims to be the vehicle but {vsrc} already is"))

        # 2. sequence numbers (same seq + different type is benign: SiK radio sends RADIO + RADIO_STATUS)
        prev = self.last_seq.get(src)
        if prev is not None:
            pseq, ptype = prev
            d = (msg.seq - pseq) % 256
            if d > 128 or (d == 0 and ptype == msg.type):
                self.seq_anom_t[src] = msg.t
                out.append(self._f(msg, AttackClass.MAVLINK_ANOMALY, SEQ_SCORE,
                                   f"sequence anomaly from {src}: {pseq}->{msg.seq} ({msg.type})"))
                if msg.t - self.danger_t.get(src, -1e18) <= SPOOF_LINK_S:
                    out.append(self._f(msg, AttackClass.COMMAND_INJECTION, 0.6,
                                       f"sequence anomaly right after a dangerous command from {src}: spoofed sender"))
        self.last_seq[src] = (msg.seq, msg.type)

        # 3. dangerous commands while airborne
        danger = dangerous_command(msg)
        if danger and self.state.airborne and src != self.state.vehicle_src:
            self.danger_t[src] = msg.t
            spoofed = msg.t - self.seq_anom_t.get(src, -1e18) <= SPOOF_LINK_S
            routine = danger.startswith("PARAM_SET") and src in self.allow
            base = PARAM_SET_TRUSTED_SCORE if routine else 0.6
            out.append(self._f(msg, AttackClass.COMMAND_INJECTION, 1.0 if spoofed else base,
                               f"{danger} while airborne from {src}" + (" with sequence anomaly" if spoofed else "")))

        # 4. per-source message rate (flood / DoS)
        w = self.rate_win[src]
        w.append(msg.t)
        while w and w[0] <= msg.t - 1.0:
            w.popleft()
        rate = len(w)
        if warm:
            self.peak_rate[src] = max(self.peak_rate[src], rate)
        else:
            peak = self.peak_rate.get(src, 0)
            limit = max(self.rate_factor * peak, peak + self.rate_margin)
            if rate > limit and msg.t - self.flood_t.get(src, -1e18) >= 1.0:
                self.flood_t[src] = msg.t
                out.append(self._f(msg, AttackClass.DOS, 1.0,
                                   f"message flood from {src}: {rate} msg/s (limit {limit:.0f})"))

        # 4b. sustained GPS fix loss in flight: the checks in residual.py are skipped without a 3D fix, so a
        #     jammer/spoofer that degrades the fix would otherwise blind them
        if msg.type == "GPS_RAW_INT" and self.state.is_vehicle(msg):
            if msg.fields.get("fix_type", 0) >= 3 or not self.state.airborne:
                self.gps_lost_since = None
            elif self.gps_lost_since is None:
                self.gps_lost_since = msg.t
            elif msg.t - self.gps_lost_since >= GPS_LOSS_S and msg.t - self.gps_loss_report_t >= 1.0:
                self.gps_loss_report_t = msg.t
                out.append(self._f(msg, AttackClass.GPS_SPOOFING, 0.5,
                                   f"GPS fix lost for {msg.t - self.gps_lost_since:.1f}s in flight (jamming/denial)"))

        # 5. vehicle heartbeat loss while armed (link loss / jamming indicator)
        if msg.type == "HEARTBEAT" and self.state.is_vehicle(msg):
            if self.last_vehicle_hb is not None and self.state.armed and msg.t - self.last_vehicle_hb > self.hb_gap_s:
                gap = msg.t - self.last_vehicle_hb
                out.append(self._f(msg, AttackClass.DOS, 1.0 if gap > HB_LOSS_LONG_FACTOR * self.hb_gap_s else 0.5,
                                   f"vehicle heartbeat lost for {gap:.1f}s"))
            self.last_vehicle_hb = msg.t
        return out
