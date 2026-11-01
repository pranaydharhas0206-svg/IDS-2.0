"""Unsupervised anomaly layer: IsolationForest over 1-s traffic/kinematics windows.

Catches deviations no rule describes. Emits unclassified ANOMALY evidence (0.5 per window), so it
alerts only when two anomalous windows fall inside the fusion window.

An IsolationForest cannot extrapolate: a window beyond the training range on a feature scores no
higher than the training extreme, and features constant in training (e.g. n_cmd == 0) are never
split on. So the forest score is paired with an explicit out-of-range check against the per-feature
training envelope, which catches floods and other magnitude excursions the forest is blind to.
"""

from __future__ import annotations

from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest

from ids.core import AttackClass, Finding, Msg
from ids.state import VehicleState

FEATURES = ["n_total", "n_vehicle", "n_gcs", "n_other", "n_sources", "n_cmd", "n_seq_back",
            "gps_speed", "climb", "roll_rate", "pitch_rate", "volt"]
CMD_TYPES = {"COMMAND_LONG", "COMMAND_INT", "SET_MODE", "PARAM_SET", "PARAM_REQUEST_LIST", "MISSION_CLEAR_ALL"}


class WindowFeaturizer:
    def __init__(self, state: VehicleState, width: float = 1.0):
        self.state, self.width = state, width
        self.win_start: float | None = None
        self.gcs: set = set()
        self.last_seq: dict = {}
        self.kin = {"gps_speed": 0.0, "climb": 0.0, "roll_rate": 0.0, "pitch_rate": 0.0, "volt": 0.0}
        self._reset()

    def _reset(self):
        self.c = {k: 0 for k in ("n_total", "n_vehicle", "n_gcs", "n_other", "n_cmd", "n_seq_back")}
        self.sources: set = set()

    def feed(self, msg: Msg) -> list[float] | None:
        if self.win_start is None:
            self.win_start = msg.t
        vec = None
        if msg.t - self.win_start >= self.width:
            vec = [float(self.c[k]) if k in self.c else float(len(self.sources)) if k == "n_sources" else self.kin[k]
                   for k in FEATURES]
            self._reset()
            self.win_start = msg.t
        f = msg.fields
        if msg.type == "HEARTBEAT" and f.get("type") == 6:
            self.gcs.add(msg.src)
        self.c["n_total"] += 1
        self.sources.add(msg.src)
        if self.state.is_vehicle(msg):
            self.c["n_vehicle"] += 1
        elif msg.src in self.gcs:
            self.c["n_gcs"] += 1
        else:
            self.c["n_other"] += 1
        if msg.type in CMD_TYPES:
            self.c["n_cmd"] += 1
        prev = self.last_seq.get(msg.src)
        if prev is not None and (msg.seq - prev) % 256 > 128:
            self.c["n_seq_back"] += 1
        self.last_seq[msg.src] = msg.seq
        if self.state.is_vehicle(msg):
            if msg.type == "GPS_RAW_INT":
                self.kin["gps_speed"] = f.get("vel", 0) / 100.0
            elif msg.type == "VFR_HUD":
                self.kin["climb"] = f.get("climb", 0.0)
            elif msg.type == "ATTITUDE":
                self.kin["roll_rate"], self.kin["pitch_rate"] = f.get("rollspeed", 0.0), f.get("pitchspeed", 0.0)
            elif msg.type == "SYS_STATUS" and f.get("voltage_battery", 65535) != 65535:
                self.kin["volt"] = f["voltage_battery"] / 1000.0
        return vec


def _vectors(msgs: Iterable[Msg]) -> np.ndarray:
    st = VehicleState()
    fz = WindowFeaturizer(st)
    rows = []
    for m in msgs:
        st.update(m)
        v = fz.feed(m)
        if v is not None:
            rows.append(v)
    return np.asarray(rows, dtype=float)


def train_ml(msgs: Iterable[Msg], q: float = 0.999, margin: float = 1.1) -> dict:
    X = _vectors(msgs)
    model = IsolationForest(n_estimators=50, random_state=0).fit(X)
    s = -model.score_samples(X)
    return {"model": model, "threshold": float(np.quantile(s, q) * margin), "features": FEATURES,
            "lo": X.min(axis=0), "hi": X.max(axis=0)}


def _excursion(v: np.ndarray, lo: np.ndarray, hi: np.ndarray) -> float:
    """Largest distance outside the training envelope, in units of the feature's training range (floor 1)."""
    scale = np.maximum(hi - lo, 1.0)
    return float(np.max(np.maximum(v - hi, lo - v) / scale))


class MLDetector:
    name = "ml"

    OOD_FACTOR = 3.0  # flag a window lying more than 3 training-ranges outside the training envelope

    def __init__(self, state: VehicleState, model: dict):
        self.model, self.threshold = model["model"], model["threshold"]
        self.lo, self.hi = model.get("lo"), model.get("hi")
        self.fz = WindowFeaturizer(state)

    def feed(self, msg: Msg) -> list[Finding]:
        v = self.fz.feed(msg)
        if v is None:
            return []
        x = np.asarray([v])
        s = float(-self.model.score_samples(x)[0])
        if self.lo is not None:
            exc = _excursion(x[0], self.lo, self.hi)
            if exc > self.OOD_FACTOR:
                return [Finding(msg.t, self.name, AttackClass.ANOMALY, 0.5,
                                f"traffic/kinematics window {exc:.1f} training-ranges outside normal envelope "
                                f"(forest score {s:.3f})")]
        if s > self.threshold:
            return [Finding(msg.t, self.name, AttackClass.ANOMALY, 0.5,
                            f"traffic/kinematics anomaly score {s:.3f} > {self.threshold:.3f}")]
        return []
