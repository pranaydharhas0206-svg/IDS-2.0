"""Derive per-check thresholds from benign traffic: thr = max(floor, margin * quantile_q(residuals))."""

from __future__ import annotations

from typing import Iterable

from ids.core import Msg
from ids.detectors.checks import default_checks
from ids.detectors.residual import ResidualDetector
from ids.state import VehicleState


def calibrate(msgs: Iterable[Msg], q: float = 0.999, margin: float = 2.0) -> dict[str, float]:
    state = VehicleState()
    det = ResidualDetector(state, default_checks(), thresholds={}, record=True)
    for m in msgs:
        state.update(m)
        det.feed(m)
    out = {}
    for c in det.checks:
        vals = sorted(det.recorded.get(c.name, []))
        if not vals:
            out[c.name] = c.floor
            continue
        qv = vals[min(len(vals) - 1, int(q * len(vals)))]
        out[c.name] = round(max(c.floor, margin * qv), 4)
    return out
