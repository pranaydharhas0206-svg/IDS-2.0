"""Runs residual checks on vehicle telemetry and turns threshold exceedances into findings."""

from __future__ import annotations

from collections import defaultdict

from ids.core import Finding, Msg
from ids.detectors.checks import Check
from ids.state import VehicleState


class ResidualDetector:
    name = "residual"

    def __init__(self, state: VehicleState, checks: list[Check], thresholds: dict[str, float], record: bool = False):
        self.state = state
        self.checks = checks
        self.thresholds = thresholds
        self.record = record
        self.recorded: dict[str, list[float]] = defaultdict(list)
        self.faults: list[str] = []  # checks that raised on a malformed message; drained by the Engine
        self.cache: dict[str, Msg] = {}
        self.by_trigger: dict[str, list[Check]] = defaultdict(list)
        for c in checks:
            for typ in c.triggers:
                self.by_trigger[typ].append(c)

    def feed(self, msg: Msg) -> list[Finding]:
        if not self.state.is_vehicle(msg):
            return []
        self.cache[msg.type] = msg
        out = []
        for c in self.by_trigger.get(msg.type, ()):
            try:
                r = c.residual(msg, self.cache)
            except Exception as e:  # one broken check must not blind the others on this message
                self.faults.append(f"check {c.name}: {e!r}")
                continue
            if r is None:
                continue
            if self.record:
                self.recorded[c.name].append(r)
            thr = self.thresholds.get(c.name, c.floor)
            if r > thr:
                out.append(Finding(msg.t, f"residual:{c.name}", c.attack_class, min(1.0, 0.5 * r / thr),
                                   f"{c.name} residual {r:.2f} > {thr:.2f}"))
        return out
