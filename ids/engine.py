"""IDS pipeline: state update -> detectors -> fusion -> alerts (+ signed log), with timing.

Fail-safe by design: a malformed frame or a detector bug must never stop the pipeline (in live mode that would
also stop the router and cut the link). Every stage is isolated; an exception is counted, reported now and then
as an IDS_FAULT alert, and the message is otherwise treated as having produced no findings.
"""

from __future__ import annotations

import time
import warnings
from collections import defaultdict, deque
from typing import Callable, Iterable, Optional

from ids.alertlog import AlertLog
from ids.core import Alert, AttackClass, Msg
from ids.detectors.checks import default_checks
from ids.detectors.integrity import IntegrityDetector
from ids.detectors.protocol import ProtocolDetector
from ids.detectors.residual import ResidualDetector
from ids.fusion import Fusion
from ids.state import VehicleState

PROC_NS_KEEP = 500_000  # more than one benchmark replay (about 165k messages)
FAULT_ALERT_INTERVAL_S = 30.0  # at most one IDS_FAULT alert per component per this much stream time


class Engine:
    def __init__(self, state: VehicleState, detectors: list, fusion: Fusion, log: Optional[AlertLog] = None,
                 on_alert: Optional[Callable[[Alert], None]] = None):
        self.state, self.detectors, self.fusion = state, detectors, fusion
        self.log, self.on_alert = log, on_alert
        self.proc_ns: deque[int] = deque(maxlen=PROC_NS_KEEP)  # bounded: the live router runs for hours
        self.n_findings = 0
        self.faults: dict[str, int] = defaultdict(int)  # component -> exceptions swallowed
        self.sink_errors = 0  # alert-log / callback failures swallowed
        self._fault_t: dict[str, float] = {}
        self._warned: set[str] = set()

    def stats(self) -> dict:
        return {"findings": self.n_findings, "faults": dict(self.faults), "sink_errors": self.sink_errors,
                "suppressed": {c.value: n for c, n in self.fusion.suppressed.items()}}

    def _fault(self, component: str, exc, msg: Msg) -> list[Alert]:
        self.faults[component] += 1
        last = self._fault_t.get(component)
        if last is not None and abs(msg.t - last) < FAULT_ALERT_INTERVAL_S:
            return []
        self._fault_t[component] = msg.t
        why = (f"{component} failed with {exc!r} on {msg.type} from {msg.src} "
               f"({self.faults[component]} fault(s) so far); input ignored, pipeline continues")
        return [Alert(t_first=msg.t, t_alert=msg.t, attack_class=AttackClass.IDS_FAULT, severity="high",
                      score=1.0, reasons=[why], detectors=[component])]

    def _emit(self, a: Alert) -> None:
        sinks = [("alert log", self.log.append if self.log is not None else None),
                 ("alert callback", self.on_alert)]
        for label, sink in sinks:
            if sink is None:
                continue
            try:
                sink(a)
            except Exception as e:  # a full disk or a dead dashboard must not stop detection
                self.sink_errors += 1
                if label not in self._warned:
                    self._warned.add(label)
                    warnings.warn(f"IDS {label} failed: {e!r} (further failures are counted, not shown)")

    def process(self, msg: Msg) -> list[Alert]:
        t0 = time.perf_counter_ns()
        fault_alerts: list[Alert] = []
        try:
            self.state.update(msg)
        except Exception as e:
            fault_alerts += self._fault("state", e, msg)
        findings = []
        for d in self.detectors:
            name = getattr(d, "name", type(d).__name__)
            try:
                findings.extend(d.feed(msg))
            except Exception as e:
                fault_alerts += self._fault(name, e, msg)
            sub = getattr(d, "faults", None)  # detectors that isolate their own sub-checks report them here
            if sub:
                for why in sub:
                    fault_alerts += self._fault(name, why, msg)
                sub.clear()
        alerts: list[Alert] = []
        if findings:
            try:
                alerts = self.fusion.feed(findings)
            except Exception as e:
                fault_alerts += self._fault("fusion", e, msg)
        alerts = fault_alerts + alerts
        self.proc_ns.append(time.perf_counter_ns() - t0)
        self.n_findings += len(findings)
        for a in alerts:
            self._emit(a)
        return alerts

    def tick(self, now: float | None = None) -> list[Alert]:
        """Run timer-driven detector checks without requiring a new telemetry frame."""
        now = time.time() if now is None else now
        findings = []
        for detector in self.detectors:
            tick = getattr(detector, "tick", None)
            if tick is None:
                continue
            try:
                findings.extend(tick(now))
            except Exception as exc:
                # No source frame exists for a timer failure; report it as a bounded IDS fault.
                self.faults[getattr(detector, "name", type(detector).__name__)] += 1
                warnings.warn(f"IDS timer check failed: {exc!r}")
        alerts = self.fusion.feed(findings) if findings else []
        self.n_findings += len(findings)
        for alert in alerts:
            self._emit(alert)
        return alerts

    def run(self, msgs: Iterable[Msg]) -> list[Alert]:
        alerts = []
        for m in msgs:
            alerts.extend(self.process(m))
        return alerts


def build_engine(thresholds=None, baseline=None, ml_model=None, log=None, on_alert=None, trusted=(),
                 vehicle=None, learn_sources=True) -> Engine:
    """`vehicle` pins the vehicle's (sysid, compid). `learn_sources=False` trusts only `trusted` (+ `vehicle`), so a
    source that is already talking during the warm-up window is not silently allowlisted."""
    state = VehicleState(vehicle)
    allow = set(trusted) | ({vehicle} if vehicle else set())
    detectors = [
        ProtocolDetector(state, trusted=allow, learn_sources=learn_sources),
        ResidualDetector(state, default_checks(), thresholds or {}),
        IntegrityDetector(baseline),
    ]
    if ml_model is not None:
        from ids.detectors.ml import MLDetector
        detectors.append(MLDetector(state, ml_model))
    return Engine(state, detectors, Fusion(), log, on_alert)
