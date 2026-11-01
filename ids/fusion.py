"""Evidence fusion: per attack class, sum finding scores in a sliding window; alert at threshold."""

from __future__ import annotations

from collections import defaultdict, deque

from ids.core import Alert, AttackClass, Finding

CRITICAL_CLASSES = {AttackClass.COMMAND_INJECTION, AttackClass.FIRMWARE_INTEGRITY}


class Fusion:
    def __init__(self, window_s: float = 3.0, threshold: float = 1.0, cooldown_s: float = 10.0,
                 critical_cooldown_s: float = 1.0):
        self.window_s, self.threshold, self.cooldown_s = window_s, threshold, cooldown_s
        # Critical classes only de-duplicate one burst: a second injection or firmware change a few seconds later
        # must not vanish inside the long cooldown.
        self.critical_cooldown_s = critical_cooldown_s
        self.win: dict[AttackClass, deque] = defaultdict(deque)
        self.cool_until: dict[AttackClass, float] = {}
        self.suppressed: dict[AttackClass, int] = defaultdict(int)  # findings dropped during a cooldown

    def feed(self, findings: list[Finding]) -> list[Alert]:
        alerts = []
        for f in findings:
            c = f.attack_class
            if f.t < self.cool_until.get(c, float("-inf")):
                self.suppressed[c] += 1
                continue
            w = self.win[c]
            w.append(f)
            while w and w[0].t < f.t - self.window_s:
                w.popleft()
            total = sum(x.score for x in w)
            if total >= self.threshold - 1e-9:
                severity = "critical" if c in CRITICAL_CLASSES or total >= 2 * self.threshold else "high"
                alerts.append(Alert(
                    t_first=w[0].t, t_alert=f.t, attack_class=c, severity=severity, score=round(total, 3),
                    reasons=list(dict.fromkeys(x.reason for x in w))[:5],
                    detectors=sorted({x.detector for x in w}),
                ))
                w.clear()
                self.cool_until[c] = f.t + (self.critical_cooldown_s if c in CRITICAL_CLASSES else self.cooldown_s)
        return alerts
