import json

from ids.alertlog import AlertLog, verify_log
from ids.core import Alert, AttackClass, Finding
from ids.fusion import Fusion

G = AttackClass.GPS_SPOOFING


def f(t, score, cls=G):
    return Finding(t, "d", cls, score, f"r{t}")


def test_single_weak_finding_does_not_alert():
    assert Fusion().feed([f(0.0, 0.5)]) == []


def test_two_weak_findings_in_window_alert():
    fu = Fusion()
    fu.feed([f(0.0, 0.5)])
    alerts = fu.feed([f(1.0, 0.5)])
    assert len(alerts) == 1 and alerts[0].t_first == 0.0 and alerts[0].t_alert == 1.0


def test_findings_outside_window_do_not_accumulate():
    fu = Fusion(window_s=3.0)
    fu.feed([f(0.0, 0.5)])
    assert fu.feed([f(5.0, 0.5)]) == []


def test_cooldown_suppresses_repeat_alerts_per_class_only():
    fu = Fusion(cooldown_s=10.0)
    assert fu.feed([f(0.0, 1.0)])
    assert fu.feed([f(2.0, 1.0)]) == []
    assert fu.feed([f(2.0, 1.0, AttackClass.DOS)])
    assert fu.feed([f(11.0, 1.0)])


def test_command_injection_is_critical():
    (a,) = Fusion().feed([f(0.0, 1.0, AttackClass.COMMAND_INJECTION)])
    assert a.severity == "critical"


def test_alert_log_verifies_and_detects_tampering(tmp_path):
    p, key = tmp_path / "alerts.jsonl", b"k"
    log = AlertLog(p, key)
    for i in range(3):
        log.append(Alert(i, i + 0.5, AttackClass.DOS, "high", 1.0, ["x"], ["protocol"]))
    assert verify_log(p, key) == (True, None, "ok")
    AlertLog(p, key).append(Alert(9, 9.5, AttackClass.DOS, "high", 1.0, ["y"], ["protocol"]))  # reopen continues chain
    assert verify_log(p, key)[0]
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["alert"]["severity"] = "low"
    lines[1] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    ok, idx, _ = verify_log(p, key)
    assert not ok and idx == 1
    assert not verify_log(p, b"wrong-key")[0]
