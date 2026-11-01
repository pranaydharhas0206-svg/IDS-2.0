import random

from ids.bench import Instance, pick_starts, score
from ids.core import Alert, AttackClass

D, G = AttackClass.DOS, AttackClass.GPS_SPOOFING


def al(t, cls):
    return Alert(t, t, cls, "high", 1.0, [], [])


def test_score_counts_detection_latency_and_false_positives():
    inst = [Instance(D, 100.0, 105.0, "x"), Instance(G, 200.0, 230.0, "y")]
    alerts = [al(101.0, D), al(50.0, G), al(210.0, D)]
    r = score(alerts, inst, 0.0, 300.0)
    assert r["instances"] == 2 and r["detected"] == 1 and r["detected_any"] == 2
    assert r["latencies"] == [1.0]
    assert r["false_positives"] == 1
    assert r["confusion"]["gps_spoofing"] == {"dos": 1}


def test_score_ignores_alerts_outside_eval_range():
    assert score([al(10.0, D)], [], 100.0, 200.0)["false_positives"] == 0


def test_pick_starts_respects_gap_and_range():
    rng = random.Random(0)
    starts = pick_starts([float(t) for t in range(0, 1000)], 100, 900, 5, 90, rng)
    assert len(starts) == 5 and all(100 <= s <= 900 for s in starts)
    assert all(b - a >= 90 for a, b in zip(starts, starts[1:]))


def test_write_results_reports_per_class_false_positives(tmp_path):
    from ids.bench import write_results
    res = {
        "config": {"seed": 1, "use_ml": False},
        "benign": {"eval_hours": 0.1, "false_positives": 0, "fp_per_hour": 0.0},
        "overall": {"instances": 2, "detection_accuracy": 1.0, "detection_rate_any_class": 1.0,
                    "latency_p50_s": 0.1, "latency_p95_s": 0.2, "latency_max_s": 0.2},
        "compute": {"flight_s": 1.0, "messages": 1, "mean_us_per_msg": 1.0, "p99_us_per_msg": 2.0,
                    "log_msg_rate_hz": 1.0, "cpu_pct_of_one_core_at_log_rate": 0.0, "throughput_msgs_per_s": 1},
        "per_class": {
            "dos": {"detected": 1, "instances": 1, "false_positives": 0, "latencies": [0.1], "confusion": {"dos": {"dos": 1}}},
            "gps_spoofing": {"detected": 1, "instances": 1, "false_positives": 1, "latencies": [0.2],
                             "confusion": {"gps_spoofing": {"gps_spoofing": 1}}},
        },
    }
    write_results(res, tmp_path)
    md = (tmp_path / "results.md").read_text(encoding="utf-8")
    assert "| Attack class | Detected / instances | Wilson 95% CI | FP alerts | Latency p50 / p95 (s) | Confusion |" in md
    assert "| dos | 1 / 1 | n/a | 0 | None / None |" in md
    assert "| gps_spoofing | 1 / 1 | n/a | 1 | None / None |" in md


def test_wilson_interval_reports_uncertainty_for_small_sample():
    from ids.bench import wilson_interval
    ci = wilson_interval(20, 20)
    assert ci is not None and ci[0] < 1.0 and ci[1] == 1.0
    assert wilson_interval(0, 0) is None
