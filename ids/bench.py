"""Reproducible benchmark: calibrate on the first half of a flight, attack and score the second half."""

from __future__ import annotations

import json
import math
import os
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import psutil

from ids.attacks import ATTACKS, make_attack
from ids.calibrate import calibrate
from ids.core import AttackClass, Msg
from ids.detectors.integrity import build_baseline
from ids.engine import build_engine
from ids.state import VehicleState

GRACE_S = 10.0


@dataclass
class Instance:
    attack_class: AttackClass
    start: float
    end: float
    variant: str


def airborne_times(msgs: list[Msg]) -> list[float]:
    st, out = VehicleState(), []
    for m in msgs:
        st.update(m)
        if st.airborne and m.type == "GLOBAL_POSITION_INT":
            out.append(m.t)
    return out


def pick_starts(candidates: list[float], lo: float, hi: float, n: int, min_gap: float, rng: random.Random) -> list[float]:
    pool = [t for t in candidates if lo <= t <= hi]
    rng.shuffle(pool)
    chosen: list[float] = []
    for t in pool:
        if all(abs(t - c) >= min_gap for c in chosen):
            chosen.append(t)
            if len(chosen) == n:
                break
    return sorted(chosen)


def _pct(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    return s[min(len(s) - 1, int(q * len(s)))]


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> list[float] | None:
    """Two-sided Wilson score interval for a binomial detection proportion."""
    if trials <= 0:
        return None
    p = successes / trials
    den = 1.0 + z * z / trials
    centre = (p + z * z / (2 * trials)) / den
    half = z * ((p * (1 - p) / trials + z * z / (4 * trials * trials)) ** 0.5) / den
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def score(alerts, instances: list[Instance], eval_start: float, eval_end: float, grace: float = GRACE_S) -> dict:
    detected = detected_any = 0
    latencies, per = [], []
    confusion: dict[str, Counter] = defaultdict(Counter)
    for inst in instances:
        in_win = [a for a in alerts if inst.start <= a.t_alert <= inst.end + grace]
        correct = [a for a in in_win if a.attack_class == inst.attack_class]
        detected += bool(correct)
        detected_any += bool(in_win)
        if correct:
            latencies.append(round(correct[0].t_alert - inst.start, 3))
        for c in {a.attack_class.value for a in in_win} or {"missed"}:
            confusion[inst.attack_class.value][c] += 1
        per.append({"class": inst.attack_class.value, "variant": inst.variant, "start": inst.start,
                    "detected": bool(correct), "predicted": sorted({a.attack_class.value for a in in_win})})
    fps = [a for a in alerts if eval_start <= a.t_alert <= eval_end
           and not any(i.start <= a.t_alert <= i.end + grace for i in instances)]
    return {"instances": len(instances), "detected": detected, "detected_any": detected_any,
            "latencies": latencies, "false_positives": len(fps),
            "false_positive_alerts": [a.to_dict() for a in fps], "confusion": {k: dict(v) for k, v in confusion.items()},
            "per_instance": per}


def run_bench(msgs: list[Msg], n_per_class: int = 5, seed: int = 7, use_ml: bool = False) -> dict:
    t0, t1 = msgs[0].t, msgs[-1].t
    split = t0 + 0.5 * (t1 - t0)
    calib = [m for m in msgs if m.t < split]
    thresholds = calibrate(calib)
    baseline = build_baseline(calib)
    model = None
    if use_ml:
        from ids.detectors.ml import train_ml
        model = train_ml(calib)

    def engine():
        return build_engine(thresholds=thresholds, baseline=baseline, ml_model=model)

    # benign run over the whole flight; only the held-out second half is scored
    eng = engine()
    wall0 = time.perf_counter()
    benign_alerts = eng.run(msgs)
    wall = time.perf_counter() - wall0
    benign = score(benign_alerts, [], split, t1)
    proc_us = [ns / 1000 for ns in eng.proc_ns]
    msg_rate = len(msgs) / (t1 - t0)
    mean_us = statistics.fmean(proc_us)
    compute = {
        "messages": len(msgs), "flight_s": round(t1 - t0, 1), "log_msg_rate_hz": round(msg_rate, 1),
        "mean_us_per_msg": round(mean_us, 2), "p99_us_per_msg": round(_pct(proc_us, 0.99), 2),
        "max_us_per_msg": round(max(proc_us), 1), "throughput_msgs_per_s": round(len(msgs) / wall),
        "cpu_pct_of_one_core_at_log_rate": round(100 * mean_us * 1e-6 * msg_rate, 3),
        "peak_rss_mb_incl_loaded_log": round(psutil.Process(os.getpid()).memory_info().rss / 2**20, 1),
    }

    air = airborne_times(msgs)
    rng = random.Random(seed)
    per_class = {}
    for cls in ATTACKS:
        starts = pick_starts(air, split + 60.0, t1 - 45.0, n_per_class, 90.0, rng)
        attacks = [make_attack(cls, s, i, seed) for i, s in enumerate(starts)]
        stream = msgs
        for a in attacks:
            stream = a.apply(stream)
        alerts = engine().run(stream)
        result = score(alerts, [Instance(cls, a.start, a.end, a.variant) for a in attacks], split, t1)
        result["detection_95ci_wilson"] = wilson_interval(result["detected"], result["instances"])
        result["latency_p50_s"] = _pct(result["latencies"], 0.50)
        result["latency_p95_s"] = _pct(result["latencies"], 0.95)
        per_class[cls.value] = result

    total = sum(r["instances"] for r in per_class.values())
    lat = [x for r in per_class.values() for x in r["latencies"]]
    eval_h = (t1 - split) / 3600
    return {
        "config": {"seed": seed, "n_per_class": n_per_class, "use_ml": use_ml, "split_t": split, "grace_s": GRACE_S},
        "thresholds": thresholds,
        "benign": {"eval_hours": round(eval_h, 3), "false_positives": benign["false_positives"],
                   "fp_per_hour": round(benign["false_positives"] / eval_h, 2),
                   "false_positive_alerts": benign["false_positive_alerts"]},
        "per_class": per_class,
        "overall": {"instances": total,
                    "detected": sum(r["detected"] for r in per_class.values()),
                    "detection_accuracy": round(sum(r["detected"] for r in per_class.values()) / total, 3) if total else None,
                    "detection_95ci_wilson": wilson_interval(sum(r["detected"] for r in per_class.values()), total),
                    "detection_rate_any_class": round(sum(r["detected_any"] for r in per_class.values()) / total, 3) if total else None,
                    "latency_p50_s": _pct(lat, 0.5), "latency_p95_s": _pct(lat, 0.95),
                    "latency_max_s": max(lat) if lat else None},
        "compute": compute,
    }


def write_results(results: dict, out_dir: str | Path) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    o, b, c = results["overall"], results["benign"], results["compute"]
    lines = [
        "# Drone IDS benchmark results", "",
        f"Flight: {c['flight_s']} s, {c['messages']} MAVLink messages; calibrated on first half, evaluated on second half "
        f"({b['eval_hours']} h). Seed {results['config']['seed']}, ML {'on' if results['config']['use_ml'] else 'off'}.", "",
        "| Metric | Value |", "|---|---|",
        f"| Detection accuracy (correct class) | {o['detection_accuracy']} over {o.get('detected', 'n/a')}/{o['instances']} instances; "
        f"Wilson 95% CI {o.get('detection_95ci_wilson', 'not available')} |",
        f"| Detection rate (any class) | {o['detection_rate_any_class']} |",
        f"| False positives on held-out benign flight | {b['false_positives']} ({b['fp_per_hour']} / flight-hour); one-sided 95% Poisson upper bound "
        f"{round(-math.log(0.05) / b['eval_hours'], 2) if b['false_positives'] == 0 and b['eval_hours'] > 0 else 'not computed'} / h |",
        f"| Detection latency p50 / p95 / max | {o['latency_p50_s']} / {o['latency_p95_s']} / {o['latency_max_s']} s |",
        f"| Processing time mean / p99 | {c['mean_us_per_msg']} / {c['p99_us_per_msg']} µs per message |",
        f"| CPU at the log's real message rate ({c['log_msg_rate_hz']} msg/s) | {c['cpu_pct_of_one_core_at_log_rate']} % of one core |",
        f"| Throughput | {c['throughput_msgs_per_s']} msg/s |", "",
        "| Attack class | Detected / instances | Wilson 95% CI | FP alerts | Latency p50 / p95 (s) | Confusion |",
        "|---|---:|---|---:|---|---|",
    ]
    for cls, r in results["per_class"].items():
        lines.append(f"| {cls} | {r['detected']} / {r['instances']} | {r.get('detection_95ci_wilson', 'n/a')} | "
                     f"{r['false_positives']} | {r.get('latency_p50_s')} / {r.get('latency_p95_s')} | "
                     f"{r['confusion'].get(cls, {})} |")
    (out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
