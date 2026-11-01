# ML ablation: rules-only vs rules + IsolationForest layer

Same flight (`sample_data/ardupilot_sample.tlog`), same seed (7), same split (calibrate on first half, evaluate on held-out second half, 0.339 h benign), same 20 attack instances. No-ML results: `../bench/`; ML results: this directory. The ML layer is opt-in (`build_engine(..., ml_model=...)`); default wiring is unchanged.

| Metric | No ML | ML on |
|---|---|---|
| Detection accuracy (correct class) | 1.0 (20/20) | 1.0 (20/20) |
| Detection rate (any class) | 1.0 | 1.0 |
| False positives on held-out benign | 0 | 0 |
| FP / flight-hour | 0.0 | 0.0 |
| Latency p50 / p95 / max (s) | 0.15 / 4.005 / 4.005 | 0.15 / 4.005 / 4.005 |
| Mean processing time (us/msg) | 3.46 | 43.25 |
| p99 / max processing time (us/msg) | 14.7 / 133.9 | 2528.8 / 4658.5 |
| Throughput (msg/s) | 266,116 | 22,916 |
| CPU at log rate (67 msg/s) | 0.023 % | 0.29 % |
| Peak RSS incl. loaded log (MB) | 169.3 | 285.9 |

Per-class detection (detected / instances, identical latencies in both runs):

| Attack class | No ML | ML on | Extra confusion labels with ML |
|---|---|---|---|
| gps_spoofing | 4 / 4 | 4 / 4 | none |
| command_injection | 3 / 3 | 3 / 3 | none |
| telemetry_manipulation | 3 / 3 | 3 / 3 | none |
| mavlink_anomaly | 4 / 4 | 4 / 4 | `anomaly` x2 |
| dos | 3 / 3 | 3 / 3 | `anomaly` x3 |
| firmware_integrity | 3 / 3 | 3 / 3 | none |

## Interpretation

The ML layer does not raise FP/hour (0 in both runs), so the training-range envelope (`OOD_FACTOR = 3.0`) needed no root-causing or tuning. It also adds no measurable detection benefit on this benchmark: accuracy, detection rate and latency are identical because the rule detectors already catch all six classes; the ML layer only corroborates the dos and mavlink_anomaly instances with unclassified `anomaly` evidence (5 extra confusion labels, never the winning class). Its cost is roughly 12x mean per-message time (3.46 to 43.3 us), a multi-millisecond p99 (per-window IsolationForest scoring), and about 117 MB more memory, which is still under 0.5 % of one core at the log's real message rate. Caveat: the benign evaluation is a single 0.339 h flight, so "0 FP" bounds the rate only loosely, and the synthetic attacks were designed with the rule detectors in mind, so the ML layer's value on unmodelled attacks is untested here.

## Changes to ids/detectors/ml.py

None. `ml.py` and `tests/test_ids_ml.py` are unchanged from the Task 9 commit.
