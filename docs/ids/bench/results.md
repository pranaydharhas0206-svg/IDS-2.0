# Drone IDS benchmark results

Flight: 2443.8 s, 163851 MAVLink messages; calibrated on first half, evaluated on second half (0.339 h). Seed 7, ML off.

| Metric | Value |
|---|---|
| Detection accuracy (correct class) | 1.0 over 20 attack instances |
| Detection rate (any class) | 1.0 |
| False positives on held-out benign flight | 0 (0.0 / flight-hour) |
| Detection latency p50 / p95 / max | 0.15 / 4.005 / 4.005 s |
| Processing time mean / p99 | 3.46 / 14.7 µs per message |
| CPU at the log's real message rate (67.0 msg/s) | 0.023 % of one core |
| Throughput | 266116 msg/s |

| Attack class | Detected / instances | False positives | Latencies (s) | Confusion |
|---|---|---|---|---|
| gps_spoofing | 4 / 4 | 0 | [0.38, 4.005, 0.311, 3.903] | {'gps_spoofing': 4} |
| command_injection | 3 / 3 | 0 | [0.0, 0.0, 0.0] | {'command_injection': 3} |
| telemetry_manipulation | 3 / 3 | 1 | [0.033, 1.836, 0.442] | {'telemetry_manipulation': 3} |
| mavlink_anomaly | 4 / 4 | 0 | [0.052, 0.0, 0.15, 0.0] | {'telemetry_manipulation': 2, 'mavlink_anomaly': 4, 'gps_spoofing': 1} |
| dos | 3 / 3 | 0 | [0.333, 0.34, 0.333] | {'dos': 3, 'mavlink_anomaly': 3} |
| firmware_integrity | 3 / 3 | 0 | [0.0, 0.0, 0.0] | {'firmware_integrity': 3} |
