# Drone Forensic Toolkit

Indigenous drone forensic acquisition, analysis, and reporting toolkit —
built for **PUSHPAK Grand Challenge 3 ("Security of Drones"), Objective 1:
Drone Forensics Toolkit Development**.

See [`docs/design_document.md`](docs/design_document.md) for the full Stage 1
preliminary design submission (architecture, methodology, evaluation-criteria
mapping, scope, and roadmap). This README covers running the code.

## What's actually implemented vs. designed-only

This is stated up front because the toolkit's own reports say the same thing:

| Capability | Status |
|---|---|
| ArduPilot dataflash log (`.bin`/`.log`) and MAVLink telemetry log (`.tlog`) acquisition, parsing, timeline reconstruction, flight-path export | **Implemented and tested** — both the dataflash record set (`MSG`/`MODE`/`EV`/`GPS`) and the live MAVLink telemetry stream (`HEARTBEAT`/`STATUSTEXT`/`GPS_RAW_INT`) are handled; the latter against a real public `.tlog` sample |
| PX4 ULog acquisition/parsing — ARM/DISARM events, flight-mode-change events, status-text events, chronologically sorted timeline, flight summary (duration, max speed, arm/disarm counts) — against a real public sample `.ulg` log | **Implemented and tested** — flight-path/map/KML/GeoJSON extraction is implemented in code (gated on GPS-referenced global position) but not exercised end-to-end by the bundled sample: that log has no GPS fix, so `flight_path` is correctly empty (with an explicit warning) rather than fabricated |
| Altitude-anomaly flagging (implausible vertical rate) | **Implemented and tested** — fires on 17 real anomalies in the sample log |
| SHA-256 evidence hashing + hash-chained, tamper-evident chain-of-custody log | **Implemented and tested** |
| Automated HTML + PDF forensic report generation, with a SHA-256 hash of each recorded in the chain-of-custody log | **Implemented and tested** |
| Modular parser-plugin architecture (`BaseParser`) | **Implemented** |
| DJI proprietary log parsing | **Partially implemented** — header-only metadata (format version, header-declared detail offset/length, encryption status); the record/telemetry stream itself is not decoded (proprietary, AES-encrypted from format version 13 onward) |
| Remote controller physical acquisition | Architected, **not implemented** — no physical RC hardware available |
| Mobile companion app extraction | Architected, **not implemented** — no test device/backup available |
| Local web-based case-management GUI (FastAPI + browser frontend) over the same pipeline | **Implemented and tested** |
| Graceful handling of corrupt/truncated/unreadable evidence (explicit `PARSE_ERROR` outcome, no unhandled crash, no leaked file handles) | **Implemented and tested** |
| Removable-media file carving (JPEG/MP4/PNG, signature-based) | **Implemented and tested** |
| Aerial media metadata extraction — capture timestamp and GPS position from carved JPEGs via a hand-rolled EXIF/TIFF IFD reader | **Implemented and tested** — JPEG only (no MP4/video subtitle telemetry); best-effort, returns `None` on missing/malformed EXIF rather than guessing |
| Restricted-airspace / no-fly-zone incursion detection (static snapshot dataset) | **Implemented and tested** — dataset is a hand-compiled static snapshot, not a live feed; see the disclaimer in [the design spec](docs/superpowers/specs/2026-09-15-airspace-incursion-design.md#data-source-decision--resolved-2026-09-18) and `sample_data/README.md` for exactly what it does and doesn't cover |

Running `analyze` against unimplemented platforms produces an explicit
"not implemented" result in the evidence timeline and report, rather than a
silent empty one.

## Planned enhancements (approved 2026-09-15)

Beyond the future work already scoped in
[`docs/design_document.md`](docs/design_document.md) (RC/mobile hardware
acquisition, full DJI record decoding), the following were brainstormed and
approved for the remaining Stage 1 submission window. Small, self-contained
items were implemented directly (see the table above); larger ones were
turned into design specs + task-by-task implementation plans under
`docs/superpowers/` rather than rushed, since they touch a new dependency,
need an external sample file, or need a judgment call on data sourcing/
claims before code should be written:

| Enhancement | Status |
|---|---|
| PDF report export (alongside the existing HTML report), with both files' SHA-256 hashes recorded in the chain-of-custody log | **Implemented and tested** |
| Robustness hardening: corrupt/empty/truncated evidence produces a clean `PARSE_ERROR` result instead of an unhandled crash; underlying parser library file handles and stdout noise are now properly contained | **Implemented and tested** |
| PX4 ULog parser — a second fully-implemented flight-log platform alongside ArduPilot | **Implemented and tested** (see capability table above) — Spec: [`docs/superpowers/specs/2026-09-15-px4-ulog-parser-design.md`](docs/superpowers/specs/2026-09-15-px4-ulog-parser-design.md) · Plan: [`docs/superpowers/plans/2026-09-15-px4-ulog-parser.md`](docs/superpowers/plans/2026-09-15-px4-ulog-parser.md) |
| Removable-media file carving (JPEG/MP4/PNG recovery from a raw SD-card image, signature-based, independent of filesystem metadata) | **Implemented and tested** — Spec: [`docs/superpowers/specs/2026-09-15-media-carving-design.md`](docs/superpowers/specs/2026-09-15-media-carving-design.md) · Plan: [`docs/superpowers/plans/2026-09-15-media-carving.md`](docs/superpowers/plans/2026-09-15-media-carving.md) |
| Restricted-airspace / no-fly-zone incursion correlation against the recovered flight path | **Implemented and tested** (see capability table above) — Spec: [`docs/superpowers/specs/2026-09-15-airspace-incursion-design.md`](docs/superpowers/specs/2026-09-15-airspace-incursion-design.md) · Plan: [`docs/superpowers/plans/2026-09-15-airspace-incursion.md`](docs/superpowers/plans/2026-09-15-airspace-incursion.md) |
| Short end-to-end demo video for judges | Human task (screen recording) — checklist: [`docs/demo_recording_checklist.md`](docs/demo_recording_checklist.md) |

## Objective 2: Drone IDS

`ids/` is a MAVLink intrusion detection system for **PUSHPAK Grand Challenge 3, Objective 2**. It detects six
attack classes (GPS spoofing, MAVLink anomalies, command injection, telemetry manipulation, DoS, firmware
integrity) from a MAVLink stream, with thresholds calibrated on benign flight data and an HMAC-signed,
hash-chained alert log. On the bundled real flight (calibrate on the first half, evaluate on the held-out half,
0.339 h) it detected 20/20 injected attack instances with 0 false positives, p50/p95 latency 0.15/4.0 s and
about 3.5 us per message. Caveats: one flight, attacks authored by us, replay-mode GPS spoofing is open-loop, and
ArduPilot SITL was **not** run (live mode is verified over loopback UDP only).

```bash
pip install -e .
python -m ids calibrate sample_data/ardupilot_sample.tlog --out profile --frac 0.5
python -m ids replay sample_data/ardupilot_sample.tlog --profile profile --attack gps_spoofing@1500:0
python -m ids bench sample_data/ardupilot_sample.tlog --out bench_out
```

Stage 2 engineering updates include timer-driven heartbeat-loss checks, authenticated calibration-profile files,
benchmark confidence intervals and Windows/VS Code setup. See [`docs/ids/stage2_readiness.md`](docs/ids/stage2_readiness.md)
for the PUSHPAK Stage 2 rubric mapping and evidence still required. The full test suite and Mission Planner / SITL
must still be run on a machine with dependencies installed; no actual flight or HIL result is claimed here.

Full documentation: [`docs/ids/README.md`](docs/ids/README.md) (install, commands, module map, implemented vs.
designed-only table) - Stage 1 proposal: [`docs/ids/proposal.md`](docs/ids/proposal.md) /
[`proposal.pdf`](docs/ids/proposal.pdf) - demo script: [`docs/ids/demo_script.md`](docs/ids/demo_script.md).
`python -m ids live --dashboard PORT` serves a live alert dashboard (needs `pip install -e ".[web]"`).

## Requirements

- Python 3.10+
- `pip install -e .` (installs `pymavlink`, `Jinja2`, `simplekml`, `xhtml2pdf`)

## Quick start (end-to-end demo)

```bash
pip install -e .

python -m toolkit.cli init-case \
  --case-dir cases/demo_case --examiner "A. Examiner" \
  --description "Demo case"

python -m toolkit.cli acquire \
  --case-dir cases/demo_case --source sample_data/ardupilot_sample.bin \
  --platform ardupilot --examiner "A. Examiner" \
  --description "ArduCopter dataflash log, public sample"

python -m toolkit.cli analyze --case-dir cases/demo_case --examiner "A. Examiner"

python -m toolkit.cli report --case-dir cases/demo_case --examiner "A. Examiner"

python -m toolkit.cli verify --case-dir cases/demo_case
```

This produces:
- `cases/demo_case/evidence/` — forensic copy of the acquired log
- `cases/demo_case/custody_log.json` — hash-chained chain-of-custody log
- `cases/demo_case/analysis/<evidence_id>/result.json` — extracted timeline, flight summary, flight path
- `cases/demo_case/analysis/<evidence_id>/flight_path.kml` / `.geojson` — flight path for Google Earth / QGIS
- `cases/demo_case/reports/forensic_report.html` / `.pdf` — the forensic report

`sample_data/` contains a real, public ArduCopter dataflash log used purely
for demonstration (see `sample_data/README.md`); no physical drone hardware
was available for this submission window.

A committed snapshot of this exact run's output — report, KML/GeoJSON,
raw analysis JSON, custody log — is in
[`docs/sample_report/`](docs/sample_report/), so it can be reviewed without
running anything.

The same sequence also works against the bundled PX4 sample
(`sample_data/px4_sample.ulg`), using `--platform px4`:

```bash
python -m toolkit.cli init-case \
  --case-dir cases/px4_demo_case --examiner "A. Examiner" \
  --description "PX4 demo case"

python -m toolkit.cli acquire \
  --case-dir cases/px4_demo_case --source sample_data/px4_sample.ulg \
  --platform px4 --examiner "A. Examiner" \
  --description "PX4 ULog, public sample"

python -m toolkit.cli analyze --case-dir cases/px4_demo_case --examiner "A. Examiner"

python -m toolkit.cli report --case-dir cases/px4_demo_case --examiner "A. Examiner"

python -m toolkit.cli verify --case-dir cases/px4_demo_case
```

This produces the same kind of case directory as the ArduPilot run above
(ARM and flight-mode-change events, a flight summary, an HTML/PDF report),
except `analysis/<evidence_id>/result.json`'s `flight_path` is `[]` and no
`flight_path.kml`/`.geojson` is written — this particular sample log never
achieves a GPS-referenced position fix (it looks like an indoor/bench
recording), and the parser correctly reports an empty flight path with an
explanatory warning rather than fabricating coordinates. The report renders
that same warning instead of a map for this evidence item.

## GUI (optional)

```bash
pip install -e ".[web]"
python -m toolkit.web
```

Opens a browser at `http://127.0.0.1:8000` with a case list, per-case
acquire/analyze/report/verify actions, and views for the timeline, flight
path map, custody log, and generated report — backed by the same
`toolkit.service` functions the CLI uses.

## Running tests

```bash
pip install -e . pytest
python -m pytest -q
```

The full run is 205 tests (101 of them cover the Objective 2 IDS in `tests/test_ids_*.py`). The Objective 1 tests: unit tests for hashing, chain-of-custody (including tamper
detection), the case model, KML/GeoJSON export, ArduPilot parsing
(including altitude-anomaly detection and corrupt/empty-file robustness),
DJI header-metadata parsing (against synthetic headers — no real DJI
sample was available), and PDF report rendering; CLI-level integration
tests that run the actual `init-case → acquire → analyze → report →
verify` command sequence as subprocesses, including one that corrupts
acquired evidence on disk and confirms `verify` catches it;
`toolkit.service` unit tests exercising the shared pipeline logic directly
(including the single-item-vs-bulk error semantics for both integrity
failures and unparseable evidence); and FastAPI `TestClient` tests
covering the web API's full pipeline and error-mapping behavior.

## Project layout

```
toolkit/
  core/       case model, SHA-256 hashing, chain-of-custody, timeline model
  parsers/    BaseParser interface + ArduPilotParser (implemented),
              DJIParser (header-metadata-only), and RC/mobile-app stubs
              (architected, not implemented)
  report/     Jinja2 HTML report generator + template, PDF export
  geo.py      KML/GeoJSON flight-path export
  service.py  shared pipeline logic (used by both cli.py and web/)
  cli.py      init-case / acquire / analyze / report / verify commands
  web/        FastAPI backend + static HTML/CSS/JS case-management GUI
docs/design_document.md   Stage 1 preliminary design submission
docs/sample_report/        committed snapshot of a real generated report
sample_data/                public sample ArduPilot log used for the demo
tests/                      pytest suite (unit + CLI integration)
```
