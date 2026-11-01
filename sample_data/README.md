# Sample data

- `ardupilot_sample.bin` — a real ArduCopter dataflash log (APM:Copter V3.3-dev, QUAD frame), sourced from the public [dronekit/dronekit-la-testdata](https://github.com/dronekit/dronekit-la-testdata) repository (`log171.bin`), used here for demonstration and testing only.
- `ardupilot_sample.tlog` — a companion MAVLink telemetry log from the same source repository (`flight.tlog`), now exercised by `tests/test_ardupilot_parser.py::test_parse_tlog_extracts_arm_mode_and_flight_path` (ARM/DISARM, mode changes, status text, and a 6,338-point GPS flight path recovered from `HEARTBEAT`/`STATUSTEXT`/`GPS_RAW_INT` telemetry, as distinct from the dataflash `MSG`/`MODE`/`EV`/`GPS` records the parser reads from `.bin`).
- `px4_sample.ulg` — a real PX4 ULog flight log (HolyBro QAV250 quadrotor, ~60s flight, logged 2026-04-03), sourced from the public [PX4/flight_review](https://review.px4.io) log database (`log_id: dabd0a12-e88c-4379-9eec-c15000ae26ec`, `https://review.px4.io/plot_app?log=dabd0a12-e88c-4379-9eec-c15000ae26ec`). Public logs on review.px4.io are licensed [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) with attribution to PX4; used here for demonstration and testing only.

These are third-party public test fixtures, not evidence acquired for this submission from any physical drone. They exist so the toolkit's acquisition → analysis → reporting pipeline can be run and verified end-to-end without requiring physical UAV hardware, per the honestly-scoped plan for this submission window.

## No-fly-zone dataset (`toolkit/data/no_fly_zones.json`)

`toolkit/data/no_fly_zones.json` bundles six illustrative restricted-airspace
zones (four circles, two polygons) used by `toolkit.airspace` for incursion
detection. The plan's suggested source is the public
[OurAirports](https://ourairports.com/data/) `airports.csv` (public domain /
CC0), but this sandboxed environment has no live internet fetch tool, so
that CSV was not actually downloaded or ingested. Instead, this file is a
small, hand-compiled set of real, well-known airport coordinates (JFK,
Heathrow, Haneda, Dubai, Charles de Gaulle, LAX) drawn from public/training
knowledge, each paired with an illustrative ATZ-style radius or a rough
approximate boundary polygon — not an official published no-fly-zone
boundary, not a real ATZ radius, and not a full CSV ingestion pipeline. Each
zone entry's `source_note` field states this plainly. Like the ArduPilot and
PX4 samples above, this is treated as a static, version-controlled snapshot
for reproducibility — nothing is fetched over the network at analysis time.
