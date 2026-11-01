# Drone Forensic Toolkit — Stage 1 Preliminary Design

**PUSHPAK Grand Challenge 3 (Security of Drones) — Objective 1: Drone Forensics Toolkit Development**

This document is the Stage 1 preliminary design submission required by §1.4
of the challenge brief. It covers architecture, forensic methodology,
supported platforms, acquisition workflow, hardware interfaces, evidence
preservation, chain-of-custody, hashing, metadata extraction, reporting,
software architecture, risk assessment, and validation methodology — and is
explicit throughout about what is implemented today versus what is designed
for Stage 2.

A working reference implementation accompanies this document in this same
repository (see `README.md`); it is a proof-of-concept for one platform
end-to-end, not a finished multi-platform product. That distinction is the
central honesty constraint of this submission and is treated as a feature,
not a hedge: every claim below is either demonstrated in code or explicitly
marked as planned.

---

## 1. Objective recap

Design, develop, and validate an indigenous Drone Forensic Toolkit capable
of acquiring, preserving, analyzing, and reporting digital evidence from
UAVs and associated components in a forensically sound, repeatable, and
legally defensible manner, across onboard storage, flight controllers,
remote controllers, removable media, and companion mobile applications.

## 2. Forensic methodology

The toolkit follows the standard four-phase digital forensics model
(**Identification → Acquisition → Analysis → Reporting**), adapted for the
specifics of UAV evidence:

1. **Identification** — determine the evidence sources present for a given
   incident (flight controller storage, dataflash logs, telemetry logs, RC
   unit, removable SD/microSD media, companion app data on a paired mobile
   device) and the platform/vendor involved.
2. **Acquisition** — create a forensic copy of each source, compute a
   cryptographic hash of the original and the copy at acquisition time, and
   open a chain-of-custody record before any analysis touches the copy.
   Analysis is always performed on the copy, never the original.
3. **Analysis** — platform-specific parsers convert raw, vendor-specific
   log formats into a single normalized evidence model (timeline events +
   flight path + flight summary), so every downstream step — reporting,
   visualization, cross-referencing — is platform-agnostic.
4. **Reporting** — an automatically generated report presents the evidence
   inventory, the chain-of-custody log (with cryptographic self-verification),
   the reconstructed timeline, flight path, and extracted metadata, plus an
   explicit statement of what was and was not analyzed.

This methodology is intentionally evidence-preserving by construction: the
acquisition step is the only step permitted to touch original media, hashing
happens before any parsing, and every subsequent action against a piece of
evidence is appended to an immutable, tamper-evident log (§6).

## 3. Supported UAV platforms

| Platform / source | Status this submission | Notes |
|---|---|---|
| ArduPilot (dataflash `.bin`/`.log`, MAVLink `.tlog`) | **Implemented** | Via `pymavlink`; covers ArduCopter/Plane/Rover, the dominant open flight-stack family. |
| DJI proprietary flight logs (`.DAT`) | Header metadata only | Format version, header-declared detail-section offset/length, and encryption status are extracted from the fixed unencrypted 100-byte Prefix header (reverse-engineered layout, not vendor-documented, not validated against a real sample). Record/telemetry decoding not implemented. See §10 (risk assessment) for why. |
| Remote controller onboard storage | Designed, not implemented | Requires physical hardware access (§4.2). |
| Companion mobile application data (e.g. DJI Fly, Litchi caches) | Designed, not implemented | Requires a physical test device/backup (§4.3). |
| Onboard removable media (SD/microSD, generic filesystem evidence) | Partially covered | Any file on such media that is itself an ArduPilot dataflash log is already handled by the acquisition/hashing pipeline; general filesystem-level forensics (deleted file recovery, carving) is future work. |

The reference implementation demonstrates the full pipeline against a real
ArduCopter dataflash log. Extending platform coverage is a matter of adding
new `BaseParser` implementations (§7.2) — the acquisition, chain-of-custody,
reporting, and CLI layers do not change.

## 4. Digital evidence acquisition workflow

### 4.1 Onboard flight-controller storage / dataflash & telemetry logs (implemented)

1. Examiner runs `toolkit acquire --source <file> --platform ardupilot
   --examiner <name>`.
2. The toolkit copies the source file byte-for-byte into the case's
   `evidence/` directory (a write-once forensic copy; the original is never
   opened again by the toolkit).
3. SHA-256 is computed over the copy and recorded against the evidence
   record and the chain-of-custody log in the same operation, so there is
   no window where a hash could be recorded against a since-modified file.
4. `toolkit analyze` re-verifies the hash immediately before parsing (catching
   any tampering or corruption between acquisition and analysis) and only
   then invokes the platform parser.

### 4.2 Remote controller acquisition (designed, not implemented)

Planned workflow for Stage 2: physical connection to the RC unit's
diagnostic/service port (model-dependent — USB, UART, or eMMC), imaged
through a hardware write-blocker, hashed identically to §4.1. Where the
storage is not directly accessible (soldered eMMC, locked bootloader),
chip-off or JTAG acquisition is the fallback, which requires lab equipment
not available in this submission window. This is disclosed rather than
simulated.

### 4.3 Companion mobile application acquisition (designed, not implemented)

Planned workflow: logical acquisition via ADB backup (Android) or an iTunes/
Finder encrypted backup (iOS), extraction of the companion app's sandboxed
SQLite databases and cached flight records, and a dedicated parser
translating app-specific schemas into the same normalized timeline model
used for flight-controller data. Requires a physical test device.

### 4.4 Removable storage media

Generic removable media (SD/microSD) is acquired the same way as §4.1 when
it contains recognizable log files. Full filesystem-level forensic imaging
(dd/E01 imaging, deleted-file carving) is scoped for Stage 2 and would sit
behind the same `BaseParser`-style plugin boundary, operating on the
acquired image rather than a live device.

## 5. Hardware acquisition interfaces

| Interface | Use case | Status |
|---|---|---|
| USB mass storage / file copy | Flight controller SD cards, exported dataflash logs | Implemented (any file reachable via the filesystem) |
| MAVLink telemetry stream capture (`.tlog`) | Live telemetry capture during operation | Format supported by the parser; live capture tooling not built this submission |
| RC service port (USB/UART/eMMC) | Remote controller acquisition | Designed only — needs hardware in hand |
| ADB / mobile backup | Companion app acquisition | Designed only — needs a test device |
| Hardware write-blocker | Ensuring source media is never written to during acquisition | Process requirement, documented; the toolkit's software-side guarantee is that it opens sources read-only and immediately hashes the copy, not the source |

## 6. Evidence preservation & chain-of-custody methodology (implemented)

Every case is a self-contained directory. Every action taken against it —
case creation, acquisition, hash re-verification, analysis, report export —
appends one entry to `custody_log.json`. Each entry embeds the SHA-256 hash
of the *previous* entry, forming a hash chain (genesis entry chains to a
fixed all-zero value):

```
entry_hash(n) = SHA256(seq, timestamp, action, evidence_id, actor, detail,
                       evidence_sha256, prev_entry_hash(n))
```

`toolkit verify` recomputes every entry's hash and checks linkage; altering,
reordering, or deleting any past entry breaks every hash after it, which is
detected and reported (including *which* entry broke). This is a
practical, dependency-free substitute for a full blockchain/timestamp-
authority scheme, appropriate for this submission's timeframe; a hardware
security module or external timestamping service is noted as a Stage 2
hardening option (§10).

Evidence files themselves are never modified after acquisition; all
derived artifacts (timeline JSON, flight path exports, reports) are written
to separate `analysis/` and `reports/` directories.

## 7. Cryptographic hashing approach (implemented)

- **Algorithm**: SHA-256, computed by streaming the file in 1 MiB chunks
  (constant memory regardless of evidence size).
- **When computed**: immediately after the forensic copy is made
  (acquisition-time hash, stored in the evidence record and the custody
  log) and again immediately before analysis (re-verification, logged as
  its own custody event; a mismatch aborts analysis of that evidence and is
  logged as an `integrity_failure` event rather than silently proceeding).
- **Why SHA-256**: collision-resistant, hardware-accelerated on essentially
  all modern CPUs, and the de facto standard accepted in digital forensics
  and legal proceedings (e.g. NIST-recommended for evidentiary hashing).

### 7.1 Metadata extraction strategy (implemented for ArduPilot)

The ArduPilot parser (`toolkit/parsers/ardupilot.py`) converts raw MAVLink/
dataflash messages into:

- **Timeline events** — arm/disarm, flight-mode changes, GPS-fix acquisition,
  mission commands, firmware/frame identification, system error codes, raw
  status text, and flagged altitude anomalies (below) — each with a UTC
  timestamp derived from the log's own time reference (not wall-clock at
  analysis time).
- **Flight summary** — firmware version, frame type, flight start/end time
  and duration, max altitude, max ground speed, total track distance
  (haversine over the GPS track), arm/disarm counts, GPS track point count,
  altitude anomaly count.
- **Flight path** — the full GPS track (lat/lon/alt/timestamp), independent
  of the event timeline, feeding KML/GeoJSON export for Google Earth/QGIS.
- **Anomaly flagging** — consecutive GPS altitude samples implying a
  vertical rate beyond any plausible multirotor/fixed-wing climb or descent
  (>15 m/s) are flagged as `ALTITUDE_ANOMALY` timeline events rather than
  silently smoothed over. This is deliberately not auto-classified as
  "noise" vs. "spoofing/jamming" — that judgment is left to the examiner —
  but it is surfaced instead of hidden. This isn't hypothetical: the public
  sample log bundled with this submission (`sample_data/ardupilot_sample.bin`)
  genuinely contains 17 such anomalies near the end of the flight, and the
  toolkit flags all of them (see `docs/sample_report/`).

### 7.2 Extensibility strategy (implemented as an interface, proven with one platform)

All parsers implement `toolkit.parsers.base.BaseParser`:

```python
class BaseParser(ABC):
    def can_parse(self, evidence_path: Path) -> bool: ...
    def parse(self, evidence_path: Path) -> ParserResult: ...
```

`ParserResult` is the single normalized shape (`events`, `flight_summary`,
`flight_path`, `warnings`, `implemented`) that every downstream component —
chain-of-custody logging, report generation, KML/GeoJSON export — consumes.
Adding a new platform means writing one new parser class and registering it
in `toolkit.parsers.REGISTRY`; no other layer changes. The DJI, remote-
controller, and mobile-app stubs already implement this interface today,
returning an explicit "not implemented" `ParserResult` (with a stated
reason) rather than an empty or fabricated one, so gaps are visible in the
generated report rather than silently absent.

## 8. Reporting framework (implemented)

`toolkit report` renders a self-contained HTML report (Jinja2 template)
containing:

1. Case metadata (case ID, examiner, creation time, description).
2. Evidence inventory (filenames, platform, acquisition time, SHA-256).
3. The full chain-of-custody log plus a pass/fail hash-chain verification
   result.
4. Per-evidence analysis: flight summary table, full timeline, links to the
   generated flight-path KML/GeoJSON, and any parser warnings.
5. An explicit "not analyzed" notice, with reason, for evidence from
   unimplemented platforms.
6. A scope/limitations section pointing back to this design document.

HTML was chosen over PDF for this submission for speed and reproducibility
(no native-rendering dependency); PDF/A export (for long-term archival, a
common forensic-report requirement) is noted as Stage 2 work (§10).

## 9. Software architecture

```
toolkit/
  core/
    case.py             Case + Evidence data model, JSON persistence
    hashing.py          streaming SHA-256
    custody.py          hash-chained chain-of-custody log
    timeline.py         normalized TimelineEvent model, merge/sort utilities
  parsers/
    base.py             BaseParser interface, ParserResult, NotImplementedParser
    ardupilot.py        implemented ArduPilot dataflash/telemetry parser
    dji_stub.py         designed-only DJI parser
    rc_stub.py          designed-only remote-controller parser
    mobile_app_stub.py  designed-only companion-app parser
  geo.py                KML/GeoJSON flight-path export
  report/
    generator.py        Jinja2 report rendering
    templates/           HTML report template
  cli.py                init-case / acquire / analyze / report / verify commands
```

Design choices:
- **Plugin-per-platform** (§7.2) for vendor independence and extensibility,
  directly answering the "modular, scalable, vendor-independent, easily
  extensible" requirement in §1.2 of the brief.
- **Filesystem-based case storage** (plain directories + JSON) rather than a
  database, for this submission: zero setup, trivially portable/archivable
  as a single folder, human-inspectable without special tooling — all
  desirable properties for evidence handling. A database backend (for
  large-scale, multi-case deployments) is a Stage 2 option, not a Stage 1
  requirement.
- **CLI-first**, no GUI: prioritizes the forensic pipeline itself being
  correct and automatable (scriptable, CI-testable) over presentation. A
  GUI/case-management front-end is future work (§10).

## 10. Risk assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| DJI and other proprietary formats resist reverse-engineering within Stage 2's timeframe | Limits platform coverage | Medium-High | Architecture already isolates format handling behind `BaseParser`; the fallback of metadata-only extraction from unencrypted header fields is now implemented for DJI (`toolkit/parsers/dji.py`) — format version, header-declared detail offset/length, and AES-encryption status, with everything past byte 99 of the file explicitly left undecoded |
| No physical drone/RC/mobile hardware available before Stage 2 funding | Can't validate acquisition workflows end-to-end | High (current), resolved once funded | Stage 2 funding (₹1 lakh, per §1.4) is explicitly earmarked for hardware acquisition; design already scopes exactly what hardware is needed (§4.2, §4.3) |
| Timestamp drift/absence in dataflash logs without GPS lock | Timeline accuracy for pre-GPS-fix events | Medium | Parser already flags "no 3D GPS fix" as a warning surfaced in the report rather than silently trusting an unreliable timestamp |
| Chain-of-custody log itself could be replaced wholesale (not just edited in place) | Integrity claim could be circumvented | Low-Medium | Stage 2 hardening: sign each case's custody log with an offline keypair and/or anchor periodic hashes to an external timestamping service |
| Legal admissibility standards vary by jurisdiction | Report may not satisfy every evidentiary regime unmodified | Medium | Report explicitly recommends independent re-verification of hashes before legal use; format designed to be extended with jurisdiction-specific report sections |
| Single-examiner assumption in current CLI (no multi-examiner access control) | Not suitable for multi-analyst lab workflows as-is | Medium | Acceptable for Stage 1 proof-of-concept; role-based access is Stage 2 scope |

## 11. Validation methodology

**This submission's validation** (implemented, reproducible, checked into
this repository):
- Unit tests (`tests/`) for hashing correctness/determinism, chain-of-custody
  construction/persistence/tamper-detection, case model round-tripping, KML/
  GeoJSON export correctness, ArduPilot parsing correctness (arm-event
  detection, chronological ordering, non-empty flight path, altitude-anomaly
  detection against the real sample log), and DJI header-metadata parsing
  correctness against synthetic headers (version/encryption classification,
  version-12+ offset override, out-of-range version handling, undersized-file
  handling) — 21 tests, run via `pytest`.
- CLI-level integration tests (`tests/test_cli.py`) that drive the actual
  `init-case → acquire → analyze → report → verify` command sequence as
  subprocesses (not just calling the underlying Python functions), including
  a test that deliberately corrupts acquired evidence on disk and confirms
  `toolkit verify` detects the hash mismatch and exits non-zero.
- An end-to-end demonstration (`README.md` "Quick start") against a real,
  public ArduCopter dataflash log, with a committed snapshot of the actual
  output in `docs/sample_report/` (report, KML/GeoJSON, raw analysis JSON,
  custody log) so it can be reviewed without installing anything.
- Repeatability: re-running `acquire`/`analyze`/`report` against the same
  source file is deterministic (same hash, same extracted events) and is
  exactly what `toolkit verify` checks at any later time.

**Stage 2 validation plan** (not yet executable — needs hardware/funding):
- Acquisition validation against ≥2 additional real UAV platforms (at least
  one DJI unit) using a hardware write-blocker, with hash comparison against
  an independently-taken reference hash.
- Timeline cross-validation: compare toolkit-reconstructed timelines against
  ground-truth flight logs captured independently (e.g. a second GCS logging
  the same flight).
- Chain-of-custody stress test: simulate multi-examiner handoffs and confirm
  the log accurately reflects every handoff.
- Legal-defensibility review with a forensics/legal domain expert against
  the target jurisdictions' evidentiary standards.

## 12. Mapping to evaluation criteria (§1.3)

| Criterion | Weight | This submission |
|---|---|---|
| Successful forensic acquisition from multiple drone platforms | 20% | ArduPilot fully implemented and demonstrated; DJI acquisition + header-metadata extraction implemented (full DJI decode, RC, and mobile explicitly scoped for Stage 2); multi-platform architecture in place |
| Evidence integrity using hashing and chain-of-custody | 20% | Fully implemented: streaming SHA-256, acquisition + pre-analysis re-verification, hash-chained tamper-evident custody log with automated verification |
| Ability to recover logs, telemetry, GPS, media, and configuration files | 20% | Logs/telemetry/GPS implemented for ArduPilot; parameter (config) extraction present in parsed data; DJI limited to header metadata (format version, encryption status); media/companion-app recovery scoped for Stage 2 |
| Completeness of forensic reporting | 15% | Automated report covers evidence inventory, custody log + verification, full timeline, flight summary, flight-path exports, and explicit scope/limitations |
| Automation and usability of forensic toolkit | 10% | Single CLI covers the full pipeline in five commands (init-case/acquire/analyze/report/verify); report and exports generated automatically with no manual data wrangling |
| Extensibility to new drone platforms | 5% | `BaseParser` interface, `REGISTRY`-based plugin loading, three stub implementations already conforming to the interface |
| Documentation and reproducibility | 5% | This document, README with exact reproducible commands, inline code documentation, automated test suite |
| Future integration potential | 5% | Filesystem-based case model and normalized evidence schema (`ParserResult`/`TimelineEvent`) are designed to be easy to wrap with a REST API, database backend, or case-management GUI without touching parsing/acquisition logic |

## 13. Honesty statement

This design explicitly does not claim multi-platform acquisition, physical
RC/mobile forensics, or DJI log decoding as working today. What is claimed
as working is backed by runnable code and a passing test suite in this
repository. The gap between what's designed and what's implemented is
Stage 2's scope, and is exactly what the requested ₹1 lakh Stage 2 funding
and two-month timeline (per §1.4) are structured to close.
