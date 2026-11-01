"""Shared business logic for the drone forensic toolkit's pipeline.

Both toolkit.cli and toolkit.web call these functions so the CLI and the
GUI share exactly one implementation of acquire/analyze/report/verify.
Functions raise ToolkitError subclasses instead of printing/exiting, so
each caller can present errors its own way (CLI: print + exit; web: HTTP
status code).
"""

from __future__ import annotations

import dataclasses
import json
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from toolkit.airspace import check_incursions, load_zones
from toolkit.carving import CarvedFile, carve_media
from toolkit.core.case import Case, Evidence, utcnow_iso
from toolkit.core.custody import ChainOfCustody
from toolkit.core.hashing import sha256_file, verify_file
from toolkit.core.timeline import TimelineEvent
from toolkit.geo import export_geojson, export_kml
from toolkit.parsers import get_parser
from toolkit.parsers.base import ParserError, ParserResult

AIRSPACE_DISCLAIMER = (
    "Airspace zone dataset is a static snapshot compiled 2026-09-18 from "
    "public airport coordinates (see sample_data/README.md for sourcing "
    "detail); not a live feed, and does not include time-windowed NOTAMs "
    "or TFRs. See docs/design_document.md for live-source integration "
    "planned for Stage 2."
)


class ToolkitError(Exception):
    """Base class for all service-layer errors."""


class CaseNotFoundError(ToolkitError):
    pass


class EvidenceNotFoundError(ToolkitError):
    pass


class ParseError(ToolkitError):
    pass


class IntegrityError(ToolkitError):
    pass


class AnalysisNotFoundError(ToolkitError):
    pass


def _load_case(case_dir: Path) -> Case:
    if not (case_dir / "case.json").exists():
        raise CaseNotFoundError(f"No case found at {case_dir}")
    return Case.load(case_dir)


def get_case(case_dir: Path) -> Case:
    return _load_case(case_dir)


def init_case(case_dir: Path, examiner: str, description: str = "") -> Case:
    case = Case.create(case_dir, examiner=examiner, description=description)
    custody = ChainOfCustody(case_dir)
    custody.record("case_opened", actor=examiner, detail=f"Case {case.case_id} created.")
    return case


@dataclass
class CaseSummary:
    case_id: str       # directory name relative to cases_root — routing key
    internal_id: str   # Case.case_id (uuid stored in case.json) — display only
    examiner: str
    created_at: str
    description: str
    evidence_count: int
    custody_ok: bool


def list_cases(cases_root: Path) -> list[CaseSummary]:
    summaries: list[CaseSummary] = []
    if not cases_root.exists():
        return summaries
    for case_dir in sorted(cases_root.iterdir()):
        if not case_dir.is_dir() or not (case_dir / "case.json").exists():
            continue
        case = Case.load(case_dir)
        custody = ChainOfCustody(case_dir)
        ok, _ = custody.verify_chain()
        summaries.append(CaseSummary(
            case_id=case_dir.name,
            internal_id=case.case_id,
            examiner=case.examiner,
            created_at=case.created_at,
            description=case.description,
            evidence_count=len(case.evidence),
            custody_ok=ok,
        ))
    return summaries


def acquire_evidence(
    case_dir: Path,
    source: Path,
    platform: str,
    examiner: str,
    description: str = "",
) -> Evidence:
    case = _load_case(case_dir)
    custody = ChainOfCustody(case_dir)

    if not source.is_file():
        raise ParseError(f"Source file not found: {source}")

    try:
        parser = get_parser(platform)
    except ValueError as exc:
        raise ParseError(str(exc)) from exc

    if not parser.can_parse(source):
        raise ParseError(f"'{source}' does not look like a {platform} log.")

    evidence_id = str(uuid.uuid4())
    dest_name = f"{evidence_id}_{source.name}"
    dest_path = case_dir / "evidence" / dest_name
    shutil.copy2(source, dest_path)

    digest = sha256_file(dest_path)

    evidence = Evidence(
        evidence_id=evidence_id,
        original_filename=source.name,
        platform=platform,
        source_description=description,
        acquired_path=str(Path("evidence") / dest_name),
        sha256=digest,
        acquired_at=utcnow_iso(),
        examiner=examiner,
    )
    case.add_evidence(case_dir, evidence)

    custody.record(
        "acquired",
        actor=examiner,
        detail=f"Acquired '{source.name}' as platform={platform}.",
        evidence_id=evidence_id,
        evidence_sha256=digest,
    )
    return evidence


def _carved_manifest_path(case_dir: Path) -> Path:
    return case_dir / "carved" / "manifest.json"


def _load_carved_manifest(case_dir: Path) -> list[dict]:
    """Read the cumulative record of every carved-file across all carve runs.

    Report generation reads this rather than re-scanning case_dir/carved/'s
    raw filenames, because the filename alone (carved_<offset>_<hash8>.<ext>)
    doesn't carry the fields the report needs (full hash, EXIF, whether a
    carve was truncated at the size cap, which source image it came from).
    """
    manifest_path = _carved_manifest_path(case_dir)
    if not manifest_path.exists():
        return []
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def carve_evidence(
    case_dir: Path,
    source: Path,
    examiner: str,
) -> list[CarvedFile]:
    """Signature-carve `source` (a raw disk/SD-card image) into case_dir/carved/.

    Not a BaseParser platform-log acquisition: `source` is a raw image, not
    a known-platform log, and the output is a set of recovered files rather
    than a timeline. Follows the same provenance pattern as
    acquire_evidence — one custody entry per carved file (evidence_id/
    evidence_sha256 = that carved file's own id/hash) plus a summary entry.

    Also appends each carved file to case_dir/carved/manifest.json, a
    cumulative record across every carve run against this case, which
    generate_case_report reads to populate the report's "Carved Media"
    section — mirroring how analyze_case persists analysis/<id>/result.json
    for generate_case_report to read back later.
    """
    _load_case(case_dir)
    custody = ChainOfCustody(case_dir)

    if not source.is_file():
        raise ParseError(f"Source file not found: {source}")

    out_dir = case_dir / "carved"
    carved_files = carve_media(source, out_dir)

    manifest = _load_carved_manifest(case_dir)
    for carved in carved_files:
        evidence_id = str(uuid.uuid4())
        custody.record(
            "carved",
            actor=examiner,
            detail=f"Carved {carved.file_type} file at offset {carved.offset} "
                    f"({carved.size} bytes) from '{source.name}' "
                    f"-> {carved.output_path.name}.",
            evidence_id=evidence_id,
            evidence_sha256=carved.sha256,
        )
        manifest.append({
            "evidence_id": evidence_id,
            "offset": carved.offset,
            "size": carved.size,
            "file_type": carved.file_type,
            "sha256": carved.sha256,
            "output_path": str(carved.output_path.relative_to(case_dir)),
            "exif": carved.exif,
            "source_filename": source.name,
        })

    custody.record(
        "carve_summary",
        actor=examiner,
        detail=f"Carved {len(carved_files)} file(s) from '{source.name}'.",
    )

    _carved_manifest_path(case_dir).write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    return carved_files


def _result_to_json(result: ParserResult) -> dict:
    return {
        "platform": result.platform,
        "events": [dataclasses.asdict(e) for e in result.events],
        "flight_summary": result.flight_summary,
        "flight_path": result.flight_path,
        "warnings": result.warnings,
        "implemented": result.implemented,
        "partial": result.partial,
    }


def _result_from_json(data: dict) -> ParserResult:
    events = [TimelineEvent(**e) for e in data["events"]]
    return ParserResult(
        platform=data["platform"],
        events=events,
        flight_summary=data["flight_summary"],
        flight_path=data.get("flight_path", []),
        warnings=data.get("warnings", []),
        implemented=data.get("implemented", True),
        partial=data.get("partial", False),
    )


def _extract_incursions(result: ParserResult) -> list[dict]:
    """Build a structured incursions table (zone, entry, exit, duration) for
    the report/GUI from AIRSPACE_INCURSION events' `extra` dicts."""
    from datetime import datetime

    incursions = []
    for event in result.events:
        if event.event_type != "AIRSPACE_INCURSION":
            continue
        extra = event.extra or {}
        zone_name = extra.get("zone_name")
        entry_ts = extra.get("entry_ts", event.timestamp_utc)
        exit_ts = extra.get("exit_ts")
        point_count = extra.get("point_count")
        duration_seconds = None
        if entry_ts and exit_ts:
            try:
                entry_dt = datetime.fromisoformat(entry_ts.replace("Z", "+00:00"))
                exit_dt = datetime.fromisoformat(exit_ts.replace("Z", "+00:00"))
                duration_seconds = (exit_dt - entry_dt).total_seconds()
            except ValueError:
                duration_seconds = None
        incursions.append({
            "zone_name": zone_name,
            "entry_ts": entry_ts,
            "exit_ts": exit_ts,
            "point_count": point_count,
            "duration_seconds": duration_seconds,
        })
    return incursions


@dataclass
class AnalysisOutcome:
    evidence_id: str
    original_filename: str
    platform: str
    status: str  # "OK" | "PARTIAL" | "NOT_IMPLEMENTED" | "INTEGRITY_FAILURE"
    event_count: int = 0
    track_point_count: int = 0
    warnings: list = field(default_factory=list)


def analyze_case(
    case_dir: Path,
    examiner: str,
    evidence_id: str | None = None,
    zones: list[dict] | None = None,
) -> list[AnalysisOutcome]:
    case = _load_case(case_dir)
    custody = ChainOfCustody(case_dir)

    targets = case.evidence
    if evidence_id:
        targets = [e for e in targets if e.evidence_id == evidence_id]
        if not targets:
            raise EvidenceNotFoundError(f"No evidence with id {evidence_id}")

    outcomes: list[AnalysisOutcome] = []
    for evidence in targets:
        evidence_path = case_dir / evidence.acquired_path

        if not verify_file(evidence_path, evidence.sha256):
            custody.record(
                "integrity_failure", actor=examiner,
                detail="Hash mismatch detected during analyze.",
                evidence_id=evidence.evidence_id,
            )
            # A caller analyzing one specific evidence item that fails
            # integrity should see a hard error (409 over the API). A bulk
            # "analyze everything" call should keep processing the rest and
            # report the failure per-item instead, matching the CLI's
            # original skip-and-continue behavior.
            if evidence_id is not None:
                raise IntegrityError(
                    f"Integrity check failed for evidence {evidence.evidence_id}: "
                    f"current hash does not match acquisition-time hash."
                )
            outcomes.append(AnalysisOutcome(
                evidence_id=evidence.evidence_id,
                original_filename=evidence.original_filename,
                platform=evidence.platform,
                status="INTEGRITY_FAILURE",
            ))
            continue

        custody.record(
            "hash_verified", actor=examiner,
            detail="Hash re-verified before analysis.",
            evidence_id=evidence.evidence_id, evidence_sha256=evidence.sha256,
        )

        parser = get_parser(evidence.platform)
        try:
            result = parser.parse(evidence_path)
        except ParserError as exc:
            custody.record(
                "parse_error", actor=examiner,
                detail=f"Parsing failed with {evidence.platform} parser: {exc}",
                evidence_id=evidence.evidence_id,
            )
            # Same policy as an integrity failure above: analyzing one
            # specific item that can't be parsed is a hard error, but a
            # bulk "analyze everything" call keeps going and reports the
            # failure per-item instead of aborting the whole run.
            if evidence_id is not None:
                raise ParseError(str(exc)) from exc
            outcomes.append(AnalysisOutcome(
                evidence_id=evidence.evidence_id,
                original_filename=evidence.original_filename,
                platform=evidence.platform,
                status="PARSE_ERROR",
                warnings=[str(exc)],
            ))
            continue

        if result.flight_path:
            zones_to_check = zones if zones is not None else load_zones()
            incursions = check_incursions(result.flight_path, zones_to_check)
            result.flight_summary["airspace_incursions"] = len(incursions)
            if incursions:
                for incursion in incursions:
                    result.events.append(TimelineEvent(
                        timestamp_utc=incursion.entry_ts,
                        source="toolkit.airspace",
                        event_type="AIRSPACE_INCURSION",
                        description=(
                            f"Flight path entered restricted zone "
                            f"'{incursion.zone_name}' (exited {incursion.exit_ts}, "
                            f"{incursion.point_count} track point(s))"
                        ),
                        extra={
                            "zone_name": incursion.zone_name,
                            "entry_ts": incursion.entry_ts,
                            "exit_ts": incursion.exit_ts,
                            "point_count": incursion.point_count,
                        },
                    ))
                result.events.sort(key=lambda e: e.timestamp_utc)
                result.warnings.append(AIRSPACE_DISCLAIMER)
        else:
            result.flight_summary["airspace_incursions"] = 0

        out_dir = case_dir / "analysis" / evidence.evidence_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "result.json").write_text(
            json.dumps(_result_to_json(result), indent=2, default=str), encoding="utf-8"
        )

        if result.flight_path:
            export_kml(result.flight_path, out_dir / "flight_path.kml")
            export_geojson(result.flight_path, out_dir / "flight_path.geojson")

        custody.record(
            "analyzed", actor=examiner,
            detail=f"Parsed with {evidence.platform} parser "
                    f"({'implemented' if result.implemented else 'NOT implemented'}); "
                    f"{len(result.events)} events extracted.",
            evidence_id=evidence.evidence_id,
        )

        if not result.implemented:
            status = "NOT_IMPLEMENTED"
        elif result.partial:
            status = "PARTIAL"
        else:
            status = "OK"

        outcomes.append(AnalysisOutcome(
            evidence_id=evidence.evidence_id,
            original_filename=evidence.original_filename,
            platform=evidence.platform,
            status=status,
            event_count=len(result.events),
            track_point_count=len(result.flight_path),
            warnings=result.warnings,
        ))

    return outcomes


def get_analysis_result(case_dir: Path, evidence_id: str) -> ParserResult:
    case = _load_case(case_dir)
    evidence = case.get_evidence(evidence_id)
    if evidence is None:
        raise EvidenceNotFoundError(f"No evidence with id {evidence_id}")

    result_path = case_dir / "analysis" / evidence_id / "result.json"
    if not result_path.exists():
        raise AnalysisNotFoundError(
            f"No analysis found for {evidence_id} ({evidence.original_filename}) "
            f"— run analyze first."
        )
    data = json.loads(result_path.read_text(encoding="utf-8"))
    return _result_from_json(data)


@dataclass
class SkippedEvidence:
    evidence_id: str
    original_filename: str


@dataclass
class ReportResult:
    path: Path
    skipped: list
    pdf_path: Path | None = None


def generate_case_report(
    case_dir: Path,
    examiner: str | None = None,
    output: Path | None = None,
) -> ReportResult:
    from toolkit.report.generator import generate_report
    from toolkit.report.pdf import PdfGenerationError, generate_pdf

    case = _load_case(case_dir)
    custody = ChainOfCustody(case_dir)

    analyses = []
    skipped: list[SkippedEvidence] = []
    for evidence in case.evidence:
        result_path = case_dir / "analysis" / evidence.evidence_id / "result.json"
        if not result_path.exists():
            skipped.append(SkippedEvidence(evidence.evidence_id, evidence.original_filename))
            continue
        data = json.loads(result_path.read_text(encoding="utf-8"))
        result = _result_from_json(data)
        analyses.append({
            "evidence": evidence,
            "result": result,
            "flight_path_kml": str(Path("analysis") / evidence.evidence_id / "flight_path.kml")
                if result.flight_path else "—",
            "flight_path_geojson": str(Path("analysis") / evidence.evidence_id / "flight_path.geojson")
                if result.flight_path else "—",
            "incursions": _extract_incursions(result),
        })

    carved_files = _load_carved_manifest(case_dir)

    output_path = output or (case_dir / "reports" / "forensic_report.html")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generate_report(case, custody, analyses, output_path, carved_files=carved_files)
    html_sha256 = sha256_file(output_path)

    # PDF generation is best-effort — an examiner should get the (already
    # complete, verifiable-via-hash) HTML report even if the PDF renderer
    # trips on a future template change. Don't fail the whole report step.
    pdf_path = output_path.with_suffix(".pdf")
    pdf_sha256 = None
    try:
        generate_pdf(output_path, pdf_path)
        pdf_sha256 = sha256_file(pdf_path)
    except PdfGenerationError:
        pdf_path = None

    detail = f"Forensic report exported to {output_path.name} (sha256={html_sha256})."
    if pdf_path is not None:
        detail += f" PDF exported to {pdf_path.name} (sha256={pdf_sha256})."
    custody.record("exported", actor=examiner or case.examiner, detail=detail)

    return ReportResult(path=output_path, skipped=skipped, pdf_path=pdf_path)


@dataclass
class EvidenceVerifyStatus:
    evidence_id: str
    original_filename: str
    status: str  # "OK" | "MISSING" | "HASH_MISMATCH"


@dataclass
class VerifyResult:
    custody_ok: bool
    broken_at: int | None
    entry_count: int
    evidence: list


def verify_case(case_dir: Path) -> VerifyResult:
    case = _load_case(case_dir)
    custody = ChainOfCustody(case_dir)

    ok, broken_seq = custody.verify_chain()

    evidence_statuses = []
    for evidence in case.evidence:
        evidence_path = case_dir / evidence.acquired_path
        if not evidence_path.exists():
            evidence_statuses.append(EvidenceVerifyStatus(
                evidence.evidence_id, evidence.original_filename, "MISSING"))
            continue
        match = verify_file(evidence_path, evidence.sha256)
        evidence_statuses.append(EvidenceVerifyStatus(
            evidence.evidence_id, evidence.original_filename,
            "OK" if match else "HASH_MISMATCH"))

    return VerifyResult(
        custody_ok=ok,
        broken_at=broken_seq,
        entry_count=len(custody.entries),
        evidence=evidence_statuses,
    )


def get_custody_log(case_dir: Path) -> list[dict]:
    _load_case(case_dir)  # raises CaseNotFoundError if the case doesn't exist
    custody = ChainOfCustody(case_dir)
    return [dataclasses.asdict(e) for e in custody.entries]
