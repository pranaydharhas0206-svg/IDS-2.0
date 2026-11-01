"""Unit tests for toolkit.service — the shared logic behind both the CLI and
the web GUI. These exercise service functions directly (no subprocess), unlike
tests/test_cli.py which drives the CLI end-to-end.
"""

from pathlib import Path

import pytest

from toolkit import service
from toolkit.core.case import Case

REPO_ROOT = Path(__file__).parent.parent
SAMPLE_LOG = REPO_ROOT / "sample_data" / "ardupilot_sample.bin"


def test_init_case_creates_case_and_custody_entry(tmp_path):
    case_dir = tmp_path / "case"
    case = service.init_case(case_dir, examiner="Tester", description="desc")

    assert case.examiner == "Tester"
    assert case.description == "desc"
    assert (case_dir / "case.json").exists()

    custody = (case_dir / "custody_log.json")
    assert custody.exists()
    assert "case_opened" in custody.read_text(encoding="utf-8")


def test_get_case_raises_for_missing_case(tmp_path):
    with pytest.raises(service.CaseNotFoundError):
        service.get_case(tmp_path / "nonexistent")


def test_list_cases_returns_summaries_keyed_by_directory_name(tmp_path):
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    case_dir = cases_root / "abc123"
    case = service.init_case(case_dir, examiner="Tester")

    summaries = service.list_cases(cases_root)

    assert len(summaries) == 1
    assert summaries[0].case_id == "abc123"
    assert summaries[0].internal_id == case.case_id
    assert summaries[0].evidence_count == 0
    assert summaries[0].custody_ok is True


def test_list_cases_empty_root_returns_empty_list(tmp_path):
    assert service.list_cases(tmp_path / "does_not_exist") == []


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_acquire_evidence_copies_and_hashes_file(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")

    evidence = service.acquire_evidence(
        case_dir, SAMPLE_LOG, platform="ardupilot", examiner="Tester",
        description="sample",
    )

    assert evidence.platform == "ardupilot"
    assert (case_dir / evidence.acquired_path).exists()

    case = Case.load(case_dir)
    assert case.evidence[0].evidence_id == evidence.evidence_id


def test_acquire_evidence_missing_source_raises_parse_error(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")

    with pytest.raises(service.ParseError):
        service.acquire_evidence(
            case_dir, tmp_path / "nope.bin", platform="ardupilot", examiner="Tester",
        )


def test_acquire_evidence_unknown_platform_raises_parse_error(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")
    source = tmp_path / "file.bin"
    source.write_bytes(b"data")

    with pytest.raises(service.ParseError):
        service.acquire_evidence(
            case_dir, source, platform="not_a_platform", examiner="Tester",
        )


def test_acquire_evidence_missing_case_raises_case_not_found(tmp_path):
    source = tmp_path / "file.bin"
    source.write_bytes(b"data")

    with pytest.raises(service.CaseNotFoundError):
        service.acquire_evidence(
            tmp_path / "no_such_case", source, platform="ardupilot", examiner="Tester",
        )


from toolkit.parsers.base import ParserResult


def _acquire_sample(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")
    evidence = service.acquire_evidence(
        case_dir, SAMPLE_LOG, platform="ardupilot", examiner="Tester",
    )
    return case_dir, evidence


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_analyze_case_returns_ok_outcome_for_ardupilot(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)

    outcomes = service.analyze_case(case_dir, examiner="Tester")

    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.evidence_id == evidence.evidence_id
    assert outcome.status == "OK"
    assert outcome.event_count > 0
    assert (case_dir / "analysis" / evidence.evidence_id / "result.json").exists()


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_analyze_case_unknown_evidence_id_raises(tmp_path):
    case_dir, _ = _acquire_sample(tmp_path)

    with pytest.raises(service.EvidenceNotFoundError):
        service.analyze_case(case_dir, examiner="Tester", evidence_id="not-a-real-id")


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_analyze_case_detects_airspace_incursion_with_overridden_zones(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)

    # Real coordinate from the middle of sample_data/ardupilot_sample.bin's
    # track, with a generous radius so several consecutive track points fall
    # inside it. Overriding zones (rather than relying on the bundled
    # dataset) makes this deterministic regardless of what real-world
    # zones happen to be bundled.
    test_zone = {
        "name": "Test Zone",
        "type": "circle",
        "category": "test",
        "source_note": "test fixture",
        "center_lat": -35.3620215,
        "center_lon": 149.1657805,
        "radius_m": 100.0,
    }

    outcomes = service.analyze_case(
        case_dir, examiner="Tester", zones=[test_zone],
    )

    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.status == "OK"

    result = service.get_analysis_result(case_dir, evidence.evidence_id)
    assert result.flight_summary["airspace_incursions"] >= 1
    assert any(
        e.event_type == "AIRSPACE_INCURSION" for e in result.events
    )
    assert any(
        "static snapshot compiled 2026-09-18" in w for w in result.warnings
    )


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_analyze_case_single_target_integrity_failure_raises(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)
    evidence_path = case_dir / evidence.acquired_path
    with open(evidence_path, "r+b") as f:
        f.seek(0)
        f.write(b"TAMPERED")

    with pytest.raises(service.IntegrityError):
        service.analyze_case(case_dir, examiner="Tester", evidence_id=evidence.evidence_id)


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_analyze_case_bulk_integrity_failure_does_not_raise(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)
    evidence_path = case_dir / evidence.acquired_path
    with open(evidence_path, "r+b") as f:
        f.seek(0)
        f.write(b"TAMPERED")

    outcomes = service.analyze_case(case_dir, examiner="Tester")

    assert outcomes[0].status == "INTEGRITY_FAILURE"


def _acquire_empty_ardupilot_log(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")
    empty_source = tmp_path / "empty.bin"
    empty_source.write_bytes(b"")
    evidence = service.acquire_evidence(
        case_dir, empty_source, platform="ardupilot", examiner="Tester",
    )
    return case_dir, evidence


def test_analyze_case_single_target_parse_error_raises(tmp_path):
    case_dir, evidence = _acquire_empty_ardupilot_log(tmp_path)

    with pytest.raises(service.ParseError):
        service.analyze_case(case_dir, examiner="Tester", evidence_id=evidence.evidence_id)


def test_analyze_case_bulk_parse_error_does_not_raise(tmp_path):
    case_dir, evidence = _acquire_empty_ardupilot_log(tmp_path)

    outcomes = service.analyze_case(case_dir, examiner="Tester")

    assert len(outcomes) == 1
    assert outcomes[0].status == "PARSE_ERROR"
    assert outcomes[0].warnings


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_get_analysis_result_after_analyze(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)
    service.analyze_case(case_dir, examiner="Tester")

    result = service.get_analysis_result(case_dir, evidence.evidence_id)

    assert isinstance(result, ParserResult)
    assert result.platform == "ardupilot"
    assert len(result.events) > 0


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_get_analysis_result_before_analyze_raises(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)

    with pytest.raises(service.AnalysisNotFoundError):
        service.get_analysis_result(case_dir, evidence.evidence_id)


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_generate_case_report_writes_html_and_skips_unanalyzed(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)
    service.analyze_case(case_dir, examiner="Tester")
    # Second, unanalyzed evidence item to exercise the "skip" path.
    unanalyzed_source = tmp_path / "second.DAT"
    unanalyzed_source.write_bytes(b"not a real log, just needs to exist")
    unanalyzed = service.acquire_evidence(
        case_dir, unanalyzed_source, platform="dji", examiner="Tester",
    )

    result = service.generate_case_report(case_dir, examiner="Tester")

    assert result.path.exists()
    assert "VERIFIED" in result.path.read_text(encoding="utf-8")
    assert len(result.skipped) == 1
    assert result.skipped[0].evidence_id == unanalyzed.evidence_id

    assert result.pdf_path is not None
    assert result.pdf_path.exists()
    assert result.pdf_path.read_bytes().startswith(b"%PDF")

    custody = service.get_custody_log(case_dir)
    export_entry = next(e for e in custody if e["action"] == "exported")
    assert "sha256=" in export_entry["detail"]
    assert "PDF exported" in export_entry["detail"]


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_generate_case_report_includes_airspace_disclaimer_and_incursion_table(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)

    test_zone = {
        "name": "Test Zone",
        "type": "circle",
        "category": "test",
        "source_note": "test fixture",
        "center_lat": -35.3620215,
        "center_lon": 149.1657805,
        "radius_m": 100.0,
    }
    service.analyze_case(case_dir, examiner="Tester", zones=[test_zone])

    result = service.generate_case_report(case_dir, examiner="Tester")

    html = result.path.read_text(encoding="utf-8")
    disclaimer = (
        "Airspace zone dataset is a static snapshot compiled 2026-09-18 "
        "from public airport coordinates"
    )
    assert disclaimer in html
    assert "Airspace / No-Fly-Zone Analysis" in html
    assert "Test Zone" in html

    # The disclaimer must appear again immediately above the incursion
    # table itself (not just once, earlier in the per-evidence warnings
    # block) so a reader who scrolls straight past the timeline to the
    # incursion table still sees it right alongside the data.
    heading_idx = html.index("Airspace / No-Fly-Zone Analysis")
    second_disclaimer_idx = html.index(disclaimer, heading_idx)
    table_idx = html.index("<table>", heading_idx)
    assert heading_idx < second_disclaimer_idx < table_idx

    # The incursion table itself must actually be populated (not just the
    # zone name appearing earlier in the Timeline table's event
    # description) — this is what generate_report's render_analyses list
    # comprehension must actually pass the "incursions" key through for.
    assert "Test Zone" in html[table_idx:]


def test_generate_case_report_missing_case_raises(tmp_path):
    with pytest.raises(service.CaseNotFoundError):
        service.generate_case_report(tmp_path / "no_such_case")


def _minimal_jpeg_bytes() -> bytes:
    """A tiny but well-formed JPEG: SOI + APP0/JFIF segment + EOI."""
    app0 = (
        b"\xff\xe0"
        b"\x00\x10"
        b"JFIF\x00"
        b"\x01\x01"
        b"\x00"
        b"\x00\x01\x00\x01"
        b"\x00\x00"
    )
    return b"\xff\xd8" + app0 + b"\xff\xd9"


def test_generate_case_report_includes_carved_media_section(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")

    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(b"PADDING-NOT-A-SIGNATURE-" * 4 + _minimal_jpeg_bytes())

    carved = service.carve_evidence(case_dir, image_path, examiner="Tester")
    assert len(carved) == 1

    result = service.generate_case_report(case_dir, examiner="Tester")

    html = result.path.read_text(encoding="utf-8")
    assert "Carved Media" in html
    assert carved[0].sha256 in html
    assert "sdcard.img" in html
    assert "No media carving was performed" not in html


def test_generate_case_report_without_carving_shows_no_media_message(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")

    result = service.generate_case_report(case_dir, examiner="Tester")

    html = result.path.read_text(encoding="utf-8")
    assert "Carved Media" in html
    assert "No media carving was performed" in html


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_verify_case_ok(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)

    result = service.verify_case(case_dir)

    assert result.custody_ok is True
    assert result.broken_at is None
    assert result.evidence[0].status == "OK"


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_verify_case_detects_tampering(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)
    evidence_path = case_dir / evidence.acquired_path
    with open(evidence_path, "r+b") as f:
        f.seek(0)
        f.write(b"TAMPERED")

    result = service.verify_case(case_dir)

    assert result.evidence[0].status == "HASH_MISMATCH"


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_get_custody_log_returns_entries(tmp_path):
    case_dir, evidence = _acquire_sample(tmp_path)

    entries = service.get_custody_log(case_dir)

    assert len(entries) >= 2  # case_opened, acquired
    assert entries[0]["action"] == "case_opened"


def _build_synthetic_image(tmp_path):
    """A small raw image with two carvable JPEGs (with padding between/around them)."""
    jpeg_1 = b"\xff\xd8" + b"A" * 20 + b"\xff\xd9"
    jpeg_2 = b"\xff\xd8" + b"B" * 30 + b"\xff\xd9"
    data = b"\x00" * 16 + jpeg_1 + b"\x00" * 8 + jpeg_2 + b"\x00" * 16
    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(data)
    return image_path


def test_carve_evidence_writes_files_and_custody_entries(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")
    image_path = _build_synthetic_image(tmp_path)

    carved = service.carve_evidence(case_dir, image_path, examiner="Tester")

    assert len(carved) == 2
    for cf in carved:
        assert cf.output_path.exists()
        assert (case_dir / "carved") in cf.output_path.parents

    custody = service.get_custody_log(case_dir)
    carved_entries = [e for e in custody if e["action"] == "carved"]
    assert len(carved_entries) == 2
    carved_hashes = {cf.sha256 for cf in carved}
    assert {e["evidence_sha256"] for e in carved_entries} == carved_hashes

    summary_entries = [e for e in custody if e["action"] == "carve_summary"]
    assert len(summary_entries) == 1
    assert "2" in summary_entries[0]["detail"]


def test_carve_evidence_missing_case_raises_case_not_found(tmp_path):
    image_path = _build_synthetic_image(tmp_path)
    with pytest.raises(service.CaseNotFoundError):
        service.carve_evidence(tmp_path / "no_such_case", image_path, examiner="Tester")


def test_carve_evidence_missing_source_raises_parse_error(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")

    with pytest.raises(service.ParseError):
        service.carve_evidence(case_dir, tmp_path / "nope.img", examiner="Tester")


def test_carve_evidence_no_matches_returns_empty_list_and_summary_entry(tmp_path):
    case_dir = tmp_path / "case"
    service.init_case(case_dir, examiner="Tester")
    image_path = tmp_path / "blank.img"
    image_path.write_bytes(b"\x00" * 64)

    carved = service.carve_evidence(case_dir, image_path, examiner="Tester")

    assert carved == []
    custody = service.get_custody_log(case_dir)
    summary_entries = [e for e in custody if e["action"] == "carve_summary"]
    assert len(summary_entries) == 1
    assert "0" in summary_entries[0]["detail"]
