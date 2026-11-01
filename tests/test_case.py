from toolkit.core.case import Case, Evidence


def test_create_and_load_case_roundtrip(tmp_path):
    case_dir = tmp_path / "case1"
    case = Case.create(case_dir, examiner="A. Examiner", description="test case")

    loaded = Case.load(case_dir)
    assert loaded.case_id == case.case_id
    assert loaded.examiner == "A. Examiner"
    assert loaded.evidence == []


def test_add_evidence_persists(tmp_path):
    case_dir = tmp_path / "case2"
    case = Case.create(case_dir, examiner="A. Examiner")

    ev = Evidence(
        evidence_id="ev1", original_filename="log.bin", platform="ardupilot",
        source_description="", acquired_path="evidence/ev1_log.bin",
        sha256="a" * 64, acquired_at="2026-01-01T00:00:00+00:00",
        examiner="A. Examiner",
    )
    case.add_evidence(case_dir, ev)

    reloaded = Case.load(case_dir)
    assert len(reloaded.evidence) == 1
    assert reloaded.get_evidence("ev1").sha256 == "a" * 64
    assert reloaded.get_evidence("missing") is None
