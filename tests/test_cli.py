"""End-to-end CLI integration test: exercises the full
init-case -> acquire -> analyze -> report -> verify pipeline exactly the
way an examiner would from the command line, against the real sample
ArduPilot log. This is what backs the "automation and usability" claim in
docs/design_document.md — it's not just the underlying modules that work,
the CLI wiring them together works too.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SAMPLE_LOG = REPO_ROOT / "sample_data" / "ardupilot_sample.bin"


def run_cli(*args, cwd):
    result = subprocess.run(
        [sys.executable, "-m", "toolkit.cli", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )
    return result


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_full_pipeline_via_cli(tmp_path):
    case_dir = tmp_path / "case"

    r = run_cli("init-case", "--case-dir", str(case_dir), "--examiner", "Tester",
                "--description", "CLI integration test case", cwd=REPO_ROOT)
    assert r.returncode == 0, r.stderr
    assert "Case created" in r.stdout

    r = run_cli("acquire", "--case-dir", str(case_dir), "--source", str(SAMPLE_LOG),
                "--platform", "ardupilot", "--examiner", "Tester", cwd=REPO_ROOT)
    assert r.returncode == 0, r.stderr
    assert "Evidence acquired" in r.stdout
    assert "SHA-256" in r.stdout

    r = run_cli("analyze", "--case-dir", str(case_dir), "--examiner", "Tester", cwd=REPO_ROOT)
    assert r.returncode == 0, r.stderr
    assert "[OK]" in r.stdout
    assert "events" in r.stdout

    r = run_cli("report", "--case-dir", str(case_dir), "--examiner", "Tester", cwd=REPO_ROOT)
    assert r.returncode == 0, r.stderr
    report_path = case_dir / "reports" / "forensic_report.html"
    assert report_path.exists()
    html = report_path.read_text(encoding="utf-8")
    assert "VERIFIED" in html
    assert "ARMED" in html

    r = run_cli("verify", "--case-dir", str(case_dir), cwd=REPO_ROOT)
    assert r.returncode == 0, r.stderr
    assert "Chain-of-custody log: OK" in r.stdout
    assert "[OK]" in r.stdout


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_verify_detects_evidence_tampering(tmp_path):
    case_dir = tmp_path / "case_tamper"

    run_cli("init-case", "--case-dir", str(case_dir), "--examiner", "Tester", cwd=REPO_ROOT)
    run_cli("acquire", "--case-dir", str(case_dir), "--source", str(SAMPLE_LOG),
            "--platform", "ardupilot", "--examiner", "Tester", cwd=REPO_ROOT)

    evidence_dir = case_dir / "evidence"
    evidence_file = next(evidence_dir.iterdir())
    with open(evidence_file, "r+b") as f:
        f.seek(0)
        f.write(b"TAMPERED")

    r = run_cli("verify", "--case-dir", str(case_dir), cwd=REPO_ROOT)
    assert r.returncode != 0
    assert "HASH MISMATCH" in r.stdout


def test_carve_via_cli(tmp_path):
    case_dir = tmp_path / "case"
    run_cli("init-case", "--case-dir", str(case_dir), "--examiner", "Tester", cwd=REPO_ROOT)

    jpeg = b"\xff\xd8" + b"A" * 20 + b"\xff\xd9"
    image_path = tmp_path / "sdcard.img"
    image_path.write_bytes(b"\x00" * 16 + jpeg + b"\x00" * 16)

    r = run_cli("carve", "--case-dir", str(case_dir), "--source", str(image_path),
                "--examiner", "Tester", cwd=REPO_ROOT)
    assert r.returncode == 0, r.stderr
    assert "1" in r.stdout
    assert list((case_dir / "carved").iterdir())
