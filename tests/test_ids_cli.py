import json

from ids.cli import main
from tests.test_ids_core import TLOG


def test_calibrate_writes_profile(tmp_path):
    assert main(["calibrate", str(TLOG), "--out", str(tmp_path), "--frac", "0.2"]) == 0
    assert json.loads((tmp_path / "thresholds.json").read_text())["gps_jump"] >= 30.0
    assert "params" in json.loads((tmp_path / "baseline.json").read_text())


def test_replay_with_injected_attack_prints_alert_and_writes_verifiable_log(tmp_path, capsys):
    main(["calibrate", str(TLOG), "--out", str(tmp_path), "--frac", "0.2"])
    log = tmp_path / "alerts.jsonl"
    rc = main(["replay", str(TLOG), "--profile", str(tmp_path), "--attack", "firmware_integrity@600",
               "--log", str(log), "--max-seconds", "700"])
    assert rc == 0
    assert "firmware_integrity" in capsys.readouterr().out
    assert main(["verify-log", str(log)]) == 0


def test_attest_enroll_then_verify(tmp_path):
    img, man = tmp_path / "fw.apj", tmp_path / "manifest.json"
    img.write_bytes(b"fw")
    assert main(["attest", str(img), "--manifest", str(man), "--enroll"]) == 0
    assert main(["attest", str(img), "--manifest", str(man)]) == 0
    img.write_bytes(b"evil")
    assert main(["attest", str(img), "--manifest", str(man)]) == 1


def _write_log(path):
    from ids.alertlog import AlertLog, load_key
    from ids.core import Alert, AttackClass
    log = AlertLog(path, load_key())
    for t in (1.0, 2.0):
        log.append(Alert(t, t, AttackClass.DOS, "high", 1.0, ["x"], ["d"]))
    return path


def test_verify_log_missing_file_is_clean_error(tmp_path, capsys):
    assert main(["verify-log", str(tmp_path / "nope.jsonl")]) == 1
    assert "cannot read alert log" in capsys.readouterr().out


def test_verify_log_empty_file_reported_distinctly(tmp_path, capsys):
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert main(["verify-log", str(p)]) == 1
    assert "empty log - nothing to verify" in capsys.readouterr().out


def test_verify_log_malformed_json_line_is_tampered_not_traceback(tmp_path, capsys):
    p = _write_log(tmp_path / "a.jsonl")
    p.write_text(p.read_text(encoding="utf-8") + "{not json\n", encoding="utf-8")
    assert main(["verify-log", str(p)]) == 1
    assert "TAMPERED at record 2: malformed record" in capsys.readouterr().out


def test_verify_log_intact_still_ok(tmp_path, capsys):
    p = _write_log(tmp_path / "a.jsonl")
    assert main(["verify-log", str(p)]) == 0
    assert "OK: alert log intact" in capsys.readouterr().out
