"""Regression tests for the 2026-09-20 whole-branch review findings."""

import json

import pytest

from ids.alertlog import AlertLog, verify_log
from ids.cli import main
from ids.core import Alert, AttackClass, Msg
from ids.detectors.integrity import attest, enroll
from ids.detectors.protocol import ProtocolDetector
from ids.engine import PROC_NS_KEEP, build_engine
from ids.state import VehicleState
from tests.ids_helpers import Stream, gcs_hb, gpi, hb

KEY = b"k"


def _alert(i=0):
    return Alert(t_first=i, t_alert=i, attack_class=AttackClass.DOS, severity="high", score=1.0,
                 reasons=["r"], detectors=["protocol"])


def _airborne_detector(**kw):
    st, s = VehicleState(), Stream()
    det = ProtocolDetector(st, warmup_s=1.0, trusted={(1, 1), (255, 0)}, **kw)
    for m in (hb(s, 0.0), gcs_hb(s, 0.1), gpi(s, 0.2, rel_m=30.0)):
        st.update(m)
        det.feed(m)
    return st, det, s


def _run(det, st, msgs):
    out = []
    for m in msgs:
        st.update(m)
        out += det.feed(m)
    return out


# ---------- alert log ----------

def test_alertlog_survives_a_torn_last_line_and_keeps_the_evidence(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AlertLog(p, KEY)
    log.append(_alert(0))
    log.append(_alert(1))
    with open(p, "a", encoding="utf-8") as f:
        f.write('{"seq": 2, "ale')  # power cut mid-append
    with pytest.warns(UserWarning, match="torn"):
        log2 = AlertLog(p, KEY)
    assert log2.seq == 2
    log2.append(_alert(2))
    assert verify_log(p, KEY)[0]
    assert (tmp_path / "a.jsonl.torn").read_text(encoding="utf-8").startswith('{"seq": 2')


def test_alertlog_torn_only_line_restarts_the_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"seq": 0, "al', encoding="utf-8")
    with pytest.warns(UserWarning):
        log = AlertLog(p, KEY)
    log.append(_alert())
    assert verify_log(p, KEY)[0]


def test_non_ascii_hmac_is_reported_as_tampering_not_a_crash(tmp_path):
    p = tmp_path / "a.jsonl"
    AlertLog(p, KEY).append(_alert())
    rec = json.loads(p.read_text(encoding="utf-8"))
    rec["hmac"] = "é" * 64
    p.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    ok, idx, why = verify_log(p, KEY)
    assert not ok and idx == 0 and "HMAC" in why


def test_non_ascii_manifest_signature_is_rejected_not_a_crash(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"x")
    man = enroll(fw, {}, key=KEY)
    man["hmac"] = "é" * 64
    r = attest(fw, man, key=KEY)
    assert not r["ok"] and "signature invalid" in r["reason"]


# ---------- manifest ----------

def test_enroll_refuses_to_re_sign_a_tampered_manifest(tmp_path):
    fw, other = tmp_path / "fw.bin", tmp_path / "other.bin"
    fw.write_bytes(b"good")
    other.write_bytes(b"other")
    man = enroll(fw, {}, key=KEY)
    man["images"]["fw.bin"] = "0" * 64  # attacker swaps the golden hash
    with pytest.raises(ValueError, match="invalid"):
        enroll(other, man, key=KEY)


def test_enroll_can_sign_a_first_time_unsigned_manifest(tmp_path):
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"good")
    assert "hmac" in enroll(fw, {"images": {"old.bin": "1" * 64}}, key=KEY)


def test_cli_attest_enroll_reports_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IDS_ALERT_KEY", "k")
    fw, other, mp = tmp_path / "fw.bin", tmp_path / "other.bin", tmp_path / "m.json"
    fw.write_bytes(b"good")
    other.write_bytes(b"other")
    man = enroll(fw, {}, key=b"k")
    man["images"]["fw.bin"] = "0" * 64
    mp.write_text(json.dumps(man))
    assert main(["attest", str(other), "--manifest", str(mp), "--enroll"]) == 1
    assert "refused" in capsys.readouterr().out


# ---------- engine ----------

def test_engine_timing_samples_are_bounded():
    eng = build_engine()
    assert eng.proc_ns.maxlen == PROC_NS_KEEP


# ---------- protocol detector ----------

def test_trusted_gcs_in_flight_param_tuning_does_not_alert():
    st, det, s = _airborne_detector()
    out = _run(det, st, [s(5.0 + i, "PARAM_SET", src=(255, 0), param_id="RATE_RLL_P", param_value=0.1)
                         for i in range(2)])
    assert sum(f.score for f in out if f.attack_class == AttackClass.COMMAND_INJECTION) < 1.0


def test_unknown_source_param_set_in_flight_still_alerts_at_once():
    st, det, s = _airborne_detector()
    out = _run(det, st, [s(5.0, "PARAM_SET", src=(66, 1), param_id="ARMING_CHECK", param_value=0)])
    assert max(f.score for f in out if f.attack_class == AttackClass.COMMAND_INJECTION) >= 1.0


def test_trusted_gcs_disarm_in_flight_is_still_evidence():
    st, det, s = _airborne_detector()
    out = _run(det, st, [s(5.0, "COMMAND_LONG", src=(255, 0), command=400, param1=0, param2=0)])
    assert [f for f in out if "disarm while airborne" in f.reason]


def test_sustained_heartbeat_loss_reaches_alert_weight_and_short_gap_does_not():
    st, det, s = _airborne_detector(hb_gap_s=5.0)
    short = _run(det, st, [hb(s, 10.0)])
    assert max([f.score for f in short if f.attack_class == AttackClass.DOS] or [0]) < 1.0
    long_gap = _run(det, st, [hb(s, 60.0)])
    assert max(f.score for f in long_gap if f.attack_class == AttackClass.DOS) >= 1.0


def test_radio_noise_alone_never_alerts_but_still_leaves_evidence():
    eng = build_engine()
    alerts = []
    for i in range(40):
        alerts += eng.process(Msg(1.0 + i * 0.05, "BAD_DATA", 0, 0, 0))
    assert alerts == []
    assert eng.n_findings == 5  # capped at 5 findings (0.5) per 3 s window
