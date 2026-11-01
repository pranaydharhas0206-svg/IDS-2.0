"""Hardening tests: fail-safe pipeline, identity/allowlist evasions, GPS-fix loss, fusion, log/manifest integrity."""

import json
import random
import threading
import time

import pytest
from pymavlink import mavutil

from ids.alertlog import AlertLog, load_key, verify_log
from ids.cli import build_parser, main, parse_src, startup_notices
from ids.core import Alert, AttackClass, Finding, Msg
from ids.detectors.checks import Check
from ids.detectors.integrity import attest, enroll
from ids.detectors.protocol import ProtocolDetector
from ids.detectors.residual import ResidualDetector
from ids.engine import build_engine
from ids.fusion import Fusion
from ids.live import run_router
from ids.state import VehicleState
from tests.ids_helpers import Stream, gcs_hb, gpi, gps, hb

BASE = {"banners": [], "autopilot_version": None, "params": {"A": 1.0}, "params_sha256": ""}


# ---------- fail-safe engine ----------

def test_malformed_message_does_not_crash_engine_and_raises_fault_alert():
    eng = build_engine(baseline=BASE)
    alerts = eng.process(Msg(1.0, "PARAM_VALUE", 1, 1, 0, {"param_id": "A"}))  # no param_value
    assert eng.faults["integrity"] == 1
    assert [a.attack_class for a in alerts] == [AttackClass.IDS_FAULT]
    assert "integrity" in alerts[0].reasons[0]


def test_fault_alerts_are_rate_limited_but_every_fault_is_counted():
    eng = build_engine(baseline=BASE)
    bad = lambda t: Msg(t, "PARAM_VALUE", 1, 1, 0, {"param_id": "A"})
    assert eng.process(bad(1.0))
    assert eng.process(bad(2.0)) == []
    assert eng.faults["integrity"] == 2
    assert eng.process(bad(100.0))  # long after: reported again


def test_engine_survives_random_garbage_messages():
    rng = random.Random(1234)
    types = ["HEARTBEAT", "GPS_RAW_INT", "GLOBAL_POSITION_INT", "ATTITUDE", "AHRS2", "VFR_HUD", "SYS_STATUS",
             "PARAM_VALUE", "STATUSTEXT", "AUTOPILOT_VERSION", "COMMAND_LONG", "SCALED_PRESSURE",
             "EKF_STATUS_REPORT", "BAD_DATA", "NOT_A_TYPE"]
    keys = ["lat", "lon", "alt", "fix_type", "vel", "roll", "pitch", "yawspeed", "base_mode", "type", "autopilot",
            "param_id", "param_value", "text", "command", "param1", "relative_alt", "voltage_battery",
            "current_battery", "hdg", "heading", "groundspeed", "vx", "vy", "press_abs", "flight_custom_version"]
    junk = [None, "x", "", -1, 0, 2 ** 40, 1e300, float("nan"), float("inf"), [], [1, 2], {}, b"\xff", True]
    eng = build_engine(baseline=BASE, ml_model=None)
    t = 0.0
    for _ in range(3000):
        t += rng.random() * 0.2
        fields = {rng.choice(keys): rng.choice(junk) for _ in range(rng.randint(0, 6))}
        eng.process(Msg(t, rng.choice(types), rng.randint(0, 255), rng.randint(0, 255), rng.randint(-5, 300), fields))
    assert eng.proc_ns  # ran to completion


def test_failing_alert_sinks_do_not_break_the_pipeline():
    class BadLog:
        def append(self, a):
            raise OSError("disk full")

    def bad_cb(a):
        raise RuntimeError("dashboard gone")

    eng = build_engine(log=BadLog(), on_alert=bad_cb)
    s = Stream()
    alerts = eng.process(s(1.0, "STATUSTEXT", severity=6, text="x"))  # benign: no alert, no crash
    assert alerts == []
    eng.fusion.threshold = 0.0  # force an alert path
    out = eng.process(Msg(2.0, "BAD_DATA", 0, 0, 0))
    assert out and eng.sink_errors == 2


def test_residual_check_failure_is_isolated_from_other_checks():
    class Boom(Check):
        name, triggers = "boom", frozenset({"GPS_RAW_INT"})

        def residual(self, msg, cache):
            raise KeyError("lat")

    class Big(Check):
        name, triggers, floor = "big", frozenset({"GPS_RAW_INT"}), 1.0

        def residual(self, msg, cache):
            return 5.0

    st, s = VehicleState(), Stream()
    det = ResidualDetector(st, [Boom(), Big()], {})
    st.update(hb(s, 0.0))
    out = det.feed(gps(s, 1.0))
    assert [f.detector for f in out] == ["residual:big"]
    assert det.faults and "boom" in det.faults[0]


def test_router_keeps_forwarding_when_analysis_raises():
    class Boom:
        def process(self, msg):
            raise RuntimeError("detector bug")

    stop = threading.Event()
    th = threading.Thread(target=run_router, args=("udpin:127.0.0.1:14652", "udpin:127.0.0.1:14653", Boom(), stop),
                          daemon=True)
    th.start()
    gcs = mavutil.mavlink_connection("udpout:127.0.0.1:14653", source_system=255, source_component=0)
    veh = mavutil.mavlink_connection("udpout:127.0.0.1:14652", source_system=1, source_component=1)
    got = None
    deadline = time.time() + 5
    while got is None and time.time() < deadline:
        try:
            gcs.mav.heartbeat_send(6, 8, 0, 0, 0)  # lets the router learn the GCS peer
            veh.mav.heartbeat_send(2, 3, 129, 0, 4)
            time.sleep(0.1)
            m = gcs.recv_match(type="HEARTBEAT", blocking=False)
            while m is not None and m.get_srcSystem() != 1:
                m = gcs.recv_match(type="HEARTBEAT", blocking=False)
            got = m
        except ConnectionResetError:
            pass  # Windows raises a stale ICMP port-unreachable on UDP sockets; retry on the next pass
    alive = th.is_alive()
    stop.set()
    th.join(timeout=2)
    assert alive and got is not None


# ---------- vehicle identity ----------

def rogue_hb(s, t, src=(66, 1)):
    return s(t, "HEARTBEAT", src=src, type=2, autopilot=3, base_mode=129, custom_mode=0, system_status=4)


def test_configured_vehicle_identity_cannot_be_claimed_by_a_rogue_heartbeat():
    eng = build_engine(vehicle=(1, 1))
    s = Stream()
    eng.process(rogue_hb(s, 0.0))
    eng.process(hb(s, 1.0))
    assert eng.state.vehicle_src == (1, 1)


def test_second_source_claiming_to_be_the_vehicle_is_flagged():
    st, s = VehicleState(), Stream()
    det = ProtocolDetector(st, warmup_s=10.0)
    for m in (hb(s, 0.0), gcs_hb(s, 0.1)):
        st.update(m)
        det.feed(m)
    m = rogue_hb(s, 1.0)
    st.update(m)
    out = det.feed(m)
    assert any(f.attack_class == AttackClass.MAVLINK_ANOMALY and "claims to be the vehicle" in f.reason for f in out)


def test_gcs_and_companion_heartbeats_are_not_vehicle_claims():
    st, s = VehicleState(), Stream()
    det = ProtocolDetector(st, warmup_s=10.0)
    st.update(hb(s, 0.0))
    det.feed(hb(s, 0.0))
    comp = s(1.0, "HEARTBEAT", src=(1, 191), type=18, autopilot=8, base_mode=0, custom_mode=0, system_status=4)
    assert not [f for f in det.feed(comp) if "claims" in f.reason]
    assert not [f for f in det.feed(gcs_hb(s, 1.0)) if "claims" in f.reason]


def test_repeated_identity_claims_raise_an_alert():
    eng = build_engine(vehicle=(1, 1))
    s = Stream()
    alerts = []
    for i in range(6):
        alerts += eng.process(hb(s, float(i)))
        alerts += eng.process(rogue_hb(s, i + 0.5))
    assert any(a.attack_class == AttackClass.MAVLINK_ANOMALY for a in alerts)


# ---------- allowlist poisoning ----------

def test_strict_allowlist_ignores_sources_seen_during_warmup():
    st, s = VehicleState(), Stream()
    det = ProtocolDetector(st, warmup_s=60.0, trusted={(1, 1), (255, 0)}, learn_sources=False)
    st.update(hb(s, 0.0))
    det.feed(hb(s, 0.0))
    m = s(5.0, "COMMAND_LONG", src=(66, 1), command=400, param1=0, param2=21196)  # inside warmup
    out = det.feed(m)
    assert any(f.attack_class == AttackClass.COMMAND_INJECTION for f in out)


def test_default_still_learns_sources_during_warmup():
    st, s = VehicleState(), Stream()
    det = ProtocolDetector(st, warmup_s=60.0)
    det.feed(s(5.0, "COMMAND_LONG", src=(66, 1), command=400, param1=0, param2=0))
    assert not [f for f in det.feed(s(70.0, "STATUSTEXT", src=(66, 1), severity=6, text="x"))
                if f.attack_class == AttackClass.COMMAND_INJECTION]


# ---------- GPS fix degradation while airborne ----------

def _airborne_engine():
    eng = build_engine()
    s = Stream()
    for i in range(3):
        eng.process(hb(s, float(i)))
        eng.process(gpi(s, i + 0.1, rel_m=30.0))
    return eng, s


def test_gps_fix_loss_while_airborne_raises_gps_alert():
    eng, s = _airborne_engine()
    alerts, t = [], 3.0
    while t < 9.0:
        alerts += eng.process(gps(s, t, fix=1))
        t += 0.2
    gp = [a for a in alerts if a.attack_class == AttackClass.GPS_SPOOFING]
    assert gp and gp[0].t_alert - 3.0 >= 2.0  # not on the first bad sample


def test_gps_fix_loss_on_the_ground_is_ignored():
    eng = build_engine()
    s = Stream()
    eng.process(hb(s, 0.0, armed=False))
    alerts, t = [], 1.0
    while t < 12.0:
        alerts += eng.process(gps(s, t, fix=0))
        t += 0.2
    assert alerts == []


def test_gps_fix_recovery_resets_the_loss_timer():
    eng, s = _airborne_engine()
    alerts = []
    for k in range(4):  # 1.5 s of loss then recovery, repeatedly: never a sustained loss
        base = 3.0 + k * 2.0
        for j in range(8):
            alerts += eng.process(gps(s, base + j * 0.2, fix=1))
        alerts += eng.process(gps(s, base + 1.7, fix=3))
    assert [a for a in alerts if a.attack_class == AttackClass.GPS_SPOOFING] == []


# ---------- fusion ----------

def test_critical_class_is_not_muted_by_the_long_cooldown():
    fu = Fusion(cooldown_s=10.0)
    ci = AttackClass.COMMAND_INJECTION
    assert fu.feed([Finding(0.0, "d", ci, 1.0, "a")])
    assert fu.feed([Finding(2.0, "d", ci, 1.0, "b")])  # a second injection 2 s later is still reported
    assert fu.feed([Finding(2.2, "d", ci, 1.0, "b")]) == []  # but the same burst is de-duplicated


def test_suppressed_findings_are_counted():
    fu = Fusion(cooldown_s=10.0)
    g = AttackClass.GPS_SPOOFING
    fu.feed([Finding(0.0, "d", g, 1.0, "a")])
    fu.feed([Finding(2.0, "d", g, 1.0, "b")])
    fu.feed([Finding(3.0, "d", g, 1.0, "c")])
    assert fu.suppressed[g] == 2


# ---------- alert log ----------

def _alert(i):
    return Alert(i, i + 0.5, AttackClass.DOS, "high", 1.0, ["x"], ["protocol"])


def test_append_is_fsynced(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("os.fsync", lambda fd: calls.append(fd))
    AlertLog(tmp_path / "a.jsonl", b"k").append(_alert(1))
    assert calls


def test_tail_truncation_is_detected_with_an_anchor(tmp_path):
    p, anchor, key = tmp_path / "a.jsonl", tmp_path / "anchor.json", b"k"
    log = AlertLog(p, key, anchor_path=anchor)
    for i in range(4):
        log.append(_alert(i))
    assert verify_log(p, key, anchor=anchor) == (True, None, "ok")
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:2]) + "\n")  # attacker drops the newest two records
    ok, _, why = verify_log(p, key, anchor=anchor)
    assert not ok and "truncat" in why
    assert verify_log(p, key)[0]  # the chain alone cannot see this: documented limitation


def test_emptied_log_is_detected_with_an_anchor(tmp_path):
    p, anchor, key = tmp_path / "a.jsonl", tmp_path / "anchor.json", b"k"
    AlertLog(p, key, anchor_path=anchor).append(_alert(1))
    p.write_text("")
    ok, _, why = verify_log(p, key, anchor=anchor)
    assert not ok and "truncat" in why


def test_forged_anchor_is_rejected(tmp_path):
    p, anchor, key = tmp_path / "a.jsonl", tmp_path / "anchor.json", b"k"
    log = AlertLog(p, key, anchor_path=anchor)
    log.append(_alert(1))
    log.append(_alert(2))
    a = json.loads(anchor.read_text())
    a["seq"] = 0  # lower the anchor so a truncated log would pass
    anchor.write_text(json.dumps(a))
    ok, _, why = verify_log(p, key, anchor=anchor)
    assert not ok and "anchor" in why


def test_require_key_refuses_the_development_key(monkeypatch):
    monkeypatch.delenv("IDS_ALERT_KEY", raising=False)
    with pytest.raises(RuntimeError):
        load_key(require=True)
    monkeypatch.setenv("IDS_ALERT_KEY", "secret")
    assert load_key(require=True) == b"secret"


def test_cli_require_key_exits_2_without_a_key(monkeypatch, capsys):
    monkeypatch.delenv("IDS_ALERT_KEY", raising=False)
    assert main(["live", "--require-key"]) == 2
    assert "IDS_ALERT_KEY" in capsys.readouterr().out


def test_cli_verify_log_with_anchor_flags_truncation(tmp_path, monkeypatch):
    monkeypatch.setenv("IDS_ALERT_KEY", "k")
    p, anchor = tmp_path / "a.jsonl", tmp_path / "anchor.json"
    log = AlertLog(p, b"k", anchor_path=anchor)
    for i in range(3):
        log.append(_alert(i))
    assert main(["verify-log", str(p), "--anchor", str(anchor)]) == 0
    p.write_text("\n".join(p.read_text().splitlines()[:1]) + "\n")
    assert main(["verify-log", str(p), "--anchor", str(anchor)]) == 1


# ---------- firmware manifest ----------

def test_signed_manifest_detects_tampering(tmp_path):
    img = tmp_path / "fw.apj"
    img.write_bytes(b"fw")
    man = enroll(img, {}, key=b"k")
    assert "hmac" in man and attest(img, man, key=b"k")["ok"]
    forged = json.loads(json.dumps(man))
    forged["images"]["fw.apj"] = "0" * 64  # attacker swaps the golden hash
    r = attest(img, forged, key=b"k")
    assert not r["ok"] and "signature" in r["reason"]
    assert not attest(img, man, key=b"other")["ok"]


def test_unsigned_manifest_accepted_unless_signature_required(tmp_path):
    img = tmp_path / "fw.apj"
    img.write_bytes(b"fw")
    man = enroll(img, {})
    assert attest(img, man, key=b"k")["ok"]
    r = attest(img, man, key=b"k", require_signed=True)
    assert not r["ok"] and "unsigned" in r["reason"]


def test_cli_attest_signs_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("IDS_ALERT_KEY", "k")
    img, man = tmp_path / "fw.apj", tmp_path / "m.json"
    img.write_bytes(b"fw")
    assert main(["attest", str(img), "--manifest", str(man), "--enroll"]) == 0
    assert "hmac" in json.loads(man.read_text())
    assert main(["attest", str(img), "--manifest", str(man), "--require-signed"]) == 0
    d = json.loads(man.read_text())
    d["images"]["fw.apj"] = "0" * 64
    man.write_text(json.dumps(d))
    assert main(["attest", str(img), "--manifest", str(man)]) == 1


# ---------- CLI plumbing / startup notices ----------

def test_parse_src():
    assert parse_src("1:1") == (1, 1)
    with pytest.raises(Exception):
        parse_src("nonsense")


def test_startup_notices_call_out_disabled_layers():
    n = " ".join(startup_notices(None, None, None))
    assert "integrity" in n and "floors" in n
    assert startup_notices({"gps_jump": 30.0}, BASE, None) == []


def test_live_and_replay_accept_identity_options():
    p = build_parser()
    a = p.parse_args(["live", "--vehicle", "1:1", "--trusted", "255:0", "--trusted", "51:68",
                      "--no-learn-sources", "--require-key", "--anchor", "x.json"])
    assert a.vehicle == (1, 1) and a.trusted == [(255, 0), (51, 68)] and a.no_learn_sources and a.anchor == "x.json"
    assert p.parse_args(["replay", "f.tlog", "--vehicle", "1:1"]).vehicle == (1, 1)
