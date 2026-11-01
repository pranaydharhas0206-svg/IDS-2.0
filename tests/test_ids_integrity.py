from ids.core import AttackClass
from ids.detectors.integrity import IntegrityDetector, attest, build_baseline, enroll
from tests.ids_helpers import Stream


def trusted(s):
    return [
        s(0.0, "STATUSTEXT", severity=6, text="APM:Copter V3.4-dev (bdddfae5)"),
        s(0.1, "PARAM_VALUE", param_id="ARMING_CHECK", param_value=1.0, param_type=2, param_count=2, param_index=0),
        s(0.2, "PARAM_VALUE", param_id="WPNAV_SPEED", param_value=500.0, param_type=4, param_count=2, param_index=1),
    ]


def test_baseline_and_benign_replay_is_silent():
    s = Stream()
    base = build_baseline(trusted(s))
    assert base["banners"] == ["APM:Copter V3.4-dev (bdddfae5)"]
    assert base["params"]["WPNAV_SPEED"] == 500.0
    det = IntegrityDetector(base)
    assert all(det.feed(m) == [] for m in trusted(Stream()))


def test_banner_change_is_firmware_violation():
    s = Stream()
    det = IntegrityDetector(build_baseline(trusted(s)))
    out = det.feed(s(5.0, "STATUSTEXT", severity=6, text="APM:Copter V3.4-dev (deadbeef)"))
    assert [(f.attack_class, f.score) for f in out] == [(AttackClass.FIRMWARE_INTEGRITY, 1.0)]


def test_critical_param_change_scores_full_noncritical_half():
    s = Stream()
    det = IntegrityDetector(build_baseline(trusted(s)))
    crit = det.feed(s(5.0, "PARAM_VALUE", param_id="ARMING_CHECK", param_value=0.0, param_type=2, param_count=2, param_index=0))
    minor = det.feed(s(6.0, "PARAM_VALUE", param_id="WPNAV_SPEED", param_value=900.0, param_type=4, param_count=2, param_index=1))
    assert crit[0].score == 1.0 and minor[0].score == 0.5


def test_no_baseline_means_no_findings():
    s = Stream()
    assert IntegrityDetector(None).feed(s(1.0, "STATUSTEXT", severity=6, text="APM:Copter V9 (x)")) == []


def test_attest_detects_modified_image(tmp_path):
    img = tmp_path / "arducopter.apj"
    img.write_bytes(b"golden firmware")
    manifest = enroll(img, {})
    assert attest(img, manifest)["ok"] is True
    img.write_bytes(b"patched firmware")
    assert attest(img, manifest)["ok"] is False


def test_unseen_noncritical_param_is_silent_but_unseen_critical_still_flags():
    s = Stream()
    det = IntegrityDetector(build_baseline(trusted(s)))
    minor = det.feed(s(5.0, "PARAM_VALUE", param_id="NEW_BENIGN_PARAM", param_value=1.0, param_type=4, param_count=3, param_index=2))
    crit = det.feed(s(6.0, "PARAM_VALUE", param_id="FENCE_ENABLE", param_value=0.0, param_type=2, param_count=3, param_index=2))
    assert minor == []
    assert [(f.attack_class, f.score) for f in crit] == [(AttackClass.FIRMWARE_INTEGRITY, 0.5)]
