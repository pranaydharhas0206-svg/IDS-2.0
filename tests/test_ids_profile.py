import json

from ids.profile import sign_profile, verify_profile


def test_profile_signature_detects_modified_thresholds(tmp_path):
    (tmp_path / "thresholds.json").write_text('{"gps": 1.0}')
    (tmp_path / "baseline.json").write_text('{"params": {}}')
    key = b"test-only-secret"
    sign_profile(tmp_path, key)
    assert verify_profile(tmp_path, key) == (True, "ok")
    (tmp_path / "thresholds.json").write_text('{"gps": 0.01}')
    ok, reason = verify_profile(tmp_path, key)
    assert not ok
    assert "modified" in reason


def test_profile_signature_rejects_wrong_key(tmp_path):
    (tmp_path / "thresholds.json").write_text("{}")
    sign_profile(tmp_path, b"right-key")
    ok, reason = verify_profile(tmp_path, b"wrong-key")
    assert not ok
    assert "signature invalid" in reason


def test_unsigned_model_added_after_signing_is_rejected(tmp_path):
    (tmp_path / "thresholds.json").write_text("{}")
    sign_profile(tmp_path, b"key")
    (tmp_path / "ml.joblib").write_bytes(b"untrusted pickle")
    ok, reason = verify_profile(tmp_path, b"key")
    assert not ok
    assert "do not match" in reason
