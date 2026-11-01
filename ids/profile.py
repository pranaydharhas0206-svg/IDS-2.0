"""Authenticated IDS calibration profiles.

The manifest authenticates every profile file before any optional model is deserialized.
Use a private IDS_ALERT_KEY in deployments; the built-in development key is for local
reproducibility only and provides no protection against a source-code-aware attacker.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from ids.alertlog import load_key

PROFILE_FILES = {"thresholds.json", "baseline.json", "ml.joblib"}


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_profile(directory: str | Path, key: bytes | None = None) -> dict:
    directory = Path(directory)
    files = {}
    for name in ("thresholds.json", "baseline.json", "ml.joblib"):
        path = directory / name
        if path.is_file():
            files[name] = _digest(path)
    body = {"format": 1, "files": files}
    key = key or load_key()
    signed = {**body, "hmac_sha256": hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()}
    (directory / "profile.manifest.json").write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
    return signed


def verify_profile(directory: str | Path, key: bytes | None = None) -> tuple[bool, str]:
    directory = Path(directory)
    manifest_path = directory / "profile.manifest.json"
    if not manifest_path.is_file():
        return False, "profile has no integrity manifest; recalibrate to create one"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        body = {"format": manifest["format"], "files": manifest["files"]}
        if body["format"] != 1 or not isinstance(body["files"], dict):
            return False, "unsupported profile manifest format"
        if not set(body["files"]).issubset(PROFILE_FILES):
            return False, "profile manifest contains an unexpected file"
        present = {name for name in PROFILE_FILES if (directory / name).is_file()}
        if present != set(body["files"]):
            return False, "profile files do not match the authenticated manifest"
        expected = hmac.new(key or load_key(), _canonical(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(manifest["hmac_sha256"])):
            return False, "profile signature invalid (wrong key or manifest modified)"
        for name, digest in body["files"].items():
            path = directory / name
            if not path.is_file() or not hmac.compare_digest(_digest(path), str(digest)):
                return False, f"profile file missing or modified: {name}"
        return True, "ok"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, f"profile manifest invalid: {exc}"
