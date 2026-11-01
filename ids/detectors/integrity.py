"""Firmware / configuration integrity: runtime baseline comparison + offline image attestation."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from pathlib import Path
from typing import Iterable

from ids.core import AttackClass, Finding, Msg

BANNER_RE = re.compile(r"^(APM:|ArduCopter|ArduPlane|ArduRover|ArduSub|PX4:|ChibiOS:)")
CRITICAL_PREFIXES = ("ARMING_CHECK", "FENCE_", "GPS_TYPE", "SYSID_MYGCS", "BRD_SAFETYENABLE", "FS_",
                     "SERIAL", "EK2_ENABLE", "EK3_ENABLE", "AHRS_EKF_TYPE")


def _text(msg: Msg) -> str:
    return str(msg.fields.get("text", "")).rstrip("\x00").strip()


def _pid(msg: Msg) -> str:
    return str(msg.fields.get("param_id", "")).rstrip("\x00")


def _version_sig(msg: Msg) -> str:
    f = msg.fields
    return f"{f.get('flight_sw_version')}:{bytes(f.get('flight_custom_version', [])).hex()}"


def build_baseline(msgs: Iterable[Msg]) -> dict:
    banners: list[str] = []
    params: dict[str, float] = {}
    version = None
    for m in msgs:
        if m.type == "STATUSTEXT":
            txt = _text(m)
            if BANNER_RE.match(txt) and txt not in banners:
                banners.append(txt)
        elif m.type == "PARAM_VALUE":
            params[_pid(m)] = float(m.fields["param_value"])
        elif m.type == "AUTOPILOT_VERSION" and version is None:
            version = _version_sig(m)
    blob = json.dumps(params, sort_keys=True).encode("utf-8")
    return {"banners": banners, "autopilot_version": version, "params": params,
            "params_sha256": hashlib.sha256(blob).hexdigest()}


class IntegrityDetector:
    name = "integrity"

    def __init__(self, baseline: dict | None):
        self.baseline = baseline

    def _f(self, msg, score, reason):
        return Finding(msg.t, self.name, AttackClass.FIRMWARE_INTEGRITY, score, reason)

    def feed(self, msg: Msg) -> list[Finding]:
        b = self.baseline
        if b is None:
            return []
        if msg.type == "STATUSTEXT":
            txt = _text(msg)
            if b["banners"] and BANNER_RE.match(txt) and txt not in b["banners"]:
                return [self._f(msg, 1.0, f"firmware banner '{txt}' not in baseline")]
        elif msg.type == "AUTOPILOT_VERSION" and b.get("autopilot_version"):
            if _version_sig(msg) != b["autopilot_version"]:
                return [self._f(msg, 1.0, "AUTOPILOT_VERSION differs from baseline")]
        elif msg.type == "PARAM_VALUE" and b["params"]:
            pid, val = _pid(msg), float(msg.fields["param_value"])
            base = b["params"].get(pid)
            if base is None:
                # A parameter the baseline never saw is only suspicious when it is safety-critical; otherwise a
                # benign parameter re-download would raise a fused CRITICAL alert.
                if pid.startswith(CRITICAL_PREFIXES):
                    return [self._f(msg, 0.5, f"parameter {pid} not in baseline")]
                return []
            if not math.isclose(val, base, rel_tol=1e-6, abs_tol=1e-6):
                score = 1.0 if pid.startswith(CRITICAL_PREFIXES) else 0.5
                return [self._f(msg, score, f"parameter {pid} changed {base:g} -> {val:g}")]
        return []


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_sig(images: dict, key: bytes) -> str:
    return hmac.new(key, json.dumps(images, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def enroll(path: str | Path, manifest: dict, key: bytes | None = None) -> dict:
    """Add an image to the golden manifest. With `key` the manifest is HMAC-signed, so swapping the golden hash
    (not only the image) is detected by `attest`."""
    path = Path(path)
    if key is not None and "hmac" in manifest and not hmac.compare_digest(
            _manifest_sig(manifest.get("images", {}), key).encode(), str(manifest["hmac"]).encode()):
        raise ValueError("existing manifest signature is invalid (edited or wrong key); refusing to re-sign it")
    images = dict(manifest.get("images", {}))
    images[path.name] = _sha256_file(path)
    out = {k: v for k, v in manifest.items() if k != "hmac"}
    out["images"] = images
    if key is not None:
        out["hmac"] = _manifest_sig(images, key)
    return out


def attest(path: str | Path, manifest: dict, key: bytes | None = None, require_signed: bool = False) -> dict:
    path = Path(path)
    digest = _sha256_file(path)
    expected = manifest.get("images", {}).get(path.name)
    res = {"name": path.name, "sha256": digest, "expected": expected, "ok": expected == digest,
           "signed": "hmac" in manifest, "reason": "ok" if expected == digest else "image hash differs from manifest"}
    if key is not None:
        sig = manifest.get("hmac")
        if sig is None:
            if require_signed:
                res.update(ok=False, reason="manifest unsigned but a signature is required")
            else:
                res["reason"] += " (manifest unsigned: the manifest itself is not authenticated)"
        elif not hmac.compare_digest(_manifest_sig(manifest.get("images", {}), key).encode(), str(sig).encode()):
            res.update(ok=False, reason="manifest signature invalid (manifest edited or wrong key)")
    return res
