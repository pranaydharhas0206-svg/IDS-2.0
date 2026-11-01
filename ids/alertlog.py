"""Append-only alert log: each JSONL record is hash-chained to the previous one and HMAC-signed.

Editing or reordering any record, or deleting a non-final record, breaks verification; forging a record needs the
key. Truncating the tail (dropping the newest records, or emptying the file) is NOT detectable from the chain alone.
To make it detectable, pass `anchor_path`: after every append the log's head (seq + entry hash, HMAC-signed) is
written atomically to that file. Keep the anchor on a different medium than the log (a second partition, a
write-once mount, or ship it off the vehicle); `verify_log(..., anchor=...)` then fails if the log is shorter than the
anchor or its history no longer matches. An attacker who can rewrite both files AND holds the key is out of scope.
Same tamper-evidence idea as the Objective 1 chain-of-custody log, so IDS output is forensics-ready.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import warnings
from pathlib import Path

from ids.core import Alert

GENESIS = "0" * 64
DEV_KEY = b"ids-dev-key-change-me"


def load_key(require: bool = False) -> bytes:
    k = os.environ.get("IDS_ALERT_KEY")
    if k:
        return k.encode("utf-8")
    if require:
        raise RuntimeError("IDS_ALERT_KEY is not set; refusing to sign alerts with the public development key")
    warnings.warn("IDS_ALERT_KEY not set: using the development key; alerts are not securely signed")
    return DEV_KEY


def _canon(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(key: bytes, body: dict) -> str:
    return hmac.new(key, _canon(body), hashlib.sha256).hexdigest()


def _fsync_write(path: Path, text: str, mode: str) -> None:
    with open(path, mode, encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())  # an alert that only reached the OS cache is lost on power cut / crash


class AlertLog:
    def __init__(self, path: str | Path, key: bytes, anchor_path: str | Path | None = None):
        self.path, self.key = Path(path), key
        self.anchor_path = Path(anchor_path) if anchor_path else None
        self.prev, self.seq = GENESIS, 0
        if self.path.exists():
            lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                try:
                    last = json.loads(lines[-1])
                    self.prev, self.seq = last["entry_hash"], last["seq"] + 1
                except (ValueError, KeyError, TypeError):
                    self._quarantine_torn_tail(lines)

    def _quarantine_torn_tail(self, lines: list[str]) -> None:
        """A crash or power cut mid-append leaves a torn last line. Keep the sensor running: move that line to a
        `.torn` sidecar (evidence is preserved, not deleted), resume the chain from the last intact record, and
        warn. `verify-log` then still passes on the remaining log; the anchor (if any) reports the lost record."""
        torn = lines.pop()
        with open(self.path.with_name(self.path.name + ".torn"), "a", encoding="utf-8") as f:
            f.write(torn + "\n")
        _fsync_write(self.path, "".join(ln + "\n" for ln in lines), "w")
        warnings.warn(f"alert log {self.path} ended in a torn record (crash?); moved to {self.path.name}.torn")
        if lines:
            last = json.loads(lines[-1])
            self.prev, self.seq = last["entry_hash"], last["seq"] + 1

    def head(self) -> tuple[int, str] | None:
        """(seq, entry_hash) of the newest record, or None for an empty log."""
        return None if self.seq == 0 else (self.seq - 1, self.prev)

    def append(self, alert: Alert) -> dict:
        body = {"seq": self.seq, "alert": alert.to_dict(), "prev_hash": self.prev}
        blob = _canon(body)
        rec = {**body, "entry_hash": hashlib.sha256(blob).hexdigest(),
               "hmac": hmac.new(self.key, blob, hashlib.sha256).hexdigest()}
        _fsync_write(self.path, json.dumps(rec, sort_keys=True) + "\n", "a")
        self.prev, self.seq = rec["entry_hash"], self.seq + 1
        self._write_anchor(rec["seq"], rec["entry_hash"])
        return rec

    def _write_anchor(self, seq: int, entry_hash: str) -> None:
        if self.anchor_path is None:
            return
        body = {"seq": seq, "entry_hash": entry_hash}
        tmp = self.anchor_path.with_name(self.anchor_path.name + ".tmp")
        _fsync_write(tmp, json.dumps({**body, "hmac": _sign(self.key, body)}), "w")
        os.replace(tmp, self.anchor_path)


def _check_anchor(anchor: str | Path, key: bytes, hashes: list[str]) -> tuple[bool, int | None, str]:
    try:
        a = json.loads(Path(anchor).read_text(encoding="utf-8"))
        body = {"seq": a["seq"], "entry_hash": a["entry_hash"]}
        good = hmac.compare_digest(_sign(key, body).encode(), str(a["hmac"]).encode())
    except (OSError, ValueError, KeyError, TypeError):
        return False, None, "anchor file unreadable or malformed"
    if not good:
        return False, None, "anchor signature invalid (forged or wrong key)"
    n = len(hashes)
    if n <= a["seq"]:
        return False, n, f"log truncated: anchor is at record {a['seq']} but the log has only {n} record(s)"
    if hashes[a["seq"]] != a["entry_hash"]:
        return False, a["seq"], "anchor mismatch: log history differs from the anchored head"
    return True, None, "ok"


def verify_log(path: str | Path, key: bytes, anchor: str | Path | None = None) -> tuple[bool, int | None, str]:
    prev = GENESIS
    hashes: list[str] = []
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
            body = {"seq": rec["seq"], "alert": rec["alert"], "prev_hash": rec["prev_hash"]}
            rec["entry_hash"], rec["hmac"]
        except (ValueError, KeyError, TypeError):
            return False, i, "malformed record"
        blob = _canon(body)
        if rec["seq"] != i:
            return False, i, "sequence gap"
        if rec["prev_hash"] != prev:
            return False, i, "broken hash chain"
        if hashlib.sha256(blob).hexdigest() != rec["entry_hash"]:
            return False, i, "entry hash mismatch"
        if not hmac.compare_digest(hmac.new(key, blob, hashlib.sha256).hexdigest().encode(), str(rec["hmac"]).encode()):
            return False, i, "bad HMAC"
        prev = rec["entry_hash"]
        hashes.append(prev)
    if anchor is not None:
        return _check_anchor(anchor, key, hashes)
    return True, None, "ok"
