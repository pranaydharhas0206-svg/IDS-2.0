"""Hash-chained chain-of-custody log.

Each entry records who did what to which evidence item and when, and embeds
the SHA-256 hash of the previous entry (genesis entry uses 64 zero bytes).
This makes the log itself tamper-evident: altering or deleting a past entry
breaks every subsequent link, which `verify_chain` detects.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from toolkit.core.case import utcnow_iso

GENESIS_HASH = "0" * 64


@dataclass
class CustodyEntry:
    seq: int
    timestamp: str
    action: str  # acquired | hash_verified | analyzed | exported | note
    evidence_id: Optional[str]
    actor: str
    detail: str
    evidence_sha256: Optional[str]
    prev_entry_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "action": self.action,
            "evidence_id": self.evidence_id,
            "actor": self.actor,
            "detail": self.detail,
            "evidence_sha256": self.evidence_sha256,
            "prev_entry_hash": self.prev_entry_hash,
        }
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


class ChainOfCustody:
    def __init__(self, case_dir: Path):
        self.path = case_dir / "custody_log.json"
        self.entries: list[CustodyEntry] = []
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.entries = [CustodyEntry(**e) for e in raw]

    def _last_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS_HASH

    def record(
        self,
        action: str,
        actor: str,
        detail: str = "",
        evidence_id: Optional[str] = None,
        evidence_sha256: Optional[str] = None,
    ) -> CustodyEntry:
        entry = CustodyEntry(
            seq=len(self.entries),
            timestamp=utcnow_iso(),
            action=action,
            evidence_id=evidence_id,
            actor=actor,
            detail=detail,
            evidence_sha256=evidence_sha256,
            prev_entry_hash=self._last_hash(),
        )
        entry.entry_hash = entry.compute_hash()
        self.entries.append(entry)
        self._save()
        return entry

    def _save(self) -> None:
        self.path.write_text(
            json.dumps([asdict(e) for e in self.entries], indent=2),
            encoding="utf-8",
        )

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Recompute every entry's hash and check the linkage.

        Returns (ok, first_broken_seq). ok is False if any entry's stored
        hash doesn't match its recomputed hash, or if prev_entry_hash
        doesn't match the previous entry's actual hash.
        """
        prev_hash = GENESIS_HASH
        for entry in self.entries:
            if entry.prev_entry_hash != prev_hash:
                return False, entry.seq
            recomputed = entry.compute_hash()
            if recomputed != entry.entry_hash:
                return False, entry.seq
            prev_hash = entry.entry_hash
        return True, None
