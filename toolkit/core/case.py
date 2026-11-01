"""Case and evidence data models.

A "case" is a directory on disk with a fixed layout:

    <case_dir>/
        case.json           case metadata
        custody_log.json    append-only, hash-chained chain-of-custody log
        evidence/           forensic copies of acquired source files (read-only)
        analysis/           per-evidence extracted artifacts (timeline, flight path, ...)
        reports/            generated forensic reports
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Evidence:
    evidence_id: str
    original_filename: str
    platform: str  # e.g. "ardupilot", "dji", "remote_controller", "mobile_app"
    source_description: str
    acquired_path: str  # path relative to case_dir, under evidence/
    sha256: str
    acquired_at: str
    examiner: str


@dataclass
class Case:
    case_id: str
    examiner: str
    created_at: str
    description: str = ""
    evidence: list = field(default_factory=list)

    @staticmethod
    def create(case_dir: Path, examiner: str, description: str = "") -> "Case":
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence").mkdir(exist_ok=True)
        (case_dir / "analysis").mkdir(exist_ok=True)
        (case_dir / "reports").mkdir(exist_ok=True)

        case = Case(
            case_id=str(uuid.uuid4()),
            examiner=examiner,
            created_at=utcnow_iso(),
            description=description,
            evidence=[],
        )
        case.save(case_dir)
        return case

    @staticmethod
    def load(case_dir: Path) -> "Case":
        data = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        data["evidence"] = [Evidence(**e) for e in data.get("evidence", [])]
        return Case(**data)

    def save(self, case_dir: Path) -> None:
        data = asdict(self)
        (case_dir / "case.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def add_evidence(self, case_dir: Path, evidence: Evidence) -> None:
        self.evidence.append(evidence)
        self.save(case_dir)

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        for e in self.evidence:
            if e.evidence_id == evidence_id:
                return e
        return None
