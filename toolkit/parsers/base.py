"""Parser plugin interface.

Adding support for a new UAV platform means implementing this interface —
nothing in the acquisition, chain-of-custody, timeline, or reporting layers
needs to change. That is the toolkit's extensibility story.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from toolkit.core.timeline import TimelineEvent


@dataclass
class ParserResult:
    platform: str
    events: list[TimelineEvent]
    flight_summary: dict
    flight_path: list = field(default_factory=list)  # [{lat, lon, alt_m, timestamp_utc}, ...]
    warnings: list[str] = field(default_factory=list)
    implemented: bool = True
    partial: bool = False  # True: some real data extracted, but not full platform coverage


class ParserError(Exception):
    """Evidence could not be read at all (empty/truncated/unreadable file).

    Distinct from a file that parses but yields no useful data (which is a
    normal, non-error outcome carried in ParserResult.warnings) — this is
    for cases where the platform-specific parser can't even open the file.
    """


class BaseParser(ABC):
    """Interface every platform-specific forensic parser must implement."""

    platform_name: str = "base"

    @abstractmethod
    def can_parse(self, evidence_path: Path) -> bool:
        """Cheap format sniff — does this file look like this platform's log?"""
        raise NotImplementedError

    @abstractmethod
    def parse(self, evidence_path: Path) -> ParserResult:
        """Extract a normalized timeline and flight summary from evidence_path."""
        raise NotImplementedError


class NotImplementedParser(BaseParser):
    """Base class for platforms that are architected but not yet implemented.

    Returns an honest, explicit "not implemented" result rather than silently
    producing an empty timeline, so gaps are visible in reports instead of
    looking like a clean negative result.
    """

    reason: str = "Not implemented for this submission."

    def can_parse(self, evidence_path: Path) -> bool:
        # No format signature is known for this platform yet, so accept any
        # file rather than blocking evidence acquisition/preservation.
        return True

    def parse(self, evidence_path: Path) -> ParserResult:
        return ParserResult(
            platform=self.platform_name,
            events=[],
            flight_summary={},
            warnings=[self.reason],
            implemented=False,
        )
