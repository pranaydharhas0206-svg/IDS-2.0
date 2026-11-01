"""Normalized event/timeline model shared by all platform parsers.

Every parser converts platform-specific log records into a flat list of
TimelineEvent objects. This is what makes the toolkit "vendor-independent":
downstream code (timeline reconstruction, reporting, flight-path export)
only ever deals with this common shape, never raw ArduPilot/DJI structures.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


@dataclass
class TimelineEvent:
    timestamp_utc: str          # ISO-8601, UTC
    source: str                 # e.g. "ardupilot.dataflash"
    event_type: str             # e.g. "ARM", "DISARM", "GPS_FIX", "FAILSAFE", "MODE_CHANGE"
    description: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    extra: Optional[dict] = None


def merge_timelines(*event_lists: list[TimelineEvent]) -> list[TimelineEvent]:
    """Merge one or more event lists into a single chronologically sorted timeline."""
    merged: list[TimelineEvent] = []
    for events in event_lists:
        merged.extend(events)
    merged.sort(key=lambda e: e.timestamp_utc)
    return merged


def save_timeline(events: list[TimelineEvent], path: Path) -> None:
    path.write_text(
        json.dumps([asdict(e) for e in events], indent=2, default=str),
        encoding="utf-8",
    )


def load_timeline(path: Path) -> list[TimelineEvent]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [TimelineEvent(**e) for e in raw]
