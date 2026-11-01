"""DJI flight-log parser — header-only metadata extraction.

DJI .DAT flight logs are a proprietary, versioned binary format whose record/
telemetry stream is AES-encrypted (with a per-file, vendor-specific keychain)
from format version 13 onward. Correctly and defensibly decoding that stream
— rather than shelling out to a third-party closed decoder of unknown
provenance, which would break forensic soundness/chain-of-custody guarantees
— is out of scope for this submission window. See docs/design_document.md
for the planned full-decode approach.

What this module implements is the fallback docs/design_document.md's risk
assessment (section 10) calls out: "partial support (e.g. metadata-only
extraction from unencrypted header fields)". Every DJI log, regardless of
version or encryption, starts with a fixed-size, unencrypted 100-byte
"Prefix" header. This parser reads only those 100 bytes and reports the
handful of fields it contains: the format version byte, and (for the
version range this layout was confirmed against) the header-declared offset
and length of the log's "Details" section.

This layout is not vendor-documented (DJI has never published it); it is
cross-referenced here from two independent public reverse-engineering
efforts: https://djilogs.live555.com/ and the open-source `dji-log-parser`
Rust crate (https://github.com/lvauvillier/dji-log-parser). Neither this
parser nor those references have been validated against a real DJI sample
file — none was available for this submission (see docs/design_document.md
section 10, hardware risk). Nothing past byte 99 of the file is read or
decoded by this parser.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from toolkit.core.timeline import TimelineEvent
from toolkit.parsers.base import BaseParser, ParserResult

# The DJI Prefix header is 100 bytes: an 8-byte header-declared detail
# offset, a 2-byte header-declared detail length, a 1-byte format version, a
# 1-byte unknown/reserved field, then 88 further reserved bytes not decoded
# here. See module docstring for sourcing.
PREFIX_SIZE = 100
_PREFIX_STRUCT = struct.Struct("<QHBB")  # detail_offset, detail_length, version, unknown

# Format versions whose Prefix layout matches _PREFIX_STRUCT per the public
# references this module is based on. Versions below this range are known to
# use a different, shorter, undocumented prefix; versions above it are
# unobserved in the references consulted, so this parser doesn't guess.
KNOWN_VERSION_RANGE = (6, 14)

# From format version 13 onward, DJI's record/detail stream is AES-encrypted
# with a per-file keychain this toolkit has no way to obtain. Below that,
# the stream is not AES-encrypted (older obfuscation may still apply).
AES_ENCRYPTED_FROM_VERSION = 13

_SCOPE_WARNING = (
    "DJI log parsing in this toolkit is header-metadata-only: the "
    "record/telemetry stream is not decoded (proprietary format, "
    "AES-encrypted from format version 13 onward). No flight path, no "
    "timeline of flight events, and no flight summary is available for DJI "
    "evidence beyond the header fields reported below — see "
    "docs/design_document.md."
)


class DJIParser(BaseParser):
    platform_name = "dji"

    def can_parse(self, evidence_path: Path) -> bool:
        return evidence_path.suffix.upper() == ".DAT"

    def parse(self, evidence_path: Path) -> ParserResult:
        file_size = evidence_path.stat().st_size
        warnings = [_SCOPE_WARNING]

        if file_size < PREFIX_SIZE:
            warnings.append(
                f"File is {file_size} bytes, smaller than the "
                f"{PREFIX_SIZE}-byte DJI Prefix header — this cannot be a "
                "valid DJI flight log. No header fields extracted."
            )
            return ParserResult(
                platform=self.platform_name,
                events=[],
                flight_summary={},
                warnings=warnings,
                implemented=False,
            )

        with open(evidence_path, "rb") as f:
            header = f.read(PREFIX_SIZE)

        raw_detail_offset, raw_detail_length, version, _unknown = (
            _PREFIX_STRUCT.unpack(header[: _PREFIX_STRUCT.size])
        )

        flight_summary = {
            "format_version": version,
            "file_size_bytes": file_size,
            "header_source": (
                "Prefix header only (file bytes 0-99); reverse-engineered "
                "layout, not vendor-documented — see module docstring."
            ),
        }

        low, high = KNOWN_VERSION_RANGE
        if low <= version <= high:
            # From version 12 onward the stored offset isn't used; the
            # Details section immediately follows the fixed-size Prefix.
            detail_offset = PREFIX_SIZE if version >= 12 else raw_detail_offset
            flight_summary["header_declared_detail_offset"] = detail_offset
            flight_summary["header_declared_detail_length"] = raw_detail_length
        else:
            warnings.append(
                f"Format version byte is {version}, outside the "
                f"{low}-{high} range this parser's header layout was "
                "reverse-engineered against; only format_version and "
                "file_size_bytes are reported for this file."
            )

        if version >= AES_ENCRYPTED_FROM_VERSION:
            flight_summary["encryption"] = (
                f"AES-encrypted (format version {version} >= "
                f"{AES_ENCRYPTED_FROM_VERSION}); record/detail decoding "
                "requires a DJI-specific keychain this toolkit does not have."
            )
        else:
            flight_summary["encryption"] = (
                f"Not AES-encrypted at format version {version}; full "
                "record/detail decoding is architecturally possible but not "
                "implemented in this toolkit — see docs/design_document.md."
            )

        event = TimelineEvent(
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            source="dji.header",
            event_type="DJI_HEADER_PARSED",
            description=(
                f"DJI log header parsed: format_version={version}, "
                f"file_size={file_size} bytes. The header carries no flight "
                "timestamp, so this event's timestamp reflects analysis "
                "time, not flight time. Record/telemetry content not "
                "decoded."
            ),
            extra={"format_version": version},
        )

        return ParserResult(
            platform=self.platform_name,
            events=[event],
            flight_summary=flight_summary,
            flight_path=[],
            warnings=warnings,
            implemented=True,
            partial=True,
        )
