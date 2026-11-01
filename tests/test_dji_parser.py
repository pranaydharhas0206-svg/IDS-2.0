"""Tests for the DJI header-only metadata parser.

No real DJI sample file is available for this submission (see
docs/design_document.md section 10), so these tests construct synthetic
100-byte Prefix headers matching the reverse-engineered layout the parser
implements (see toolkit/parsers/dji.py docstring for sourcing), rather than
testing against genuine evidentiary data.
"""

import struct
from pathlib import Path

from toolkit.parsers.dji import PREFIX_SIZE, DJIParser


def _make_header(version: int, detail_offset: int = 0, detail_length: int = 0) -> bytes:
    header = struct.pack("<QHBB", detail_offset, detail_length, version, 0)
    return header + b"\x00" * (PREFIX_SIZE - len(header))


def test_can_parse_recognizes_dat_extension_only():
    parser = DJIParser()
    assert parser.can_parse(Path("evidence.DAT")) is True
    assert parser.can_parse(Path("evidence.dat")) is True
    assert parser.can_parse(Path("evidence.bin")) is False


def test_parse_pre_aes_version_reports_header_fields(tmp_path):
    log = tmp_path / "flight.DAT"
    log.write_bytes(_make_header(version=6, detail_offset=1234, detail_length=200))

    parser = DJIParser()
    result = parser.parse(log)

    assert result.implemented is True
    assert result.partial is True
    assert result.flight_summary["format_version"] == 6
    assert result.flight_summary["header_declared_detail_offset"] == 1234
    assert result.flight_summary["header_declared_detail_length"] == 200
    assert "Not AES-encrypted" in result.flight_summary["encryption"]
    assert result.flight_path == []

    event_types = {e.event_type for e in result.events}
    assert "DJI_HEADER_PARSED" in event_types


def test_parse_version_12_and_above_ignores_stored_detail_offset(tmp_path):
    log = tmp_path / "flight.DAT"
    log.write_bytes(_make_header(version=12, detail_offset=999999, detail_length=50))

    result = DJIParser().parse(log)

    assert result.flight_summary["header_declared_detail_offset"] == PREFIX_SIZE
    assert result.flight_summary["header_declared_detail_length"] == 50


def test_parse_aes_encrypted_version_flags_encryption(tmp_path):
    log = tmp_path / "flight.DAT"
    log.write_bytes(_make_header(version=13, detail_offset=100, detail_length=300))

    result = DJIParser().parse(log)

    assert "AES-encrypted" in result.flight_summary["encryption"]
    assert "keychain" in result.flight_summary["encryption"]


def test_parse_version_outside_known_range_reports_only_version(tmp_path):
    log = tmp_path / "flight.DAT"
    log.write_bytes(_make_header(version=2, detail_offset=1, detail_length=1))

    result = DJIParser().parse(log)

    assert result.flight_summary["format_version"] == 2
    assert "header_declared_detail_offset" not in result.flight_summary
    assert any("outside the" in w for w in result.warnings)


def test_parse_file_too_small_is_not_implemented(tmp_path):
    log = tmp_path / "flight.DAT"
    log.write_bytes(b"\x00" * 10)

    result = DJIParser().parse(log)

    assert result.implemented is False
    assert result.flight_summary == {}
    assert any("smaller than" in w for w in result.warnings)
