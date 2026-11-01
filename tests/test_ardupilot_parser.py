from pathlib import Path

import pytest

from toolkit.parsers.ardupilot import ArduPilotParser

SAMPLE_LOG = Path(__file__).parent.parent / "sample_data" / "ardupilot_sample.bin"
SAMPLE_TLOG = Path(__file__).parent.parent / "sample_data" / "ardupilot_sample.tlog"


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_can_parse_recognizes_bin_extension():
    parser = ArduPilotParser()
    assert parser.can_parse(SAMPLE_LOG) is True
    assert parser.can_parse(Path("evidence.DAT")) is False


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_parse_extracts_arm_event_and_flight_path():
    parser = ArduPilotParser()
    result = parser.parse(SAMPLE_LOG)

    assert result.implemented is True
    assert result.flight_summary["arm_count"] >= 1
    assert len(result.flight_path) > 0
    assert result.flight_summary["duration_s"] > 0

    event_types = {e.event_type for e in result.events}
    assert "ARMED" in event_types
    assert "MODE_CHANGE" in event_types

    # Timeline must be chronologically sorted.
    timestamps = [e.timestamp_utc for e in result.events]
    assert timestamps == sorted(timestamps)


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_parse_flags_altitude_anomalies_present_in_sample_log():
    # The public sample log has real GPS altitude glitches near the end of
    # the flight (verified by direct inspection of the raw GPS.Alt values);
    # this locks in that the anomaly detector actually fires on real data,
    # not just synthetic fixtures.
    parser = ArduPilotParser()
    result = parser.parse(SAMPLE_LOG)

    assert result.flight_summary["altitude_anomaly_count"] > 0
    anomaly_events = [e for e in result.events if e.event_type == "ALTITUDE_ANOMALY"]
    assert len(anomaly_events) == result.flight_summary["altitude_anomaly_count"]
    assert any("altitude anomaly" in w.lower() for w in result.warnings)


@pytest.mark.skipif(not SAMPLE_TLOG.exists(), reason="sample_data/ardupilot_sample.tlog not present")
def test_parse_tlog_extracts_arm_mode_and_flight_path():
    # ardupilot_sample.tlog is a real MAVLink telemetry stream (HEARTBEAT/
    # STATUSTEXT/GPS_RAW_INT), not a dataflash log (MSG/MODE/EV/GPS) — the
    # dataflash-only message handling previously left can_parse() claiming
    # .tlog support while every real .tlog silently parsed to zero events
    # and an empty flight path.
    parser = ArduPilotParser()
    assert parser.can_parse(SAMPLE_TLOG) is True
    result = parser.parse(SAMPLE_TLOG)

    assert result.implemented is True
    assert result.flight_summary["arm_count"] >= 1
    assert result.flight_summary["disarm_count"] >= 1
    assert len(result.flight_path) > 0
    assert result.flight_summary["duration_s"] > 0
    assert result.flight_summary["firmware"] is not None

    event_types = {e.event_type for e in result.events}
    assert "ARMED" in event_types
    assert "DISARMED" in event_types
    assert "MODE_CHANGE" in event_types
    assert "GPS_FIX_ACQUIRED" in event_types

    timestamps = [e.timestamp_utc for e in result.events]
    assert timestamps == sorted(timestamps)


def test_parse_empty_file_raises_clear_parse_error(tmp_path):
    # A zero-byte evidence file previously crashed pymavlink with an
    # unhandled "cannot mmap an empty file" ValueError deep inside
    # mavutil — a corrupted/truncated acquisition must surface as a
    # forensic finding, not an unhandled traceback.
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")

    from toolkit.parsers.base import ParserError

    with pytest.raises(ParserError, match="empty|corrupt"):
        ArduPilotParser().parse(empty)


def test_parse_garbage_file_does_not_crash_and_closes_file_handle(tmp_path):
    # A non-empty file that isn't a real dataflash log (wrong platform,
    # bit rot, partial acquisition) must not raise, must not spam stdout
    # with pymavlink's internal "bad header" debug prints, and must not
    # leak the underlying file handle (verified here by successfully
    # deleting the file right after parsing — this previously failed on
    # Windows with a PermissionError because mavutil's connection was
    # never closed).
    garbage = tmp_path / "garbage.bin"
    garbage.write_bytes(bytes(range(256)) * 8)

    result = ArduPilotParser().parse(garbage)

    assert result.implemented is True
    assert result.events == []
    assert any("corrupt" in w.lower() or "unreadable" in w.lower() for w in result.warnings)

    garbage.unlink()  # raises on Windows if mavutil left the file open
