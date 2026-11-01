import math
from pathlib import Path

import pytest

from toolkit.parsers.base import ParserError
from toolkit.parsers.px4 import EARTH_RADIUS_M, PX4Parser, _local_to_latlon

SAMPLE_LOG = Path(__file__).parent.parent / "sample_data" / "px4_sample.ulg"


def test_can_parse_recognizes_ulg_extension():
    parser = PX4Parser()
    assert parser.can_parse(Path("evidence.ulg")) is True
    assert parser.can_parse(Path("evidence.ULG")) is True
    assert parser.can_parse(Path("evidence.bin")) is False
    assert parser.can_parse(Path("evidence.log")) is False


def test_parse_empty_file_raises_parser_error(tmp_path):
    empty = tmp_path / "empty.ulg"
    empty.write_bytes(b"")

    with pytest.raises(ParserError):
        PX4Parser().parse(empty)


def test_parse_garbage_file_does_not_crash_and_closes_file_handle(tmp_path):
    # A non-empty file that isn't a real ULog (wrong platform, bit rot,
    # partial acquisition) must not raise and must not leak the
    # underlying file handle (verified here by successfully deleting the
    # file right after parsing).
    garbage = tmp_path / "garbage.ulg"
    garbage.write_bytes(bytes(range(256)) * 8)

    result = PX4Parser().parse(garbage)

    assert result.implemented is True
    assert result.events == []
    assert any("corrupt" in w.lower() or "unreadable" in w.lower() for w in result.warnings)

    garbage.unlink()  # raises on Windows if the file was left open


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/px4_sample.ulg not present")
def test_parse_extracts_arm_event_and_timeline_from_real_sample():
    parser = PX4Parser()
    result = parser.parse(SAMPLE_LOG)

    assert result.implemented is True
    assert result.flight_summary["arm_count"] >= 1
    assert result.flight_summary["duration_s"] > 0

    event_types = {e.event_type for e in result.events}
    assert "ARMED" in event_types
    # The real sample's vehicle_status.nav_state changes once (14 -> 1)
    # during the recorded window — verified by direct inspection.
    assert "MODE_CHANGE" in event_types

    # Timeline must be chronologically sorted.
    timestamps = [e.timestamp_utc for e in result.events]
    assert timestamps == sorted(timestamps)


def test_local_to_latlon_one_degree_north():
    # x is exactly the arc-length (in metres, on a sphere of EARTH_RADIUS_M)
    # of one degree of latitude, so the flat-earth conversion should yield
    # lat == 1.0 exactly (up to floating point) and lon unchanged, hand
    # verifiable against the formula: lat = ref_lat + (x / R) * (180 / pi).
    one_degree_m = EARTH_RADIUS_M * (math.pi / 180.0)

    lat, lon = _local_to_latlon(ref_lat=0.0, ref_lon=0.0, x=one_degree_m, y=0.0)

    assert lat == pytest.approx(1.0, abs=1e-9)
    assert lon == pytest.approx(0.0, abs=1e-9)


def test_local_to_latlon_one_degree_east():
    # Same idea along the east (y) axis, at the equator (ref_lat=0) where
    # cos(ref_lat) == 1 so a degree of longitude has the same arc-length
    # as a degree of latitude.
    one_degree_m = EARTH_RADIUS_M * (math.pi / 180.0)

    lat, lon = _local_to_latlon(ref_lat=0.0, ref_lon=0.0, x=0.0, y=one_degree_m)

    assert lat == pytest.approx(0.0, abs=1e-9)
    assert lon == pytest.approx(1.0, abs=1e-9)


def test_local_to_latlon_offsets_from_nonzero_reference():
    # A non-zero reference should simply be added to the computed offset.
    one_degree_m = EARTH_RADIUS_M * (math.pi / 180.0)

    lat, lon = _local_to_latlon(ref_lat=10.0, ref_lon=20.0, x=one_degree_m, y=0.0)

    assert lat == pytest.approx(11.0, abs=1e-9)
    assert lon == pytest.approx(20.0, abs=1e-9)


class _FakeDataset:
    def __init__(self, data):
        self.data = data


class _FakeULog:
    """Minimal stand-in for pyulog.ULog exposing just what PX4Parser reads."""

    def __init__(self, datasets, msg_info_dict=None):
        self._datasets = datasets
        self.msg_info_dict = msg_info_dict or {}
        self.logged_messages = []
        self.start_timestamp = 0
        self.last_timestamp = 1_000_000

    def get_dataset(self, name):
        if name not in self._datasets:
            raise KeyError(name)
        return self._datasets[name]

    def get_version_info_str(self):
        return None


def test_parse_flight_path_conversion_from_local_position_with_gps_reference(monkeypatch, tmp_path):
    # End-to-end coverage of the ref_lat/ref_lon/ref_alt -> flight_path
    # conversion math, via a synthetic vehicle_local_position dataset with
    # a known, valid GPS reference (never exercised by the real sample,
    # which has no GPS fix at all).
    ref_lat, ref_lon, ref_alt = 47.0, 8.0, 500.0
    one_degree_m = EARTH_RADIUS_M * (math.pi / 180.0)

    local_position = _FakeDataset({
        "timestamp": [0],
        "x": [one_degree_m],
        "y": [0.0],
        "z": [-10.0],
        "vx": [0.0], "vy": [0.0], "vz": [0.0],
        "xy_global": [True],
        "z_global": [True],
        "ref_lat": [ref_lat],
        "ref_lon": [ref_lon],
        "ref_alt": [ref_alt],
    })
    fake_ulog = _FakeULog({"vehicle_local_position": local_position})

    monkeypatch.setattr("pyulog.ULog", lambda fh: fake_ulog)

    fake_log_file = tmp_path / "fake.ulg"
    fake_log_file.write_bytes(b"\x00" * 64)

    result = PX4Parser().parse(fake_log_file)

    assert len(result.flight_path) == 1
    point = result.flight_path[0]
    assert point["latitude"] == pytest.approx(ref_lat + 1.0, abs=1e-9)
    assert point["longitude"] == pytest.approx(ref_lon, abs=1e-9)
    # alt = ref_alt - z = 500.0 - (-10.0) = 510.0
    assert point["altitude_m"] == pytest.approx(510.0, abs=1e-9)
    assert result.flight_summary["max_altitude_m"] == pytest.approx(510.0, abs=1e-9)


def test_parse_flight_path_skips_sample_with_nan_ref_alt(monkeypatch, tmp_path):
    # ref_alt present but NaN, while ref_lat/ref_lon are valid, must be
    # treated as non-georeferenced (skipped) just like NaN ref_lat/ref_lon
    # already are -- otherwise a NaN alt leaks into flight_path/JSON output.
    local_position = _FakeDataset({
        "timestamp": [0],
        "x": [0.0],
        "y": [0.0],
        "z": [0.0],
        "vx": [0.0], "vy": [0.0], "vz": [0.0],
        "xy_global": [True],
        "z_global": [True],
        "ref_lat": [47.0],
        "ref_lon": [8.0],
        "ref_alt": [float("nan")],
    })
    fake_ulog = _FakeULog({"vehicle_local_position": local_position})

    monkeypatch.setattr("pyulog.ULog", lambda fh: fake_ulog)

    fake_log_file = tmp_path / "fake.ulg"
    fake_log_file.write_bytes(b"\x00" * 64)

    result = PX4Parser().parse(fake_log_file)

    assert result.flight_path == []


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/px4_sample.ulg not present")
def test_parse_real_sample_has_no_gps_fix_so_flight_path_is_empty():
    # Verified by direct inspection: this sample log carries no
    # vehicle_gps_position/sensor_gps topic at all, and its
    # vehicle_local_position samples never have a valid global (GPS)
    # reference (xy_global/z_global are 0, ref_lat/ref_lon are NaN
    # throughout) — it appears to be an indoor/bench flight without a GPS
    # fix. flight_path must therefore come back honestly empty rather than
    # fabricating coordinates from unreferenced local position data, and a
    # warning must say so.
    parser = PX4Parser()
    result = parser.parse(SAMPLE_LOG)

    assert result.flight_path == []
    assert result.flight_summary["gps_track_points"] == 0
    assert any("gps" in w.lower() or "global" in w.lower() for w in result.warnings)
