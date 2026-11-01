import json

from toolkit.geo import export_geojson, export_kml

SAMPLE_TRACK = [
    {"timestamp_utc": "2026-01-01T00:00:00+00:00", "latitude": 12.0, "longitude": 77.0, "altitude_m": 500.0},
    {"timestamp_utc": "2026-01-01T00:00:01+00:00", "latitude": 12.001, "longitude": 77.001, "altitude_m": 505.0},
]


def test_export_kml_creates_file(tmp_path):
    out = tmp_path / "track.kml"
    export_kml(SAMPLE_TRACK, out)
    assert out.exists()
    assert b"LineString" in out.read_bytes()


def test_export_geojson_roundtrip(tmp_path):
    out = tmp_path / "track.geojson"
    export_geojson(SAMPLE_TRACK, out)
    data = json.loads(out.read_text())
    assert data["type"] == "FeatureCollection"
    coords = data["features"][0]["geometry"]["coordinates"]
    assert coords[0] == [77.0, 12.0, 500.0]
