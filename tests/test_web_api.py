"""API tests for toolkit.web.app — mirrors the CLI integration test scenarios
via FastAPI's TestClient instead of subprocess calls.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from toolkit.web import app as app_module

REPO_ROOT = Path(__file__).parent.parent
SAMPLE_LOG = REPO_ROOT / "sample_data" / "ardupilot_sample.bin"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "CASES_ROOT", tmp_path / "cases")
    return TestClient(app_module.app)


def test_list_cases_empty(client):
    r = client.get("/api/cases")
    assert r.status_code == 200
    assert r.json() == []


def test_create_and_list_case(client):
    r = client.post("/api/cases", json={"examiner": "Tester", "description": "demo"})
    assert r.status_code == 200
    body = r.json()
    assert body["examiner"] == "Tester"
    case_id = body["case_id"]

    r = client.get("/api/cases")
    assert r.status_code == 200
    cases = r.json()
    assert len(cases) == 1
    assert cases[0]["case_id"] == case_id
    assert cases[0]["evidence_count"] == 0


def _create_case(client, examiner="Tester", description=""):
    r = client.post("/api/cases", json={"examiner": examiner, "description": description})
    assert r.status_code == 200
    return r.json()["case_id"]


def test_get_case_detail(client):
    case_id = _create_case(client)

    r = client.get(f"/api/cases/{case_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["case_id"] == case_id
    assert body["evidence"] == []


def test_get_case_detail_not_found(client):
    r = client.get("/api/cases/does-not-exist")
    assert r.status_code == 404


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_acquire_evidence_via_upload(client):
    case_id = _create_case(client)

    with open(SAMPLE_LOG, "rb") as f:
        r = client.post(
            f"/api/cases/{case_id}/evidence",
            files={"file": ("ardupilot_sample.bin", f, "application/octet-stream")},
            data={"platform": "ardupilot", "examiner": "Tester", "description": "sample"},
        )

    assert r.status_code == 200
    body = r.json()
    assert body["platform"] == "ardupilot"

    r = client.get(f"/api/cases/{case_id}")
    assert len(r.json()["evidence"]) == 1


def test_acquire_evidence_unknown_platform_returns_400(client):
    case_id = _create_case(client)

    r = client.post(
        f"/api/cases/{case_id}/evidence",
        files={"file": ("x.bin", b"data", "application/octet-stream")},
        data={"platform": "not_a_platform", "examiner": "Tester"},
    )

    assert r.status_code == 400


def _acquire_via_api(client, case_id):
    with open(SAMPLE_LOG, "rb") as f:
        r = client.post(
            f"/api/cases/{case_id}/evidence",
            files={"file": ("ardupilot_sample.bin", f, "application/octet-stream")},
            data={"platform": "ardupilot", "examiner": "Tester"},
        )
    assert r.status_code == 200
    return r.json()["evidence_id"]


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_analyze_and_get_result(client):
    case_id = _create_case(client)
    evidence_id = _acquire_via_api(client, case_id)

    r = client.post(f"/api/cases/{case_id}/analyze", json={"examiner": "Tester"})
    assert r.status_code == 200
    outcomes = r.json()
    assert outcomes[0]["status"] == "OK"

    r = client.get(f"/api/cases/{case_id}/evidence/{evidence_id}/analysis")
    assert r.status_code == 200
    result = r.json()
    assert result["platform"] == "ardupilot"
    assert len(result["events"]) > 0


def test_get_analysis_before_analyze_returns_404(client):
    case_id = _create_case(client)
    evidence_id = _acquire_via_api(client, case_id) if SAMPLE_LOG.exists() else None
    if evidence_id is None:
        pytest.skip("sample_data/ardupilot_sample.bin not present")

    r = client.get(f"/api/cases/{case_id}/evidence/{evidence_id}/analysis")
    assert r.status_code == 404


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_generate_and_get_report(client):
    case_id = _create_case(client)
    _acquire_via_api(client, case_id)
    client.post(f"/api/cases/{case_id}/analyze", json={"examiner": "Tester"})

    r = client.post(f"/api/cases/{case_id}/report", json={"examiner": "Tester"})
    assert r.status_code == 200
    assert r.json()["url"] == f"/api/cases/{case_id}/report"

    r = client.get(f"/api/cases/{case_id}/report")
    assert r.status_code == 200
    assert "VERIFIED" in r.text


def test_get_report_before_generated_returns_404(client):
    case_id = _create_case(client)

    r = client.get(f"/api/cases/{case_id}/report")
    assert r.status_code == 404


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_verify_case(client):
    case_id = _create_case(client)
    _acquire_via_api(client, case_id)

    r = client.get(f"/api/cases/{case_id}/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["custody_ok"] is True
    assert body["evidence"][0]["status"] == "OK"


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_custody_log(client):
    case_id = _create_case(client)
    _acquire_via_api(client, case_id)

    r = client.get(f"/api/cases/{case_id}/custody-log")
    assert r.status_code == 200
    entries = r.json()
    assert entries[0]["action"] == "case_opened"


def _minimal_jpeg() -> bytes:
    """A tiny but well-formed JPEG: SOI + APP0/JFIF segment + EOI."""
    app0 = (
        b"\xff\xe0"
        b"\x00\x10"
        b"JFIF\x00"
        b"\x01\x01"
        b"\x00"
        b"\x00\x01\x00\x01"
        b"\x00\x00"
    )
    return b"\xff\xd8" + app0 + b"\xff\xd9"


def _minimal_png() -> bytes:
    """A tiny but well-formed 1x1 PNG: signature + IHDR + IDAT + IEND."""
    import struct
    import zlib

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return signature + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


PADDING = b"PADDING-BYTES-NOT-A-SIGNATURE-" * 20


def _synthetic_sd_image() -> bytes:
    image = bytearray()
    image += PADDING
    image += _minimal_jpeg()
    image += PADDING
    image += _minimal_png()
    image += PADDING
    return bytes(image)


def test_carve_via_upload(client):
    case_id = _create_case(client)
    image_bytes = _synthetic_sd_image()

    r = client.post(
        f"/api/cases/{case_id}/carve",
        files={"file": ("sdcard.img", image_bytes, "application/octet-stream")},
        data={"examiner": "Tester"},
    )

    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    types = {item["file_type"] for item in body}
    assert types == {"jpeg", "png"}
    for item in body:
        assert "file_id" in item
        assert "sha256" in item
        assert "size" in item
        assert "offset" in item
        assert "download_url" in item
        assert item["download_url"] == f"/api/cases/{case_id}/carved/{item['file_id']}"


def test_carve_unknown_case_returns_404(client):
    r = client.post(
        "/api/cases/does-not-exist/carve",
        files={"file": ("sdcard.img", b"data", "application/octet-stream")},
        data={"examiner": "Tester"},
    )
    assert r.status_code == 404


def test_list_carved_files(client):
    case_id = _create_case(client)
    image_bytes = _synthetic_sd_image()

    r = client.get(f"/api/cases/{case_id}/carved")
    assert r.status_code == 200
    assert r.json() == []

    client.post(
        f"/api/cases/{case_id}/carve",
        files={"file": ("sdcard.img", image_bytes, "application/octet-stream")},
        data={"examiner": "Tester"},
    )

    r = client.get(f"/api/cases/{case_id}/carved")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2


def test_download_carved_file(client):
    case_id = _create_case(client)
    jpeg_bytes = _minimal_jpeg()
    image_bytes = PADDING + jpeg_bytes + PADDING

    r = client.post(
        f"/api/cases/{case_id}/carve",
        files={"file": ("sdcard.img", image_bytes, "application/octet-stream")},
        data={"examiner": "Tester"},
    )
    carved = r.json()
    assert len(carved) == 1
    file_id = carved[0]["file_id"]

    r = client.get(f"/api/cases/{case_id}/carved/{file_id}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/jpeg")
    assert r.content == jpeg_bytes


def test_download_carved_file_not_found(client):
    case_id = _create_case(client)
    r = client.get(f"/api/cases/{case_id}/carved/does-not-exist.jpg")
    assert r.status_code == 404


@pytest.mark.skipif(not SAMPLE_LOG.exists(), reason="sample_data/ardupilot_sample.bin not present")
def test_flight_path_exports_after_analyze(client):
    case_id = _create_case(client)
    evidence_id = _acquire_via_api(client, case_id)
    client.post(f"/api/cases/{case_id}/analyze", json={"examiner": "Tester"})

    r = client.get(f"/api/cases/{case_id}/evidence/{evidence_id}/flight-path.kml")
    assert r.status_code == 200

    r = client.get(f"/api/cases/{case_id}/evidence/{evidence_id}/flight-path.geojson")
    assert r.status_code == 200
    assert r.json()["type"] == "FeatureCollection"
