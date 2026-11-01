"""FastAPI backend for the AeroXperts case-management GUI.

Every route calls into toolkit.service — no business logic lives here. This
module only handles HTTP concerns: request/response shapes and mapping
service exceptions to status codes.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from toolkit import service

# Media type per carved-file extension, for the download/preview endpoint.
_CARVED_MEDIA_TYPES = {
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".mp4": "video/mp4",
}

CASES_ROOT = Path(os.environ.get("TOOLKIT_CASES_ROOT", "cases"))

app = FastAPI(title="AeroXperts Drone Forensics")

_EXCEPTION_STATUS = {
    service.CaseNotFoundError: 404,
    service.EvidenceNotFoundError: 404,
    service.AnalysisNotFoundError: 404,
    service.ParseError: 400,
    service.IntegrityError: 409,
}


@app.exception_handler(service.ToolkitError)
async def toolkit_error_handler(request: Request, exc: service.ToolkitError):
    status_code = _EXCEPTION_STATUS.get(type(exc), 400)
    return JSONResponse(status_code=status_code, content={"detail": str(exc)})


def _case_dir(case_id: str) -> Path:
    return CASES_ROOT / case_id


def _case_summary_dict(summary: service.CaseSummary) -> dict:
    return dataclasses.asdict(summary)


class CreateCaseRequest(BaseModel):
    examiner: str
    description: str = ""


@app.get("/api/cases")
def list_cases():
    return [_case_summary_dict(s) for s in service.list_cases(CASES_ROOT)]


@app.post("/api/cases")
def create_case(body: CreateCaseRequest):
    case_id = str(uuid.uuid4())
    case_dir = _case_dir(case_id)
    case = service.init_case(case_dir, examiner=body.examiner, description=body.description)
    return {
        "case_id": case_id,
        "internal_id": case.case_id,
        "examiner": case.examiner,
        "created_at": case.created_at,
        "description": case.description,
        "evidence_count": 0,
        "custody_ok": True,
    }


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    case_dir = _case_dir(case_id)
    case = service.get_case(case_dir)
    return {
        "case_id": case_id,
        "internal_id": case.case_id,
        "examiner": case.examiner,
        "created_at": case.created_at,
        "description": case.description,
        "evidence": [dataclasses.asdict(e) for e in case.evidence],
    }


@app.post("/api/cases/{case_id}/evidence")
async def acquire_evidence(
    case_id: str,
    file: UploadFile = File(...),
    platform: str = Form(...),
    examiner: str = Form(...),
    description: str = Form(""),
):
    case_dir = _case_dir(case_id)
    tmp_dir = Path(tempfile.mkdtemp(prefix="toolkit_upload_"))
    tmp_path = tmp_dir / file.filename
    with open(tmp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    try:
        evidence = service.acquire_evidence(
            case_dir, tmp_path, platform=platform, examiner=examiner, description=description,
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return dataclasses.asdict(evidence)


def _read_carved_manifest(case_dir: Path) -> list[dict]:
    """Read case_dir/carved/manifest.json, the cumulative carved-file record
    that toolkit.service.carve_evidence maintains across carve runs (also
    consumed by report generation). This module only reads it — the write
    path lives in service.carve_evidence.
    """
    manifest_path = case_dir / "carved" / "manifest.json"
    if not manifest_path.exists():
        return []
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def _manifest_entry_to_api(case_id: str, entry: dict) -> dict:
    file_id = Path(entry["output_path"]).name
    return {
        "file_id": file_id,
        "offset": entry["offset"],
        "size": entry["size"],
        "file_type": entry["file_type"],
        "sha256": entry["sha256"],
        "exif": entry["exif"],
        "source_filename": entry.get("source_filename"),
        "download_url": f"/api/cases/{case_id}/carved/{file_id}",
    }


@app.post("/api/cases/{case_id}/carve")
async def carve_evidence(
    case_id: str,
    file: UploadFile = File(...),
    examiner: str = Form(...),
):
    case_dir = _case_dir(case_id)
    service.get_case(case_dir)  # raises CaseNotFoundError -> 404 if missing

    tmp_dir = Path(tempfile.mkdtemp(prefix="toolkit_carve_upload_"))
    tmp_path = tmp_dir / file.filename
    with open(tmp_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    try:
        carved_files = service.carve_evidence(case_dir, tmp_path, examiner=examiner)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return [
        {
            "file_id": cf.output_path.name,
            "offset": cf.offset,
            "size": cf.size,
            "file_type": cf.file_type,
            "sha256": cf.sha256,
            "exif": cf.exif,
            "source_filename": file.filename,
            "download_url": f"/api/cases/{case_id}/carved/{cf.output_path.name}",
        }
        for cf in carved_files
    ]


@app.get("/api/cases/{case_id}/carved")
def list_carved_files(case_id: str):
    case_dir = _case_dir(case_id)
    service.get_case(case_dir)  # raises CaseNotFoundError -> 404 if missing
    manifest = _read_carved_manifest(case_dir)
    return [_manifest_entry_to_api(case_id, e) for e in manifest]


@app.get("/api/cases/{case_id}/carved/{file_id}")
def download_carved_file(case_id: str, file_id: str):
    case_dir = _case_dir(case_id)
    service.get_case(case_dir)  # raises CaseNotFoundError -> 404 if missing
    safe_name = Path(file_id).name  # guard against path traversal
    carved_path = case_dir / "carved" / safe_name
    if not carved_path.is_file():
        raise HTTPException(status_code=404, detail="Carved file not found.")
    media_type = _CARVED_MEDIA_TYPES.get(carved_path.suffix.lower(), "application/octet-stream")
    return FileResponse(carved_path, media_type=media_type)


class AnalyzeRequest(BaseModel):
    examiner: str
    evidence_id: str | None = None


@app.post("/api/cases/{case_id}/analyze")
def analyze(case_id: str, body: AnalyzeRequest):
    case_dir = _case_dir(case_id)
    outcomes = service.analyze_case(case_dir, examiner=body.examiner, evidence_id=body.evidence_id)
    return [dataclasses.asdict(o) for o in outcomes]


@app.get("/api/cases/{case_id}/evidence/{evidence_id}/analysis")
def get_analysis(case_id: str, evidence_id: str):
    case_dir = _case_dir(case_id)
    result = service.get_analysis_result(case_dir, evidence_id)
    return dataclasses.asdict(result)


class ReportRequest(BaseModel):
    examiner: str | None = None


@app.post("/api/cases/{case_id}/report")
def create_report(case_id: str, body: ReportRequest):
    case_dir = _case_dir(case_id)
    result = service.generate_case_report(case_dir, examiner=body.examiner)
    return {
        "path": str(result.path),
        "url": f"/api/cases/{case_id}/report",
        "pdf_url": f"/api/cases/{case_id}/report.pdf" if result.pdf_path else None,
        "skipped": [dataclasses.asdict(s) for s in result.skipped],
    }


@app.get("/api/cases/{case_id}/report")
def get_report(case_id: str):
    case_dir = _case_dir(case_id)
    report_path = case_dir / "reports" / "forensic_report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not generated yet.")
    return FileResponse(report_path, media_type="text/html")


@app.get("/api/cases/{case_id}/report.pdf")
def get_report_pdf(case_id: str):
    case_dir = _case_dir(case_id)
    pdf_path = case_dir / "reports" / "forensic_report.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="PDF report not generated yet.")
    return FileResponse(pdf_path, media_type="application/pdf")


@app.get("/api/cases/{case_id}/verify")
def verify(case_id: str):
    case_dir = _case_dir(case_id)
    result = service.verify_case(case_dir)
    return dataclasses.asdict(result)


@app.get("/api/cases/{case_id}/custody-log")
def custody_log(case_id: str):
    case_dir = _case_dir(case_id)
    return service.get_custody_log(case_dir)


@app.get("/api/cases/{case_id}/evidence/{evidence_id}/flight-path.kml")
def flight_path_kml(case_id: str, evidence_id: str):
    case_dir = _case_dir(case_id)
    path = case_dir / "analysis" / evidence_id / "flight_path.kml"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No flight path available for this evidence.")
    return FileResponse(path, media_type="application/vnd.google-earth.kml+xml")


@app.get("/api/cases/{case_id}/evidence/{evidence_id}/flight-path.geojson")
def flight_path_geojson(case_id: str, evidence_id: str):
    case_dir = _case_dir(case_id)
    path = case_dir / "analysis" / evidence_id / "flight_path.geojson"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No flight path available for this evidence.")
    return FileResponse(path, media_type="application/geo+json")


from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
