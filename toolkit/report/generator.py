"""Forensic report generation (HTML)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from toolkit import __version__
from toolkit.core.case import Case
from toolkit.core.custody import ChainOfCustody

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_report(
    case: Case,
    custody: ChainOfCustody,
    analyses: list[dict],
    output_path: Path,
    carved_files: list[dict] | None = None,
) -> Path:
    """Render the HTML forensic report.

    analyses: list of {"evidence": Evidence, "result": ParserResult,
                        "flight_path_kml": str, "flight_path_geojson": str}
    carved_files: list of dicts (see toolkit.service._load_carved_manifest)
                  describing files recovered by signature-based media
                  carving, if any carving has been run for this case.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    ok, first_broken_seq = custody.verify_chain()
    custody_verification = {
        "ok": ok,
        "entry_count": len(custody.entries),
        "first_broken_seq": first_broken_seq,
    }

    render_analyses = [
        {
            "evidence": a["evidence"],
            "result": a["result"],
            "flight_path_kml": a.get("flight_path_kml", "—"),
            "flight_path_geojson": a.get("flight_path_geojson", "—"),
            "incursions": a.get("incursions", []),
        }
        for a in analyses
    ]

    html = template.render(
        case=case,
        custody_entries=[asdict(e) for e in custody.entries],
        custody_verification=custody_verification,
        analyses=render_analyses,
        carved_files=carved_files or [],
        generated_at=datetime.now(timezone.utc).isoformat(),
        toolkit_version=__version__,
    )

    output_path.write_text(html, encoding="utf-8")
    return output_path
