"""PDF rendering of the already-generated HTML forensic report.

Uses xhtml2pdf (pure-Python, reportlab-based) rather than a
browser-engine-backed renderer (e.g. WeasyPrint/Chromium) so the toolkit
keeps working with `pip install -e .` alone on any platform, with no system
package dependencies (Cairo/Pango/a Chromium binary, etc.) — the same
reproducibility bar the rest of this toolkit holds itself to.
"""

from __future__ import annotations

from pathlib import Path

from xhtml2pdf import pisa


class PdfGenerationError(Exception):
    """The HTML report could not be rendered to PDF."""


def generate_pdf(html_path: Path, output_path: Path) -> Path:
    html = html_path.read_text(encoding="utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "wb") as f:
        result = pisa.CreatePDF(html, dest=f, encoding="utf-8")

    if result.err:
        raise PdfGenerationError(
            f"Rendering {html_path.name} to PDF failed with {result.err} error(s)."
        )
    return output_path
