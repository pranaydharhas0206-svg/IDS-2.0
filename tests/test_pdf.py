from pathlib import Path

import pytest

from toolkit.report.pdf import PdfGenerationError, generate_pdf


def test_generate_pdf_writes_nonempty_pdf(tmp_path):
    html_path = tmp_path / "report.html"
    html_path.write_text(
        "<html><body><h1>Test Report</h1><p>Some content.</p></body></html>",
        encoding="utf-8",
    )
    output_path = tmp_path / "out" / "report.pdf"

    result = generate_pdf(html_path, output_path)

    assert result == output_path
    assert output_path.exists()
    assert output_path.read_bytes().startswith(b"%PDF")


def test_generate_pdf_raises_on_unrenderable_html(tmp_path, monkeypatch):
    # Force pisa to report an error so the best-effort failure path in
    # service.generate_case_report has something real to catch.
    import toolkit.report.pdf as pdf_module

    class FakeResult:
        err = 1

    monkeypatch.setattr(pdf_module.pisa, "CreatePDF", lambda *a, **k: FakeResult())

    html_path = tmp_path / "report.html"
    html_path.write_text("<html></html>", encoding="utf-8")

    with pytest.raises(PdfGenerationError):
        generate_pdf(html_path, tmp_path / "out.pdf")
