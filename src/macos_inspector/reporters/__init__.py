from __future__ import annotations

from .csv_reporter import write_csv
from .html_reporter import write_html
from .json_reporter import write_json
from .markdown_reporter import write_markdown
from .sarif_reporter import write_sarif
from .manifest_reporter import write_manifest
from .pdf_reporter import write_pdf
from .bundle_reporter import write_bundle
from .encrypted_bundle import encryption_available, write_encrypted_bundle

REPORTERS = {"json": write_json, "markdown": write_markdown, "csv": write_csv, "html": write_html, "sarif": write_sarif, "manifest": write_manifest, "pdf": write_pdf, "bundle": write_bundle, "encrypted-bundle": write_encrypted_bundle}


def report_format_capabilities() -> dict[str, dict[str, object]]:
    capabilities = {name: {"available": True, "reason": ""} for name in REPORTERS}
    if not encryption_available():
        capabilities["encrypted-bundle"] = {"available": False, "reason": "Encrypted case bundles require the optional signing dependency."}
    return capabilities


def unavailable_report_formats(formats: list[str]) -> dict[str, str]:
    capabilities = report_format_capabilities()
    return {
        name: str(capabilities[name]["reason"])
        for name in formats
        if name in capabilities and not capabilities[name]["available"]
    }


def require_report_formats(formats: list[str]) -> None:
    unavailable = unavailable_report_formats(formats)
    if unavailable:
        raise ValueError("; ".join(unavailable.values()))
