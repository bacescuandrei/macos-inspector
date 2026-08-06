from __future__ import annotations

import importlib.util

from .csv_reporter import write_csv
from .html_reporter import write_html
from .json_reporter import write_json
from .markdown_reporter import write_markdown
from .sarif_reporter import write_sarif
from .manifest_reporter import write_manifest
from .pdf_reporter import write_pdf
from .bundle_reporter import write_bundle

REPORTERS = {"json": write_json, "markdown": write_markdown, "csv": write_csv, "html": write_html, "sarif": write_sarif, "manifest": write_manifest, "pdf": write_pdf, "bundle": write_bundle}


OPTIONAL_FORMAT_DEPENDENCIES = {
    "pdf": (
        "reportlab",
        "PDF export requires the optional dependency: pip install 'macos-inspector[pdf]'",
    ),
}


def report_format_capabilities() -> dict[str, dict[str, object]]:
    capabilities = {}
    for name in REPORTERS:
        requirement = OPTIONAL_FORMAT_DEPENDENCIES.get(name)
        available = requirement is None or importlib.util.find_spec(requirement[0]) is not None
        capabilities[name] = {
            "available": available,
            "reason": "" if available or requirement is None else requirement[1],
        }
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
