import csv
import io
import json
from pathlib import Path

from macos_inspector.core.models import ScanResult
from .common import secure_write_text


def _cell(value: object) -> str:
    text = str(value)
    return f"'{text}" if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text


def write_csv(result: ScanResult, path: Path) -> None:
    fields = ("scan_id", "case_reference", "analyst", "target_application", "finding_id", "category", "title", "severity", "status", "description", "why_it_matters", "what_was_checked", "expected_result", "observed_result", "recommendation", "commands_used", "mitre_attack", "references", "evidence")
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    for finding in result.findings:
        data = finding.to_dict()
        row = {
            "scan_id": result.metadata.scan_id, "case_reference": result.metadata.case_reference, "analyst": result.metadata.analyst,
            "target_application": result.metadata.target_application,
            "finding_id": finding.finding_id, "category": finding.category, "title": finding.title,
            "severity": finding.severity.label(), "status": finding.status, "description": finding.description,
            "why_it_matters": finding.why_it_matters, "what_was_checked": finding.what_was_checked,
            "expected_result": finding.expected_result, "observed_result": finding.observed_result,
            "recommendation": finding.recommendation, "commands_used": "; ".join(finding.commands_used),
            "mitre_attack": "; ".join(finding.mitre_attack), "references": "; ".join(finding.references),
            "evidence": json.dumps(data["evidence"], ensure_ascii=False),
        }
        writer.writerow({key: _cell(value) for key, value in row.items()})
    secure_write_text(path, handle.getvalue())
