from __future__ import annotations

from typing import Any


def presence_comparison_limit(report: dict[str, Any], collectors: tuple[str, ...] | None = None) -> str:
    """Require complete, unfiltered collection before interpreting an absent record."""
    metadata = report.get("metadata", {})
    summary = report.get("summary", {})
    minimum = metadata.get("minimum_severity")
    if minimum is not None and minimum != "Informational":
        return "The report uses a severity filter or has an unsupported recorded filter."
    total = summary.get("total_finding_count")
    findings = report.get("findings")
    if (
        not isinstance(total, int) or isinstance(total, bool)
        or not isinstance(findings, list) or total != len(findings)
        or any(not isinstance(item, dict) for item in findings)
    ):
        return "The report does not establish that all collected finding records are included."
    selected = metadata.get("collectors", [])
    if not isinstance(selected, (list, tuple)) or not selected or any(not isinstance(item, str) for item in selected):
        return "The recorded collection scope is unavailable."
    required = collectors if collectors is not None else tuple(selected)
    if any(collector not in selected for collector in required):
        return "The required collection section was not selected."
    errors = metadata.get("collection_errors", [])
    if not isinstance(errors, (list, tuple)):
        return "Collection error metadata is unavailable."
    if any(not isinstance(error, str) or not any(error.startswith(f"{collector}:") for collector in selected) for error in errors):
        return "A collection error cannot be attributed to a recorded section."
    if any(any(str(error).startswith(f"{collector}:") for collector in required) for error in errors):
        return "A required collection section reported an error."
    if collectors is None and errors:
        return "The scan reported collection errors."
    coverage = summary.get("collector_coverage", {})
    if not isinstance(coverage, dict) or any(
        isinstance(coverage.get(collector), bool)
        or not isinstance(coverage.get(collector), (int, float))
        or coverage.get(collector) != 100
        for collector in required
    ):
        return "Required collection completion is missing or incomplete."
    return ""
