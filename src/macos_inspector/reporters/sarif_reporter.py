from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from macos_inspector import __version__
from macos_inspector.core.models import Finding, ScanResult, Severity
from .common import secure_write_text


ACTIONABLE_STATUSES = {"fail", "review", "match", "unknown"}


def _level(finding: Finding) -> str:
    if finding.severity >= Severity.HIGH:
        return "error"
    if finding.severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _uri(source: str) -> str | None:
    try:
        path = Path(source)
        if path.is_absolute():
            return path.as_uri()
    except (OSError, ValueError):
        pass
    if source.startswith(("http://", "https://")):
        return source
    return None


def _rule(finding: Finding) -> dict:
    return {
        "id": finding.finding_id,
        "name": finding.finding_id.replace("-", "_"),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "help": {"text": finding.recommendation, "markdown": finding.recommendation},
        "properties": {
            "category": finding.category,
            "severity": finding.severity.label(),
            "status": finding.status,
            "mitreAttack": list(finding.mitre_attack),
            "references": list(finding.references),
        },
    }


def _result(finding: Finding, rule_index: int) -> dict:
    result = {
        "ruleId": finding.finding_id,
        "ruleIndex": rule_index,
        "level": _level(finding),
        "message": {"text": f"{finding.observed_result} Recommendation: {finding.recommendation}"},
        "properties": {
            "category": finding.category,
            "severity": finding.severity.label(),
            "status": finding.status,
            "commandsUsed": list(finding.commands_used),
            "evidence": [item.__dict__ for item in finding.evidence],
        },
    }
    locations = []
    for evidence in finding.evidence:
        uri = _uri(evidence.source)
        if uri:
            locations.append({"physicalLocation": {"artifactLocation": {"uri": quote(uri, safe=":/%")}}})
    if locations:
        result["locations"] = locations[:10]
    return result


def write_sarif(result: ScanResult, path: Path) -> None:
    actionable = [finding for finding in result.findings if finding.status.lower() in ACTIONABLE_STATUSES]
    rules = [_rule(finding) for finding in actionable]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "macOS Inspector",
                "informationUri": "https://support.apple.com/guide/security/welcome/web",
                "version": __version__,
                "rules": rules,
            }},
            "invocations": [{
                "executionSuccessful": not bool(result.metadata.collection_errors),
                "startTimeUtc": result.metadata.started_at,
                "endTimeUtc": result.metadata.completed_at,
                "properties": {
                    "scanId": result.metadata.scan_id,
                    "caseReference": result.metadata.case_reference,
                    "analyst": result.metadata.analyst,
                    "collectors": list(result.metadata.collectors),
                    "targetApplication": result.metadata.target_application,
                    "collectionErrors": list(result.metadata.collection_errors),
                    "overallScore": None if result.assessed_count() == 0 else result.overall_score,
                    "assessedFindingCount": result.assessed_count(),
                },
            }],
            "results": [_result(finding, index) for index, finding in enumerate(actionable)],
            "properties": {"timelineEventCount": len(result.timeline)},
        }],
    }
    secure_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
