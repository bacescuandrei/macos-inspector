from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        normalized = value.strip().upper().replace("-", "_")
        if normalized == "INFO":
            normalized = "INFORMATIONAL"
        return cls[normalized]

    def label(self) -> str:
        return self.name.replace("_", " ").title()


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    value: Any
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass(frozen=True)
class Finding:
    finding_id: str
    category: str
    title: str
    severity: Severity
    status: str
    description: str
    why_it_matters: str
    what_was_checked: str
    expected_result: str
    observed_result: str
    recommendation: str
    evidence: tuple[Evidence, ...] = ()
    commands_used: tuple[str, ...] = ()
    mitre_attack: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.label()
        return result


@dataclass(frozen=True)
class ScanMetadata:
    tool_version: str
    scan_id: str
    started_at: str
    completed_at: str
    hostname: str
    platform: str
    username: str
    collectors: tuple[str, ...]
    collection_errors: tuple[str, ...] = ()
    case_reference: str = ""
    analyst: str = ""
    target_application: str = ""


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: str
    category: str
    finding_id: str
    kind: str
    source: str
    summary: str


@dataclass(frozen=True)
class ScanResult:
    metadata: ScanMetadata
    findings: tuple[Finding, ...]
    overall_score: int
    category_scores: dict[str, int]
    category_coverage: dict[str, int] = field(default_factory=dict)
    total_finding_count: int | None = None
    timeline: tuple[TimelineEvent, ...] = ()
    collector_coverage: dict[str, int] = field(default_factory=dict)
    assessed_finding_count: int | None = None
    category_assessed_counts: dict[str, int] = field(default_factory=dict)

    def assessed_count(self) -> int | None:
        if self.assessed_finding_count is not None:
            return self.assessed_finding_count
        if self.total_finding_count is not None and self.total_finding_count != len(self.findings):
            return None
        return sum(finding.status.lower() not in {"unknown", "not applicable"} for finding in self.findings)

    def category_assessed_count(self, category: str) -> int | None:
        if category in self.category_assessed_counts:
            return self.category_assessed_counts[category]
        if self.total_finding_count is not None and self.total_finding_count != len(self.findings):
            return None
        return sum(
            finding.category == category and finding.status.lower() not in {"unknown", "not applicable"}
            for finding in self.findings
        )

    def rule_index_label(self) -> str:
        return "N/A" if self.assessed_count() == 0 else f"{self.overall_score}/100"

    def category_rule_index_label(self, category: str) -> str:
        return "N/A" if self.category_assessed_count(category) == 0 else str(self.category_scores[category])

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "metadata": asdict(self.metadata),
            "summary": {
                "overall_score": self.overall_score,
                "assessed_finding_count": self.assessed_count(),
                "category_assessed_counts": {
                    category: self.category_assessed_count(category) for category in self.category_scores
                },
                "category_scores": self.category_scores,
                "category_coverage": self.category_coverage,
                "collector_coverage": self.collector_coverage,
                "finding_count": len(self.findings),
                "displayed_finding_count": len(self.findings),
                "total_finding_count": self.total_finding_count if self.total_finding_count is not None else len(self.findings),
                "timeline_event_count": len(self.timeline),
                "severity_counts": {
                    severity.label(): sum(f.severity == severity for f in self.findings)
                    for severity in Severity
                },
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "timeline": [asdict(event) for event in self.timeline],
        }


def summary_with_assessment_counts(payload: dict[str, Any]) -> dict[str, Any]:
    """Infer missing index availability only when a report contains every finding."""
    summary = dict(payload.get("summary") or {})
    findings = payload.get("findings")
    if not isinstance(findings, list) or summary.get("total_finding_count") != len(findings):
        return summary
    if not all(isinstance(finding, dict) for finding in findings):
        return summary
    assessed = [
        finding for finding in findings
        if str(finding.get("status", "")).lower() not in {"", "unknown", "not applicable"}
    ]
    if summary.get("assessed_finding_count") is None:
        summary["assessed_finding_count"] = len(assessed)
    if not isinstance(summary.get("category_assessed_counts"), dict):
        summary["category_assessed_counts"] = {
            category: sum(finding.get("category") == category for finding in assessed)
            for category in summary.get("category_scores", {})
        }
    return summary
