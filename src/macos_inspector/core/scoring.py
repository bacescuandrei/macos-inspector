from __future__ import annotations

from collections import defaultdict

from .models import Finding, Severity

PENALTIES = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 18,
    Severity.MEDIUM: 9,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 0,
}


def calculate_coverage(findings: list[Finding]) -> dict[str, int]:
    """Percentage of findings that produced a definitive or observable result."""
    categories = sorted({finding.category for finding in findings})
    return {
        category: round(100 * sum(
            finding.category == category and finding.status.lower() != "unknown"
            for finding in findings
        ) / sum(finding.category == category for finding in findings))
        for category in categories
    }


def calculate_scores(findings: list[Finding]) -> tuple[int, dict[str, int]]:
    """Risk score adjusted by collection coverage, bounded from zero to 100."""
    penalties: dict[str, int] = defaultdict(int)
    for finding in findings:
        if finding.status.lower() not in {"pass", "not applicable"}:
            penalties[finding.category] += PENALTIES[finding.severity]
    categories = sorted({finding.category for finding in findings})
    coverage = calculate_coverage(findings)
    scores = {
        category: round(max(0, 100 - penalties[category]) * coverage[category] / 100)
        for category in categories
    }
    overall = round(sum(scores.values()) / len(scores)) if scores else 100
    return overall, scores
