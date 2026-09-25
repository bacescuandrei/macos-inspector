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
    """Percentage with a recorded status, including Not Applicable but not Unknown."""
    categories = sorted({finding.category for finding in findings})
    return {
        category: round(100 * sum(
            finding.category == category and finding.status.lower() != "unknown"
            for finding in findings
        ) / sum(finding.category == category for finding in findings))
        for category in categories
    }


def calculate_scores(findings: list[Finding]) -> tuple[int, dict[str, int]]:
    """Rule outcome index adjusted by status availability, bounded from zero to 100."""
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
    applicable_categories = {
        finding.category for finding in findings if finding.status.lower() != "not applicable"
    }
    overall = (
        round(sum(scores[category] for category in applicable_categories) / len(applicable_categories))
        if applicable_categories else 100
    )
    return overall, scores
