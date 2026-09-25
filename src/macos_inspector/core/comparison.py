from __future__ import annotations

from typing import Any

from .models import summary_with_assessment_counts


TRACKED_FIELDS = ("status", "severity", "observed_result")


def compare_scan_payloads(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare normalized JSON report payloads without mutating either report."""
    baseline_findings = {item["finding_id"]: item for item in baseline.get("findings", [])}
    current_findings = {item["finding_id"]: item for item in current.get("findings", [])}
    baseline_ids, current_ids = set(baseline_findings), set(current_findings)

    new = [current_findings[item] for item in sorted(current_ids - baseline_ids)]
    resolved = [baseline_findings[item] for item in sorted(baseline_ids - current_ids)]
    changed = []
    for finding_id in sorted(baseline_ids & current_ids):
        before, after = baseline_findings[finding_id], current_findings[finding_id]
        changes = {
            field: {"before": before.get(field), "after": after.get(field)}
            for field in TRACKED_FIELDS if before.get(field) != after.get(field)
        }
        if changes:
            changed.append({"finding_id": finding_id, "title": after.get("title") or before.get("title"), "changes": changes})

    baseline_summary, current_summary = summary_with_assessment_counts(baseline), summary_with_assessment_counts(current)
    baseline_collectors = set(baseline.get("metadata", {}).get("collectors", []))
    current_collectors = set(current.get("metadata", {}).get("collectors", []))
    baseline_target = str(baseline.get("metadata", {}).get("target_application", ""))
    current_target = str(current.get("metadata", {}).get("target_application", ""))
    baseline_score = int(baseline_summary.get("overall_score", 0))
    current_score = int(current_summary.get("overall_score", 0))
    baseline_categories = baseline_summary.get("category_scores", {})
    current_categories = current_summary.get("category_scores", {})
    categories = set(baseline_categories) | set(current_categories)
    category_deltas = {
        category: (
            None if category not in baseline_categories or category not in current_categories
            or baseline_summary.get("category_assessed_counts", {}).get(category) == 0
            or current_summary.get("category_assessed_counts", {}).get(category) == 0
            else int(current_categories[category]) - int(baseline_categories[category])
        ) for category in sorted(categories)
    }
    score_comparable = (
        baseline_summary.get("assessed_finding_count") != 0
        and current_summary.get("assessed_finding_count") != 0
    )
    scope = {
        "changed": baseline_collectors != current_collectors or baseline_target != current_target,
        "added_collectors": sorted(current_collectors - baseline_collectors),
        "removed_collectors": sorted(baseline_collectors - current_collectors),
    }
    if baseline_target or current_target:
        scope["baseline_target_application"] = baseline_target or None
        scope["current_target_application"] = current_target or None
    return {
        "baseline_scan_id": baseline.get("metadata", {}).get("scan_id"),
        "current_scan_id": current.get("metadata", {}).get("scan_id"),
        "baseline_score": baseline_score,
        "current_score": current_score,
        "score_delta": current_score - baseline_score if score_comparable else None,
        "scope": scope,
        "counts": {
            "new": len(new), "resolved": len(resolved), "changed": len(changed),
            "unchanged": len(baseline_ids & current_ids) - len(changed),
        },
        "category_deltas": category_deltas,
        "new": new,
        "resolved": resolved,
        "changed": changed,
    }
