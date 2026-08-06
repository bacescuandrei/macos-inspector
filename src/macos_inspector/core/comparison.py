from __future__ import annotations

from typing import Any


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

    baseline_summary, current_summary = baseline.get("summary", {}), current.get("summary", {})
    baseline_collectors = set(baseline.get("metadata", {}).get("collectors", []))
    current_collectors = set(current.get("metadata", {}).get("collectors", []))
    baseline_score = int(baseline_summary.get("overall_score", 0))
    current_score = int(current_summary.get("overall_score", 0))
    categories = set(baseline_summary.get("category_scores", {})) | set(current_summary.get("category_scores", {}))
    category_deltas = {
        category: int(current_summary.get("category_scores", {}).get(category, 0))
        - int(baseline_summary.get("category_scores", {}).get(category, 0))
        for category in sorted(categories)
    }
    return {
        "baseline_scan_id": baseline.get("metadata", {}).get("scan_id"),
        "current_scan_id": current.get("metadata", {}).get("scan_id"),
        "baseline_score": baseline_score,
        "current_score": current_score,
        "score_delta": current_score - baseline_score,
        "scope": {
            "changed": baseline_collectors != current_collectors,
            "added_collectors": sorted(current_collectors - baseline_collectors),
            "removed_collectors": sorted(baseline_collectors - current_collectors),
        },
        "counts": {
            "new": len(new), "resolved": len(resolved), "changed": len(changed),
            "unchanged": len(baseline_ids & current_ids) - len(changed),
        },
        "category_deltas": category_deltas,
        "new": new,
        "resolved": resolved,
        "changed": changed,
    }
