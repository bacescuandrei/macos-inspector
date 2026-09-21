import html
import json
from pathlib import Path

from macos_inspector.core.models import ScanResult
from .common import secure_write_text


def _safe(value: str) -> str:
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\n", " ")


def write_markdown(result: ScanResult, path: Path) -> None:
    lines = [
        "# macOS Inspector report", "", f"**Scan ID:** `{result.metadata.scan_id}`  ",
        f"**Host:** `{result.metadata.hostname}`  ", f"**Completed:** {result.metadata.completed_at}  ",
        f"**Case reference:** {_safe(result.metadata.case_reference) or 'Not provided'}  ",
        f"**Analyst:** {_safe(result.metadata.analyst) or 'Not provided'}  ",
        f"**Rule outcome index:** **{result.overall_score}/100**  ",
        "This index summarizes documented rule outcomes. It is not the probability that this Mac is safe or compromised.",
        "", "## Category rule outcome indexes", "",
        "| Category | Rule outcome index | Coverage |", "|---|---:|---:|",
    ]
    if result.metadata.target_application:
        lines.insert(7, f"**Target application:** {_safe(result.metadata.target_application)}  ")
    lines.extend(f"| {_safe(category)} | {score} | {result.category_coverage.get(category, 100)}% |" for category, score in result.category_scores.items())
    if result.metadata.collection_errors:
        lines.extend(["", "## Collection errors", ""])
        lines.extend(f"- {_safe(error)}" for error in result.metadata.collection_errors)
    if result.timeline:
        lines.extend(["", "## Timeline", "", "| Timestamp (UTC) | Category | Finding | Event | Source |", "|---|---|---|---|---|"])
        lines.extend(
            f"| {_safe(event.timestamp)} | {_safe(event.category)} | {_safe(event.finding_id)} | {_safe(event.summary)} | {_safe(event.source)} |"
            for event in result.timeline
        )
    lines.extend(["", "## Findings", ""])
    for finding in result.findings:
        lines.extend([
            f"### {_safe(finding.finding_id)}: {_safe(finding.title)}", "",
            f"- **Severity:** {_safe(finding.severity.label())}", f"- **Status:** {_safe(finding.status)}", f"- **Category:** {_safe(finding.category)}", "",
            _safe(finding.description), "", f"**Why it matters:** {_safe(finding.why_it_matters)}", "",
            f"**Checked:** {_safe(finding.what_was_checked)}", "", f"**Expected:** {_safe(finding.expected_result)}", "",
            f"**Observed:** {_safe(finding.observed_result)}", "", f"**Recommendation:** {_safe(finding.recommendation)}", "",
        ])
        if finding.mitre_attack:
            lines.append(f"**MITRE ATT&CK:** {_safe(', '.join(finding.mitre_attack))}\n")
        if finding.commands_used:
            lines.extend(["**Commands used:**", "", *[f"- `{_safe(command)}`" for command in finding.commands_used], ""])
        if finding.references:
            lines.extend(["**References:**", "", *[f"- {_safe(reference)}" for reference in finding.references], ""])
        if finding.evidence:
            evidence = json.dumps([item.__dict__ for item in finding.evidence], indent=2, ensure_ascii=False)
            lines.extend(["<details><summary>Evidence</summary>", "", "```json", evidence.replace("```", "` ` `"), "```", "", "</details>", ""])
    secure_write_text(path, "\n".join(lines) + "\n")
