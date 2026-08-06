from __future__ import annotations

import html
import json
from pathlib import Path

from .common import secure_write_text


CSS = """
:root{--bg:#f5f7fb;--panel:#fff;--text:#18212f;--muted:#637083;--line:#dce2ea;--accent:#2563eb;--good:#16865b;--warn:#a45d00}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#8b949e;--line:#30363d;--accent:#58a6ff;--good:#50d2a0;--warn:#f3bd64}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}main{max-width:1050px;margin:auto;padding:32px 20px}h1{margin-bottom:4px}.meta{color:var(--muted)}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:22px 0}.summary div,.change,.scope,.categories{padding:14px;border:1px solid var(--line);border-radius:10px;background:var(--panel)}.summary span,.change small,.change code{display:block;color:var(--muted);font-size:11px}.summary strong{font-size:24px}.scope{border-color:var(--warn);color:var(--warn)}.categories table{width:100%;border-collapse:collapse}.categories td,.categories th{padding:7px;text-align:left;border-bottom:1px solid var(--line)}.change{display:grid;grid-template-columns:85px 1fr;gap:10px;margin:8px 0}.kind{align-self:start;padding:3px 7px;border-radius:999px;text-align:center;font-size:10px;font-weight:700;text-transform:uppercase}.new{color:var(--warn)}.resolved{color:var(--good)}.changed{color:var(--accent)}@media(max-width:650px){.summary{grid-template-columns:repeat(2,1fr)}.change{grid-template-columns:1fr}}
"""


def write_comparison_reports(comparison: dict, output: Path) -> dict[str, Path]:
    baseline = str(comparison["baseline_scan_id"])
    current = str(comparison["current_scan_id"])
    stem = f"macos-inspector-comparison-{baseline}-{current}"
    json_path, html_path = output / f"{stem}.json", output / f"{stem}.html"
    secure_write_text(json_path, json.dumps(comparison, indent=2, ensure_ascii=False) + "\n")

    counts = comparison["counts"]
    delta = comparison["score_delta"]
    delta_label = f"+{delta}" if delta > 0 else str(delta)
    scope = comparison.get("scope", {})
    scope_html = ""
    if scope.get("changed"):
        added = ", ".join(scope.get("added_collectors", [])) or "none"
        removed = ", ".join(scope.get("removed_collectors", [])) or "none"
        scope_html = f'<section class="scope"><strong>Collection scope changed.</strong> Added: {html.escape(added)}. Removed: {html.escape(removed)}. Counts may reflect collector coverage rather than a host-state change.</section>'
    category_rows = "".join(
        f"<tr><td>{html.escape(category)}</td><td>{'+' if value > 0 else ''}{value}</td></tr>"
        for category, value in comparison.get("category_deltas", {}).items()
    ) or '<tr><td colspan="2">No category scores</td></tr>'
    rows = []
    for kind in ("new", "resolved"):
        for finding in comparison.get(kind, []):
            rows.append((kind, finding.get("finding_id"), finding.get("title"), f'{finding.get("severity", "")} · {finding.get("status", "")}'))
    for finding in comparison.get("changed", []):
        detail = " · ".join(f"{field}: {values.get('before')} → {values.get('after')}" for field, values in finding.get("changes", {}).items())
        rows.append(("changed", finding.get("finding_id"), finding.get("title"), detail))
    changes_html = "".join(
        f'<article class="change"><span class="kind {kind}">{kind}</span><div><strong>{html.escape(str(title or ""))}</strong><code>{html.escape(str(finding_id or ""))}</code><small>{html.escape(detail)}</small></div></article>'
        for kind, finding_id, title, detail in rows
    ) or '<p class="meta">No finding-level changes were detected.</p>'
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>macOS Inspector comparison</title><style>{CSS}</style></head><body><main><h1>Scan comparison</h1><p class="meta">Baseline {html.escape(baseline)} → current {html.escape(current)}</p><section class="summary"><div><span>Score change</span><strong>{delta_label}</strong></div><div><span>New</span><strong>{counts['new']}</strong></div><div><span>Resolved</span><strong>{counts['resolved']}</strong></div><div><span>Changed</span><strong>{counts['changed']}</strong></div></section>{scope_html}<section class="categories"><h2>Category score changes</h2><table><thead><tr><th>Category</th><th>Delta</th></tr></thead><tbody>{category_rows}</tbody></table></section><h2>Finding changes</h2>{changes_html}</main></body></html>'''
    secure_write_text(html_path, document)
    return {"comparison_json": json_path, "comparison_html": html_path}
