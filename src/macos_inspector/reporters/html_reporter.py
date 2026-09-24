from __future__ import annotations

import html
import json
from pathlib import Path

from macos_inspector.core.models import ScanResult
from .common import secure_write_text


CSS = """
:root{--bg:#f5f7fb;--panel:#fff;--text:#18212f;--muted:#637083;--line:#dce2ea;--accent:#2563eb}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#8b949e;--line:#30363d;--accent:#58a6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:32px 20px}.hero{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center}.score{font-size:46px;font-weight:800;color:var(--accent)}.score small,.muted{font-size:13px;color:var(--muted)}.meta{color:var(--muted)}.scores{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:24px 0}.scores div,.finding,.errors{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}.scores div{display:flex;justify-content:space-between}.errors{border-color:#dc2626}.toolbar{position:sticky;top:0;z-index:2;background:var(--bg);display:flex;gap:10px;padding:12px 0}input,select,button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px}input{flex:1}.finding{margin:12px 0}.finding header{cursor:pointer}.finding h2{display:inline;font-size:18px;margin:0 10px}.finding .body{display:none}.finding.open .body{display:block}.badge,.status{display:inline-block;border-radius:999px;padding:3px 8px;font-size:12px;font-weight:700;margin-right:6px}.critical{background:#7f1d1d;color:#fff}.high{background:#dc2626;color:#fff}.medium{background:#f59e0b;color:#111}.low{background:#fde047;color:#111}.informational{background:#dbeafe;color:#1e3a8a}.status{border:1px solid var(--line)}dt{font-weight:700;margin-top:12px}dd{margin-left:0}pre{overflow:auto;background:var(--bg);padding:12px;border-radius:8px}code{color:var(--muted)}a{color:var(--accent)}
.timeline{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:18px 0}.timeline table{width:100%;border-collapse:collapse;font-size:12px}.timeline th,.timeline td{text-align:left;vertical-align:top;padding:7px;border-bottom:1px solid var(--line)}.timeline-wrap{overflow:auto;max-height:420px}
.scope-note{background:var(--panel);border:1px solid #d79a31;border-radius:12px;padding:16px;margin:18px 0;overflow-wrap:anywhere}.scope-note p{margin:6px 0}.scope-note ul{margin:8px 0 0;padding-left:20px}
@media(max-width:650px){.hero{grid-template-columns:1fr}.toolbar{flex-wrap:wrap}input{flex-basis:100%}}
"""


SCRIPT = """
const cards=[...document.querySelectorAll('.finding')],q=document.querySelector('#q'),sev=document.querySelector('#severity'),cat=document.querySelector('#category'),count=document.querySelector('#count');
function filter(){let n=0;cards.forEach(c=>{const show=(!q.value||c.dataset.search.includes(q.value.toLowerCase()))&&(!sev.value||c.dataset.severity===sev.value)&&(!cat.value||c.dataset.category===cat.value);c.hidden=!show;if(show)n++});count.textContent=`${n} of ${cards.length} findings`}
[q,sev,cat].forEach(e=>e.addEventListener('input',filter));cards.forEach(c=>c.querySelector('header').addEventListener('click',()=>c.classList.toggle('open')));document.querySelector('#theme').onclick=()=>document.documentElement.style.colorScheme=document.documentElement.style.colorScheme==='dark'?'light':'dark';filter();
"""


def write_html(result: ScanResult, path: Path) -> None:
    cards = []
    for finding in result.findings:
        evidence = html.escape(json.dumps([item.__dict__ for item in finding.evidence], indent=2, ensure_ascii=False))
        haystack = html.escape(f"{finding.finding_id} {finding.category} {finding.title} {finding.description}".lower(), quote=True)
        commands = "".join(f"<li><code>{html.escape(command)}</code></li>" for command in finding.commands_used) or "<li>None</li>"
        attacks = ", ".join(html.escape(item) for item in finding.mitre_attack) or "None"
        references = "".join(
            f'<li><a href="{html.escape(reference, quote=True)}" rel="noreferrer">{html.escape(reference)}</a></li>'
            for reference in finding.references
        ) or "<li>None</li>"
        cards.append(f'''<article class="finding" data-severity="{finding.severity.label()}" data-category="{html.escape(finding.category)}" data-search="{haystack}">
<header><span class="badge {finding.severity.name.lower()}">{finding.severity.label()}</span><span class="status">{html.escape(finding.status)}</span><h2>{html.escape(finding.title)}</h2><code>{html.escape(finding.finding_id)}</code></header>
<div class="body"><p>{html.escape(finding.description)}</p><dl><dt>Why it matters</dt><dd>{html.escape(finding.why_it_matters)}</dd><dt>Checked</dt><dd>{html.escape(finding.what_was_checked)}</dd><dt>Expected</dt><dd>{html.escape(finding.expected_result)}</dd><dt>Observed</dt><dd>{html.escape(finding.observed_result)}</dd><dt>Recommendation</dt><dd>{html.escape(finding.recommendation)}</dd><dt>MITRE ATT&amp;CK</dt><dd>{attacks}</dd><dt>Commands used</dt><dd><ul>{commands}</ul></dd><dt>References</dt><dd><ul>{references}</ul></dd></dl><details><summary>Evidence</summary><pre>{evidence}</pre></details></div></article>''')
    category_options = "".join(f'<option>{html.escape(category)}</option>' for category in result.category_scores)
    not_assessed = [finding for finding in result.findings if finding.status.lower() == "not applicable"]
    only_not_assessed = (
        bool(result.findings) and len(not_assessed) == len(result.findings)
        and (result.total_finding_count is None or result.total_finding_count == len(result.findings))
    )
    overall_display = "N/A" if only_not_assessed else str(result.overall_score)
    category_findings = {
        category: [finding for finding in result.findings if finding.category == category]
        for category in result.category_scores
    }
    score_rows = []
    for category, score in result.category_scores.items():
        findings = category_findings[category]
        not_assessed_only = bool(findings) and all(finding.status.lower() == "not applicable" for finding in findings)
        label = "Not assessed" if not_assessed_only else f"{result.category_coverage.get(category, 100)}% status availability"
        displayed_score = "N/A" if not_assessed_only else str(score)
        score_rows.append(
            f'<div><span>{html.escape(category)} <small class="muted">{label}</small></span><strong>{displayed_score}</strong></div>'
        )
    scores = "".join(score_rows)
    scope_note = ""
    if not_assessed:
        items = "".join(f"<li>{html.escape(finding.title)}</li>" for finding in not_assessed[:20])
        more = f"<li>And {len(not_assessed) - 20} more.</li>" if len(not_assessed) > 20 else ""
        scope_note = (
            f'<section class="scope-note"><strong>{len(not_assessed)} check(s) did not assess a target</strong>'
            '<p>Not Applicable is not a passing security result. Open the matching findings to see why the check did not apply and what to configure or verify next.</p>'
            f'<ul>{items}{more}</ul></section>'
        )
    errors = ""
    if result.metadata.collection_errors:
        items = "".join(f"<li>{html.escape(error)}</li>" for error in result.metadata.collection_errors)
        errors = f'<section class="errors"><strong>Collection errors</strong><ul>{items}</ul></section>'
    timeline = ""
    if result.timeline:
        rows = "".join(
            f"<tr><td>{html.escape(event.timestamp)}</td><td>{html.escape(event.category)}</td><td><code>{html.escape(event.finding_id)}</code></td><td>{html.escape(event.summary)}</td><td>{html.escape(event.source)}</td></tr>"
            for event in result.timeline
        )
        timeline = f'<details class="timeline"><summary><strong>Timeline</strong> | {len(result.timeline)} events</summary><div class="timeline-wrap"><table><thead><tr><th>Timestamp (UTC)</th><th>Category</th><th>Finding</th><th>Event</th><th>Source</th></tr></thead><tbody>{rows}</tbody></table></div></details>'
    case_line = " | ".join(filter(None, [result.metadata.case_reference, result.metadata.analyst]))
    case_html = f'<div class="meta">{html.escape(case_line)}</div>' if case_line else ""
    scope_html = (
        f'<div class="meta">Target application: {html.escape(result.metadata.target_application)}</div>'
        if result.metadata.target_application else ""
    )
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>macOS Inspector report</title><style>{CSS}</style></head><body><main>
<section class="hero"><div><h1>macOS Inspector</h1>{case_html}{scope_html}<div class="meta">{html.escape(result.metadata.hostname)} | {html.escape(result.metadata.completed_at)} | scan {html.escape(result.metadata.scan_id)}</div><p class="muted">The rule outcome index summarizes documented rule results. It is not the probability that this Mac is safe or compromised.</p></div><div class="score">{overall_display}<small>{'No assessed findings' if only_not_assessed else '/100 rule outcome index'}</small></div></section>
{errors}{scope_note}<section class="scores">{scores}</section>{timeline}<section class="toolbar"><input id="q" aria-label="Search" placeholder="Search findings"><select id="severity"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Informational</option></select><select id="category"><option value="">All categories</option>{category_options}</select><button id="theme">Theme</button></section>
<p id="count"></p><section id="findings">{''.join(cards)}</section></main><script>{SCRIPT}</script></body></html>'''
    secure_write_text(path, document)
