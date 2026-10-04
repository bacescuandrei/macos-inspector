from __future__ import annotations

from html import escape


RULE_CONTEXT_CSS = """
.rule-context{min-width:0;margin:18px 0;padding:16px;border:1px solid #637083;border-radius:12px;overflow-wrap:anywhere}.rule-context article{min-width:0;margin:12px 0;padding:12px;border:1px solid #637083;border-radius:8px}.rule-context h3{font-size:15px;margin:0 0 8px}.rule-context p,.rule-context small{display:block;margin:8px 0}.rule-context code{white-space:normal;overflow-wrap:anywhere}.rule-context ul{padding-left:20px}.rule-context summary{cursor:pointer}
"""


def render_rule_context(summary: dict) -> str:
    if not summary.get("available"):
        return ""
    rows = []
    for row in summary["rows"]:
        count = "Not recorded" if row["file_count"] is None else str(row["file_count"])
        fingerprint = escape(row["fingerprint"] or "Not recorded with a supported schema")
        sources = "".join(
            f"<li>{escape(item['name'])} | version {escape(item['version'])} | updated {escape(item['updated_at'])} | declared source host: {escape(item['source_host'] or 'Not recorded as a web source')}</li>"
            for item in row["sources"]
        )
        if row["collector"] == "ioc":
            sources = f"<ul>{sources}</ul>" if sources else "<p>Pack provenance metadata is unavailable in the visible findings.</p>"
            if row["source_count"] > len(row["sources"]):
                sources += f"<p>{row['source_count'] - len(row['sources'])} additional provenance records are retained in the original report.</p>"
        limitations = "".join(f"<li>{escape(item)}</li>" for item in row["limitations"])
        rows.append(f"<article><h3>{escape(row['title'])}</h3><strong>{escape(row['label'])}</strong><p>{escape(row['result_note'])}</p><details><summary>Recorded rule details and provenance</summary><p>Fingerprinted files: {count}</p><p>SHA-256 context fingerprint: <code>{fingerprint}</code></p>{sources}{f'<ul>{limitations}</ul>' if limitations else ''}</details></article>")
    return f"<section class=\"rule-context\"><h2>Local rules and provenance</h2><p>{escape(summary['note'])}</p>{''.join(rows)}<small>{escape(summary['source_note'])}</small></section>"
