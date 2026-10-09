"""Standalone escaped HTML for static PDF inspection results."""
from __future__ import annotations

from html import escape


def render_pdf_inspection(report: dict) -> str:
    def text(value):
        return escape(str(value))

    def table(rows, fields):
        if not rows:
            return "<p>No records in the inspected scope. Check the limitations below.</p>"
        head = "".join(f"<th>{text(label)}</th>" for _, label in fields)
        body = "".join("<tr>" + "".join(f"<td>{text(row.get(key, ''))}</td>" for key, _ in fields) + "</tr>" for row in rows)
        return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

    file, assessment, structure = report["file"], report["assessment"], report["structure"]
    actions = table(report["actions"], (("type", "Action"), ("trigger", "Declared trigger"), ("target", "Declared target"), ("context", "Object context"), ("note", "Interpretation")))
    destinations = table(report["destinations"], (("value", "Destination"), ("kind", "Recorded as"), ("context", "Object context")))
    attachments = table(report["attachments"], (("filename", "Filename"), ("context", "Object context"), ("note", "Limit")))
    scripts = "".join(f'<details><summary>JavaScript | {text(item["context"])} | {item["bytes"]} bytes</summary><p>SHA-256: <code>{text(item["sha256"])}</code></p><p>{text("; ".join(item["indicators"]) or "No supported heuristic indicators found; this is not proof of harmless code.")}</p><pre>{text(item["preview"])}</pre><p>{"Excerpt truncated." if item["preview_truncated"] else "Recorded script text."} Code was not executed.</p></details>' for item in report["javascript"]) or "<p>No readable JavaScript recorded. Consult name counts and limitations.</p>"
    limitations = "".join(f"<li>{text(item)}</li>" for item in report["limitations"]) or "<li>No additional collection limits recorded within the supported static scope.</li>"
    counts = table([{"name": "/" + key, "count": value} for key, value in report["name_counts"].items()], (("name", "Parsed name"), ("count", "Occurrences")))
    metadata = table([{"name": key, "value": value} for key, value in report["metadata"].items()], (("name", "Field"), ("value", "Declared value (unverified)")))
    answers = table(report.get("answers", []), (("question", "Question"), ("answer", "Recorded answer"), ("note", "Interpretation limits")))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>PDF Inspector | {text(file["name"])}</title><style>
    :root{{color-scheme:dark light}}*{{box-sizing:border-box}}body{{margin:0;background:#101827;color:#e7edf8;font:16px/1.6 system-ui,sans-serif}}main{{max-width:1100px;margin:auto;padding:24px;min-width:0}}section,header{{padding:20px;background:#182238;border:1px solid #34435c;border-radius:14px;margin-bottom:20px;min-width:0}}h1,h2,p,td,th,summary,code{{overflow-wrap:anywhere}}h1{{font-size:28px}}h2{{font-size:20px}}.label{{color:#ffcd73;font-weight:700}}table{{border-collapse:collapse;width:100%;table-layout:fixed}}td,th{{text-align:left;vertical-align:top;border-bottom:1px solid #34435c;padding:8px;font-size:13px}}.table-wrap{{overflow:auto}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101827;padding:12px;border-radius:8px}}details{{margin:12px 0}}summary{{cursor:pointer}}small{{color:#b5c4dd}}@media(max-width:600px){{main{{padding:12px}}section,header{{padding:14px}}table{{min-width:500px}}}}
    </style></head><body><main><header><p>macOS Inspector {text(report["tool_version"])} | PDF Inspector</p><h1>{text(file["name"])}</h1><p class="label">{text(assessment["label"])}</p><p>{text(assessment["explanation"])}</p><p>{text(assessment["next_step"])}</p><p>{text(report["boundary"])}</p><small>Analyzed {text(report["analyzed_at"])} | Malware verdict: Not determined</small></header>
    <section><h2>Quick questions</h2>{answers}</section><section><h2>Identity and structure</h2><p>{file["bytes"]} bytes | {text(structure["header"])} at byte {structure["header_offset"]} | {structure["object_count"]} observed objects ({structure["compressed_object_count"]} compressed)</p><p>SHA-256: <code>{text(file["sha256"])}</code></p><p>Final EOF marker: {text(structure["final_eof_marker"])} | Encryption indicated: {text(structure["encrypted_or_indicated"])}</p><p>{text(structure["xref_validation"])}</p></section>
    <section><h2>Actions and declared triggers</h2>{actions}</section><section><h2>JavaScript</h2>{scripts}</section><section><h2>Destinations, not observed requests</h2><p>These values are plain text, not clickable links. No destination was contacted.</p>{destinations}</section><section><h2>Attachments</h2>{attachments}</section><section><h2>Parsed structural names</h2><p>Counts are observations, not evidence that an action runs. Revisions can contain superseded objects.</p>{counts}</section><section><h2>Declared metadata</h2>{metadata}</section><section><h2>Analysis limitations</h2><ul>{limitations}</ul><p>{text(report["privacy"])}</p></section></main></body></html>'''
