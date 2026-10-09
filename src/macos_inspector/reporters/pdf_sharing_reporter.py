"""Standalone HTML for a reduced sharing summary, without original evidence."""
from __future__ import annotations

from html import escape


def render_pdf_sharing_summary(summary: dict) -> str:
    def text(value):
        return escape(str(value))

    def rows(values):
        return "".join(f"<tr><th scope='row'>{text(key.replace('_', ' '))}</th><td>{text(value if value is not None else 'Not available')}</td></tr>" for key, value in values.items())

    omitted = "".join(f"<li>{text(field)}</li>" for field in summary["redaction"]["omitted_fields"])
    digest = f'<p>Document SHA-256 (included by explicit choice): <code>{text(summary["document_sha256"])}</code></p>' if "document_sha256" in summary else "<p>Document identity omitted.</p>"
    complete = "No additional limits recorded within the supported scope" if summary["assessment"]["analysis_complete_within_supported_scope"] else "Limited or unavailable; absence cannot be established"
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PDF Inspector | Reduced sharing summary</title><style>
    *{{box-sizing:border-box}}body{{margin:0;background:#101827;color:#e7edf8;font:16px/1.6 system-ui,sans-serif}}main{{max-width:850px;margin:auto;padding:20px}}section,header{{padding:20px;margin-bottom:18px;border:1px solid #34435c;border-radius:14px;background:#182238;min-width:0}}h1{{font-size:26px}}h2{{font-size:20px}}h1,h2,p,li,td,th,code{{overflow-wrap:anywhere}}table{{width:100%;border-collapse:collapse;table-layout:fixed}}td,th{{padding:8px;text-align:left;vertical-align:top;border-bottom:1px solid #34435c}}th{{width:65%}}.notice{{color:#ffcd73}}@media(max-width:600px){{main{{padding:12px}}section,header{{padding:14px}}}}
    </style></head><body><main><header><p>macOS Inspector {text(summary["tool_version"])} | PDF Inspector</p><h1>Reduced sharing summary</h1><p class="notice">Detailed evidence omitted. Original report unchanged.</p><p>{text(summary["redaction"]["warning"])}</p></header><section><h2>Recorded assessment</h2><p>{text(summary["assessment"]["label"])}</p><p>Malware verdict: Not determined</p><p>Analysis scope: {text(complete)}</p><p>{text(summary["boundary"])}</p>{digest}</section><section><h2>Recorded observations</h2><table>{rows(summary["observations"])}</table></section><section><h2>Recorded action types</h2><table>{rows(summary["action_type_counts"])}</table><p>Empty counts do not establish absence. Records may describe the same action more than once.</p></section><section><h2>Parsed structural names</h2><table>{rows(summary["structural_name_counts"])}</table></section><section><h2>Information omitted from this copy</h2><ul>{omitted}</ul><p>This is a derived summary, not the original evidence report or an authenticated export.</p></section></main></body></html>'''
