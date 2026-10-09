"""Escaped permission explanations in ordinary HTML and investigation exports."""
from __future__ import annotations

from html import escape


BROWSER_EXTENSION_CSS = ".browser-extension-report{min-width:0;overflow-wrap:anywhere}.browser-extension-report article{border:1px solid #64748b55;border-radius:12px;padding:16px;margin:14px 0;min-width:0}.browser-extension-report h3,.browser-extension-report h4,.browser-extension-report li,.browser-extension-report code{overflow-wrap:anywhere}.browser-extension-report summary{cursor:pointer}.browser-extension-report ul{padding-left:20px}.browser-extension-report small{display:block}"


def render_browser_extension_report(findings: list[dict]) -> str:
    profiles = [item["value"] for finding in findings if isinstance(finding, dict)
                for item in finding.get("evidence", []) if isinstance(item, dict) and item.get("kind") == "browser_profile" and isinstance(item.get("value"), dict)]
    if not profiles:
        return ""
    cards = []
    total = 0
    for profile in profiles:
        extensions = profile.get("extensions", [])
        if not isinstance(extensions, list):
            continue
        for row in extensions:
            if not isinstance(row, dict):
                continue
            total += 1
            if len(cards) >= 60:
                continue
            analysis = row.get("permission_analysis")
            if not isinstance(analysis, dict) or analysis.get("schema_version") != 1:
                analysis = {}
            features = analysis.get("features", [])
            if not isinstance(features, list):
                features = []
            feature_rows = "".join(f'<li><strong>{escape(str(item.get("label", "Recorded capability")))}</strong> | {escape(str(item.get("scope", "Scope unknown")))}<br>{escape(str(item.get("explanation", "Verify access in the browser.")))}</li>' for item in features[:40] if isinstance(item, dict))
            details = []
            for group in ("required", "optional"):
                permissions = analysis.get(group)
                if not isinstance(permissions, dict):
                    continue
                for field in ("api_permissions", "host_patterns", "content_script_matches", "content_script_exclusions", "content_script_include_globs", "content_script_exclude_globs"):
                    values = permissions.get(field)
                    if isinstance(values, list) and values:
                        details.append(f'<h4>{escape(group.title())} {escape(field.replace("_", " "))}</h4><ul>' + "".join(f"<li><code>{escape(str(value))}</code></li>" for value in values[:100]) + "</ul>")
            limits = analysis.get("limitations", [])
            if isinstance(limits, list):
                details.append("<ul>" + "".join(f"<li>{escape(str(value))}</li>" for value in limits) + "</ul>")
            active = "Enabled in recorded addon metadata" if row.get("active") is True else "Disabled in recorded addon metadata" if row.get("active") is False else "Enabled state not verified"
            state = "Requirements recorded" if analysis.get("complete") is True else "Permission analysis limited"
            cards.append(f'<article><h3>{escape(str(row.get("name") or row.get("id") or "Unnamed extension record"))}</h3><p>{escape(str(profile.get("browser", "Browser")))} | {escape(str(profile.get("profile", "Profile")))} | Version {escape(str(row.get("version", "Unknown")))}</p><small>{escape(state)} | {escape(active)}</small><p>{escape(str(analysis.get("effective_access", "Permissions were not established in this report. Recheck this profile.")))}</p><ul>{feature_rows or "<li>No supported permission explanation recorded; this does not establish safety.</li>"}</ul><details><summary>Permission declarations and limits</summary><p>{escape(str(analysis.get("source", "Source unavailable")))}</p>{"".join(details)}<p>{escape(str(analysis.get("boundary", "Declaration and grant state were not assessed.")))}</p></details></article>')
    notes = [note for profile in profiles for note in (profile.get("collection_notes") if isinstance(profile.get("collection_notes"), list) else []) if isinstance(note, str)]
    limits_html = "<ul>" + "".join(f"<li>{escape(note)}</li>" for note in notes) + "</ul>" if notes else ""
    count = f"Showing {len(cards)} of {total} collected extension records." if total > len(cards) else f"{total} extension record(s)."
    return f'<section class="browser-extension-report"><h2>Browser extension permissions</h2><p>Permission requirements are not confirmed grants, observed activity, or a malware verdict. Optional permissions are not confirmed granted. Verify enabled state and actual site access in the browser before changing anything.</p><p>{escape(count)}</p>{limits_html}{"".join(cards) or "<p>No extension records in collected profiles. This is not proof that no extension exists.</p>"}</section>'
