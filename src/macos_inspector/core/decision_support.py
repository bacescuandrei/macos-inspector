from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from macos_inspector.core.guidance import build_guidance, finding_fingerprint
from macos_inspector.reporters.common import secure_write_text


ATTENTION_VERDICTS = {"needs-review", "high-risk", "likely-unwanted"}


def evidence_value(finding: dict[str, Any], kind: str) -> dict[str, Any]:
    for item in finding.get("evidence", []):
        if isinstance(item, dict) and item.get("kind") == kind and isinstance(item.get("value"), dict):
            return item["value"]
    return {}


def confidence_for_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Describe evidence quality independently from finding severity."""
    status = str(finding.get("status", "")).lower()
    evidence = [item for item in finding.get("evidence", []) if isinstance(item, dict)]
    finding_id = str(finding.get("finding_id", ""))
    missing: list[str] = []
    if status == "unknown":
        return {
            "level": "low", "label": "Low evidence confidence",
            "rationale": "The check could not collect enough evidence to verify the result.",
            "missing": ["Complete local evidence for this check"],
        }
    if finding_id.startswith("APP-TRUST-"):
        signature = evidence_value(finding, "code_signature")
        executable = evidence_value(finding, "executable_integrity")
        gatekeeper = evidence_value(finding, "gatekeeper_assessment")
        if signature.get("valid") is None:
            missing.append("Code-signature result")
        if not executable.get("sha256"):
            missing.append("Executable SHA-256")
        if gatekeeper.get("accepted") is None:
            missing.append("Gatekeeper result")
        if not missing:
            return {
                "level": "high", "label": "High evidence confidence",
                "rationale": "The result includes a signature check, Gatekeeper assessment, and executable hash.",
                "missing": [],
            }
        return {
            "level": "medium", "label": "Medium evidence confidence",
            "rationale": "Application evidence was collected, but one or more trust checks are incomplete.",
            "missing": missing,
        }
    if ("IOC" in finding_id or "YARA" in finding_id) and status == "fail" and evidence:
        return {
            "level": "high", "label": "High evidence confidence",
            "rationale": "A structured local rule or indicator match supports this result.",
            "missing": [],
        }
    if len(evidence) >= 2:
        return {
            "level": "high", "label": "High evidence confidence",
            "rationale": "Multiple structured evidence records support this observation.",
            "missing": [],
        }
    if evidence:
        return {
            "level": "medium", "label": "Medium evidence confidence",
            "rationale": "The result is supported by one structured evidence source.",
            "missing": [],
        }
    return {
        "level": "low", "label": "Low evidence confidence",
        "rationale": "The result has no structured evidence record attached.",
        "missing": ["Structured supporting evidence"],
    }


def _findings(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("finding_id")): item
        for item in report.get("findings", [])
        if isinstance(item, dict) and item.get("finding_id")
    }


def _applications(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for finding_id, finding in _findings(report).items():
        if not finding_id.startswith("APP-TRUST-"):
            continue
        app = evidence_value(finding, "application_bundle")
        signature = evidence_value(finding, "code_signature")
        executable = evidence_value(finding, "executable_integrity")
        result[finding_id] = {
            "finding_id": finding_id,
            "name": app.get("name") or finding.get("title", finding_id),
            "path": next((item.get("source") for item in finding.get("evidence", []) if isinstance(item, dict) and item.get("kind") == "application_bundle"), None),
            "version": app.get("version"),
            "publisher_team_id": signature.get("team_identifier"),
            "sha256": executable.get("sha256"),
            "fingerprint": finding_fingerprint(finding),
        }
    return result


def _network_listeners(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    finding = _findings(report).get("LIVE-NETWORK-PROCESSES", {})
    snapshot = evidence_value(finding, "network_process_snapshot")
    rows = snapshot.get("listeners", []) if isinstance(snapshot, dict) else []
    result: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        key = f"{row.get('executable', '')}|{row.get('endpoint', '')}"
        result[key] = {key: row.get(key) for key in ("executable", "command", "endpoint", "state")}
    return result


def _startup_items(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return stable startup identities from item and aggregate findings."""
    result: dict[str, dict[str, Any]] = {}
    for finding_id, finding in _findings(report).items():
        if not finding_id.startswith(("PERSIST-", "BACKGROUND-")):
            continue
        extracted = False
        for item in finding.get("evidence", []):
            if not isinstance(item, dict) or not isinstance(item.get("value"), dict):
                continue
            value = item["value"]
            if item.get("kind") == "plist" and value.get("program"):
                source = str(item.get("source") or finding_id)
                result[f"plist|{source}"] = {
                    "finding_id": finding_id,
                    "title": finding.get("title", finding_id),
                    "detail": str(value["program"]),
                    "state": "configured",
                }
                extracted = True
            if item.get("kind") == "launchctl_services":
                entries = value.get("entries", [])
                for entry in entries if isinstance(entries, list) else []:
                    if not isinstance(entry, dict) or not entry.get("label"):
                        continue
                    label = str(entry["label"])
                    scope = str(value.get("scope", "unknown"))
                    result[f"launchctl|{scope}|{label}"] = {
                        "finding_id": finding_id,
                        "title": label,
                        "detail": f"ServiceManagement state: {entry.get('state', 'unknown')}",
                        "state": str(entry.get("state", "unknown")),
                    }
                    extracted = True
        if not extracted and finding_id.startswith("PERSIST-"):
            result[f"finding|{finding_id}"] = {
                "finding_id": finding_id,
                "title": finding.get("title", finding_id),
                "detail": finding.get("observed_result", "Startup evidence recorded"),
                "state": finding_fingerprint(finding),
            }
    return result


def analyze_changes(baseline: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    if not baseline:
        return {
            "available": False,
            "baseline_scan_id": None,
            "message": "No earlier scan with the same scope is available yet. This scan can become the baseline.",
            "counts": {}, "highlights": [],
        }
    baseline_findings, current_findings = _findings(baseline), _findings(current)
    before_apps, after_apps = _applications(baseline), _applications(current)
    highlights: list[dict[str, Any]] = []
    for finding_id in sorted(after_apps.keys() - before_apps.keys()):
        app = after_apps[finding_id]
        highlights.append({"kind": "new-application", "label": "New application", "title": str(app["name"]), "detail": str(app.get("path") or "Application path unavailable"), "finding_id": finding_id})
    changed_apps = []
    for finding_id in sorted(after_apps.keys() & before_apps.keys()):
        if after_apps[finding_id]["fingerprint"] != before_apps[finding_id]["fingerprint"]:
            app = after_apps[finding_id]
            changed_apps.append(finding_id)
            details = []
            for key, label in (("version", "version"), ("publisher_team_id", "publisher"), ("sha256", "executable hash")):
                if before_apps[finding_id].get(key) != app.get(key):
                    details.append(label)
            highlights.append({"kind": "changed-application", "label": "Application changed", "title": str(app["name"]), "detail": f"Changed: {', '.join(details) or 'trust evidence'}", "finding_id": finding_id})
    new_ids = current_findings.keys() - baseline_findings.keys()
    resolved_ids = baseline_findings.keys() - current_findings.keys()
    before_startup, after_startup = _startup_items(baseline), _startup_items(current)
    new_startup_keys = after_startup.keys() - before_startup.keys()
    changed_startup_keys = {
        key for key in after_startup.keys() & before_startup.keys()
        if after_startup[key].get("state") != before_startup[key].get("state")
        or after_startup[key].get("detail") != before_startup[key].get("detail")
    }
    for key in sorted(new_startup_keys)[:20]:
        item = after_startup[key]
        highlights.append({"kind": "new-persistence", "label": "New startup item", "title": str(item["title"]), "detail": str(item["detail"]), "finding_id": item["finding_id"]})
    for key in sorted(changed_startup_keys)[:20]:
        before, after = before_startup[key], after_startup[key]
        highlights.append({"kind": "changed-persistence", "label": "Startup item changed", "title": str(after["title"]), "detail": f"{before.get('detail', 'Previous state')} to {after.get('detail', 'current state')}", "finding_id": after["finding_id"]})
    before_listeners, after_listeners = _network_listeners(baseline), _network_listeners(current)
    for key in sorted(after_listeners.keys() - before_listeners.keys())[:20]:
        row = after_listeners[key]
        highlights.append({"kind": "new-listener", "label": "New network listener", "title": str(row.get("command") or row.get("executable") or "Process"), "detail": f"{row.get('endpoint', 'unknown endpoint')} | {row.get('executable', 'unknown executable')}", "finding_id": "LIVE-NETWORK-PROCESSES"})
    changed_controls = []
    for finding_id in sorted(baseline_findings.keys() & current_findings.keys()):
        before, after = baseline_findings[finding_id], current_findings[finding_id]
        if before.get("status") == after.get("status") and before.get("severity") == after.get("severity"):
            continue
        if finding_id.startswith(("SECURITY-", "ACCOUNTS-", "MANAGEMENT-", "SYSTEMEXT-")):
            changed_controls.append(finding_id)
            highlights.append({"kind": "control-change", "label": "Security control changed", "title": str(after.get("title", finding_id)), "detail": f"{before.get('status', 'Unknown')} to {after.get('status', 'Unknown')}", "finding_id": finding_id})
    return {
        "available": True,
        "baseline_scan_id": baseline.get("metadata", {}).get("scan_id"),
        "baseline_completed_at": baseline.get("metadata", {}).get("completed_at"),
        "message": "Compared with the most recent earlier scan that used the same collection scope.",
        "counts": {
            "new_applications": len(after_apps.keys() - before_apps.keys()),
            "changed_applications": len(changed_apps),
            "removed_applications": len(before_apps.keys() - after_apps.keys()),
            "new_startup_items": len(new_startup_keys),
            "changed_startup_items": len(changed_startup_keys),
            "new_network_listeners": len(after_listeners.keys() - before_listeners.keys()),
            "closed_network_listeners": len(before_listeners.keys() - after_listeners.keys()),
            "changed_controls": len(changed_controls),
            "new_findings": len(new_ids),
            "resolved_findings": len(resolved_ids),
        },
        "highlights": highlights[:50],
    }


def _process_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding_id in ("LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"):
        finding = _findings(report).get(finding_id, {})
        for item in finding.get("evidence", []):
            value = item.get("value") if isinstance(item, dict) else None
            if not isinstance(value, dict):
                continue
            for key in ("review_candidates", "listeners"):
                for row in value.get(key, []) if isinstance(value.get(key), list) else []:
                    if isinstance(row, dict) and row.get("executable"):
                        rows.append({**row, "finding_id": finding_id, "signal": "network" if key == "listeners" else "process"})
    return rows


def _persistence_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for finding_id, finding in _findings(report).items():
        if not finding_id.startswith(("PERSIST-", "BACKGROUND-")):
            continue
        for item in finding.get("evidence", []):
            value = item.get("value") if isinstance(item, dict) else None
            if not isinstance(value, dict):
                continue
            executable = value.get("program") or value.get("executable") or value.get("path")
            if executable:
                rows.append({"finding_id": finding_id, "executable": str(executable), "title": finding.get("title", finding_id)})
    return rows


def build_stories(report: dict[str, Any], guidance: dict[str, Any]) -> list[dict[str, Any]]:
    apps = _applications(report)
    processes = _process_rows(report)
    persistence = _persistence_rows(report)
    stories: list[dict[str, Any]] = []
    used: set[tuple[str, ...]] = set()
    for finding_id, app in apps.items():
        verdict = guidance.get("findings", {}).get(finding_id, {}).get("verdict")
        if verdict not in ATTENTION_VERDICTS:
            continue
        app_path = str(app.get("path") or "")
        prefix = f"{app_path}/" if app_path else ""
        matched_processes = [row for row in processes if prefix and str(row.get("executable", "")).startswith(prefix)]
        matched_persistence = [row for row in persistence if prefix and str(row.get("executable", "")).startswith(prefix)]
        signals = [{"type": "application", "finding_id": finding_id, "detail": str(app.get("path") or app.get("name"))}]
        signals.extend({"type": row["signal"], "finding_id": row["finding_id"], "detail": str(row.get("executable"))} for row in matched_processes)
        signals.extend({"type": "persistence", "finding_id": row["finding_id"], "detail": str(row.get("executable"))} for row in matched_persistence)
        unique_types = sorted({item["type"] for item in signals})
        if len(unique_types) < 2:
            continue
        key = tuple(sorted({item["finding_id"] for item in signals}))
        if key in used:
            continue
        used.add(key)
        actions = ["Validate the application publisher, source, and executable hash."]
        if "persistence" in unique_types:
            actions.append("Confirm that this application is expected to start automatically.")
        if "process" in unique_types or "network" in unique_types:
            actions.append("Review the live process and network context before containment.")
        stories.append({
            "id": f"story-{len(stories) + 1}",
            "title": f"{app.get('name') or 'An application'} appears in {' and '.join(unique_types)} evidence",
            "narrative": f"The same application path connects {len(signals)} observations across {len(unique_types)} evidence types. This relationship deserves validation, but it is not proof of compromise.",
            "confidence": "high",
            "signals": signals[:10],
            "next_actions": actions,
        })
    return stories[:20]


def build_decision_support(
    current: dict[str, Any], baseline: dict[str, Any] | None = None,
    investigations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    guidance = build_guidance(current, investigations)
    for finding_id, finding in _findings(current).items():
        if finding_id in guidance["findings"]:
            guidance["findings"][finding_id]["confidence"] = confidence_for_finding(finding)
    changes = analyze_changes(baseline, current)
    stories = build_stories(current, guidance)
    investigation_counts: dict[str, int] = {}
    for item in guidance["findings"].values():
        status = str(item.get("investigation", {}).get("status", "New"))
        investigation_counts[status] = investigation_counts.get(status, 0) + 1
    final_summary = {
        "headline": guidance["headline"],
        "attention": guidance["counts"]["attention"],
        "unable_to_verify": guidance["counts"]["unable_to_verify"],
        "correlated_stories": len(stories),
        "changes_available": changes["available"],
        "investigation_states": investigation_counts,
        "conclusion": "The report records observations and investigation decisions. It does not by itself prove that this Mac is compromised.",
    }
    return {
        "scan_id": current.get("metadata", {}).get("scan_id"),
        "guidance": guidance,
        "changes": changes,
        "stories": stories,
        "final_summary": final_summary,
    }


def write_investigation_summary(report: dict[str, Any], decision: dict[str, Any], output: Path) -> Path:
    scan_id = str(report.get("metadata", {}).get("scan_id", "scan"))
    priorities = decision["guidance"].get("priorities", [])
    changes = decision["changes"]
    stories = decision["stories"]
    state_rows = "".join(
        f"<li><strong>{escape(str(key))}</strong>: {int(value)}</li>"
        for key, value in sorted(decision["final_summary"].get("investigation_states", {}).items())
    )
    priority_rows = "".join(
        f"<article><span>{escape(str(item.get('label', 'Review')))}</span><h3>{escape(str(item.get('title', 'Finding')))}</h3><p>{escape(str(item.get('next_action', 'Review the finding.')))}</p></article>"
        for item in priorities
    ) or "<p>No item currently needs immediate attention.</p>"
    change_rows = "".join(
        f"<article><span>{escape(str(item.get('label', 'Change')))}</span><h3>{escape(str(item.get('title', 'Change')))}</h3><p>{escape(str(item.get('detail', '')))}</p></article>"
        for item in changes.get("highlights", [])[:20]
    ) or f"<p>{escape(str(changes.get('message', 'No high-signal change was identified.')))}</p>"
    story_rows = "".join(
        f"<article><span>{escape(str(item.get('confidence', 'medium')).title())} confidence correlation</span><h3>{escape(str(item.get('title', 'Investigation story')))}</h3><p>{escape(str(item.get('narrative', '')))}</p></article>"
        for item in stories
    ) or "<p>No multi-signal investigation story was identified.</p>"
    hostname = escape(str(report.get("metadata", {}).get("hostname", "unknown")))
    target = str(report.get("metadata", {}).get("target_application", ""))
    target_html = f"<p>Target application: {escape(target)}</p>" if target else ""
    html = f"""<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Investigation summary {escape(scan_id)}</title><style>body{{margin:0;background:#0d1422;color:#edf3ff;font:15px/1.55 -apple-system,BlinkMacSystemFont,sans-serif}}main{{max-width:980px;margin:auto;padding:32px 18px 64px}}header,section{{margin-bottom:18px;padding:22px;border:1px solid #283954;border-radius:14px;background:#111b2d}}h1,h2,h3,p{{overflow-wrap:anywhere}}h1{{font-size:30px}}h2{{font-size:19px}}h3{{margin:5px 0;font-size:15px}}small,p,li{{color:#aebbd0}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px}}.metrics div,article{{padding:13px;border:1px solid #283954;border-radius:10px;background:#16233a}}.metrics strong{{display:block;font-size:24px}}article{{margin-top:9px}}article span{{color:#78aaff;font-size:11px;text-transform:uppercase}}@media print{{body{{background:white;color:#111}}header,section,article,.metrics div{{background:white;border-color:#bbb}}small,p,li{{color:#333}}}}</style></head><body><main><header><small>MACOS INSPECTOR | INVESTIGATION SUMMARY</small><h1>{escape(str(decision['final_summary']['headline']))}</h1><p>Scan {escape(scan_id)} | Host {hostname}</p>{target_html}<p>{escape(str(decision['final_summary']['conclusion']))}</p></header><section><h2>Current assessment</h2><div class=\"metrics\"><div><strong>{decision['final_summary']['attention']}</strong>need attention</div><div><strong>{decision['final_summary']['unable_to_verify']}</strong>not verified</div><div><strong>{decision['final_summary']['correlated_stories']}</strong>correlated stories</div></div></section><section><h2>Priorities</h2>{priority_rows}</section><section><h2>Changes since the previous comparable scan</h2>{change_rows}</section><section><h2>Correlated investigation stories</h2>{story_rows}</section><section><h2>Investigation state</h2><ul>{state_rows}</ul><p>Technical evidence remains in the original signed or exported scan report.</p></section></main></body></html>"""
    path = output / f"macos-inspector-{scan_id}-investigation-summary.html"
    secure_write_text(path, html)
    return path
