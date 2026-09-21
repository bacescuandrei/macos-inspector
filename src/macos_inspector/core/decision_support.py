from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from macos_inspector.core.guidance import build_guidance, finding_fingerprint
from macos_inspector.reporters.common import secure_write_text


ATTENTION_VERDICTS = {"needs-review", "high-risk", "likely-unwanted"}
SEVERITY_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def evidence_value(finding: dict[str, Any], kind: str) -> dict[str, Any]:
    for item in finding.get("evidence", []):
        if isinstance(item, dict) and item.get("kind") == kind and isinstance(item.get("value"), dict):
            return item["value"]
    return {}


def _signature_result(finding: dict[str, Any], signature: dict[str, Any]) -> bool | None:
    completed = signature.get("verification_completed")
    if completed is False:
        return None
    observed = str(finding.get("observed_result") or "").lower()
    if completed is None and str(finding.get("status", "")).lower() == "unknown" and (
        "signature verification was unavailable or timed out" in observed
        or "code-signing trust service could not complete" in observed
    ):
        return None
    value = signature.get("valid")
    return value if isinstance(value, bool) else None


def _gatekeeper_result(finding: dict[str, Any], gatekeeper: dict[str, Any]) -> bool | None:
    completed = gatekeeper.get("assessment_completed")
    if completed is False:
        return None
    observed = str(finding.get("observed_result") or "").lower()
    if completed is None and str(finding.get("status", "")).lower() == "unknown" and (
        "gatekeeper assessment was unavailable" in observed
        or "gatekeeper did not return a definitive assessment" in observed
    ):
        return None
    value = gatekeeper.get("accepted")
    return value if isinstance(value, bool) else None


def _notarization_result(gatekeeper: dict[str, Any]) -> bool | None:
    if "app store" in str(gatekeeper.get("source") or "").lower():
        return None
    value = gatekeeper.get("notarized")
    return value if isinstance(value, bool) else None


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
        metadata = evidence_value(finding, "info_plist_integrity")
        bundle_paths = evidence_value(finding, "bundle_path_integrity")
        gatekeeper = evidence_value(finding, "gatekeeper_assessment")
        result[finding_id] = {
            "finding_id": finding_id,
            "name": app.get("name") or finding.get("title", finding_id),
            "path": next((item.get("source") for item in finding.get("evidence", []) if isinstance(item, dict) and item.get("kind") == "application_bundle"), None),
            "status": finding.get("status"),
            "severity": finding.get("severity"),
            "bundle_identifier": app.get("bundle_identifier"),
            "version": app.get("version"),
            "executable_path": app.get("executable"),
            "publisher_team_id": signature.get("team_identifier"),
            "signature_valid": _signature_result(finding, signature),
            "signature_type": signature.get("signature_type"),
            "hardened_runtime": signature.get("hardened_runtime"),
            "gatekeeper_accepted": _gatekeeper_result(finding, gatekeeper),
            "notarized": _notarization_result(gatekeeper),
            "sha256": executable.get("sha256"),
            "executable_permissions": executable.get("permissions"),
            "executable_changed_during_read": executable.get("changed_during_read"),
            "info_plist_permissions": metadata.get("permissions"),
            "info_plist_changed_during_read": metadata.get("changed_during_read"),
            "executable_inside_bundle": bundle_paths.get("executable_resolves_within_bundle"),
            "signals": _application_signals(finding),
            "fingerprint": finding_fingerprint(finding),
        }
    return result


def _application_signals(finding: dict[str, Any]) -> list[str]:
    """Return short, evidence-backed trust signals without making a malware verdict."""
    signature = evidence_value(finding, "code_signature")
    gatekeeper = evidence_value(finding, "gatekeeper_assessment")
    executable = evidence_value(finding, "executable_integrity")
    bundle_paths = evidence_value(finding, "bundle_path_integrity")
    entitlements = evidence_value(finding, "code_entitlements")
    signals: list[str] = []
    signature_valid = _signature_result(finding, signature)
    notarized = _notarization_result(gatekeeper)
    if signature_valid is False:
        signals.append("The code signature did not validate.")
    if _gatekeeper_result(finding, gatekeeper) is False:
        signals.append("Gatekeeper did not accept the application.")
    if bundle_paths.get("executable_resolves_within_bundle") is False:
        signals.append("The main executable resolves outside the application bundle.")
    if executable.get("changed_during_read") is True:
        signals.append("The executable changed while its hash was being collected.")
    permissions = str(executable.get("permissions") or "")
    try:
        mode = int(permissions, 8)
        if mode & 0o002:
            signals.append("The main executable is writable by every local user.")
        elif mode & 0o020:
            signals.append("The main executable is writable by its owning group.")
    except ValueError:
        pass
    if not executable.get("sha256"):
        signals.append("The executable hash could not be collected.")
    sensitive = entitlements.get("sensitive", [])
    if isinstance(sensitive, (list, tuple)) and sensitive:
        signals.append(f"Security-sensitive entitlement: {sensitive[0]}.")
    if notarized is False:
        signals.append("Notarization was not confirmed by the Gatekeeper result.")
    if signature_valid is True and not signature.get("team_identifier"):
        signals.append("No signing Team ID was reported.")
    return signals[:4]


def _source_host(value: object) -> str | None:
    """Return a privacy-limited label for acquisition metadata."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = urlsplit(text)
    except ValueError:
        return None
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return parsed.hostname.rstrip(".").lower()
    if parsed.scheme.lower() == "file":
        return "Local file"
    return None


def _application_provenance(finding: dict[str, Any], path: str) -> dict[str, Any]:
    """Summarize signer and acquisition evidence without inferring publisher legitimacy."""
    signature = evidence_value(finding, "code_signature")
    gatekeeper = evidence_value(finding, "gatekeeper_assessment")
    quarantine = evidence_value(finding, "quarantine_attribute")
    downloads = evidence_value(finding, "download_sources")

    authorities = signature.get("authority", [])
    if not isinstance(authorities, (list, tuple)):
        authorities = []
    usable_authorities = [
        str(authority).strip() for authority in authorities
        if str(authority).strip().lower() not in {"", "(unavailable)", "unavailable"}
    ]
    publisher = str(gatekeeper.get("origin") or "").strip() or (usable_authorities[0] if usable_authorities else None)
    if not publisher and signature.get("team_identifier"):
        publisher = f"Team ID {signature['team_identifier']}"

    raw_sources = downloads.get("sources", [])
    if not isinstance(raw_sources, (list, tuple)):
        raw_sources = []
    source_hosts: list[str] = []
    for value in raw_sources:
        label = _source_host(value)
        if label and label not in source_hosts:
            source_hosts.append(label)
        if len(source_hosts) == 5:
            break

    normalized_path = path.rstrip("/")
    if normalized_path.startswith(("/System/Applications/", "/System/Library/CoreServices/")):
        install_scope = "Built into macOS or system-managed"
    elif normalized_path.startswith("/Applications/"):
        install_scope = "Installed for all users"
    elif normalized_path.startswith("/Users/") and "/Applications/" in normalized_path:
        install_scope = "Installed for one user"
    else:
        install_scope = "Other application location"

    gatekeeper_source = str(gatekeeper.get("source") or "").strip() or None
    quarantine_present = quarantine.get("present")
    if source_hosts:
        acquisition = f"Download source recorded: {', '.join(source_hosts)}."
    elif quarantine_present is True:
        acquisition = "macOS recorded downloaded-file metadata, but no source hostname is available."
    elif gatekeeper_source and "app store" in gatekeeper_source.lower():
        acquisition = "Gatekeeper reports a Mac App Store source."
    else:
        acquisition = "The installation source is not recorded in the available metadata. Its absence is not a risk signal by itself."
    signer = f"macOS reported the signing identity as {publisher}." if publisher else "No human-readable signing identity was available."
    return {
        "publisher": publisher,
        "team_id": signature.get("team_identifier"),
        "signature_type": signature.get("signature_type"),
        "gatekeeper_source": gatekeeper_source,
        "install_scope": install_scope,
        "source_hosts": source_hosts,
        "download_agent": quarantine.get("agent"),
        "downloaded_at": quarantine.get("timestamp_iso"),
        "quarantine_present": quarantine_present,
        "summary": f"{signer} {acquisition}",
        "privacy_note": "Only source hostnames are shown here. The original local evidence may contain complete acquisition metadata.",
    }


def build_application_review(
    report: dict[str, Any], guidance: dict[str, Any], changes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a plain-language application triage queue from Application Trust evidence."""
    groups = {
        "review_first": "Review first",
        "needs_context": "Needs context",
        "unable_to_verify": "Unable to verify",
        "checks_passed": "Checks passed",
        "reviewed": "Reviewed locally",
        "recorded": "Recorded",
    }
    order = {key: index for index, key in enumerate(groups)}
    findings = _findings(report)
    applications = _applications(report)
    observed_processes = _process_rows(report)
    observed_persistence = _persistence_rows(report)
    collectors = set(report.get("metadata", {}).get("collectors", []))
    activity_coverage = {
        "running": "live-triage" in collectors or "LIVE-PROCESS-TREE" in findings,
        "network": "live-triage" in collectors or "LIVE-NETWORK-PROCESSES" in findings,
        "startup": bool(collectors & {"persistence", "background-items"}) or any(
            finding_id.startswith(("PERSIST-", "BACKGROUND-")) for finding_id in findings
        ),
    }
    application_changes = {
        str(item.get("finding_id")): item
        for item in (changes or {}).get("application_changes", (changes or {}).get("highlights", []))
        if isinstance(item, dict) and item.get("kind") in {"new-application", "changed-application", "application-coverage-change"}
    }
    rows: list[dict[str, Any]] = []
    for finding_id, app in applications.items():
        finding = findings[finding_id]
        status = str(finding.get("status", "Unknown"))
        severity = str(finding.get("severity", "Informational"))
        guide = guidance.get("findings", {}).get(finding_id, {})
        investigation = guide.get("investigation", {}) if isinstance(guide, dict) else {}
        investigation_status = str(investigation.get("status", "New")) if investigation.get("current", True) else "New"
        if investigation_status in {"Expected", "Resolved"}:
            group = "reviewed"
        elif status.lower() == "fail" or (
            status.lower() == "review" and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["High"]
        ):
            group = "review_first"
        elif status.lower() == "review":
            group = "needs_context"
        elif status.lower() == "unknown":
            group = "unable_to_verify"
        elif status.lower() == "pass":
            group = "checks_passed"
        else:
            group = "recorded"
        signature = evidence_value(finding, "code_signature")
        gatekeeper = evidence_value(finding, "gatekeeper_assessment")
        executable = evidence_value(finding, "executable_integrity")
        next_actions = guide.get("next_actions", []) if isinstance(guide, dict) else []
        application_path = str(app.get("path") or "")
        rows.append({
            **app,
            "status": status,
            "severity": severity,
            "group": group,
            "group_label": groups[group],
            "explanation": guide.get("simple_explanation") or finding.get("observed_result") or "Trust evidence was recorded.",
            "next_action": next_actions[0] if next_actions else "Open the finding and validate the publisher, source, and expected use.",
            "investigation_status": investigation_status,
            "signature_valid": app.get("signature_valid"),
            "signature_type": signature.get("signature_type"),
            "gatekeeper_accepted": app.get("gatekeeper_accepted"),
            "notarized": app.get("notarized"),
            "hardened_runtime": signature.get("hardened_runtime"),
            "sha256": executable.get("sha256"),
            "signals": _application_signals(finding),
            "change": application_changes.get(finding_id),
            "provenance": _application_provenance(finding, application_path),
            "activity": _application_activity(
                application_path, observed_processes, observed_persistence, activity_coverage,
            ),
        })
    rows.sort(key=lambda row: (
        order[row["group"]],
        -SEVERITY_RANK.get(str(row["severity"]), 0),
        str(row["name"]).casefold(),
    ))
    counts = {key: sum(row["group"] == key for row in rows) for key in groups}
    activity_counts = {
        "running": sum(bool(row["activity"]["running_processes"]) for row in rows),
        "network": sum(bool(row["activity"]["network_connections"]) for row in rows),
        "starts_automatically": sum(bool(row["activity"]["startup_items"]) for row in rows),
    }
    return {
        "available": bool(rows),
        "total": len(rows),
        "counts": counts,
        "activity_counts": activity_counts,
        "groups": groups,
        "applications": rows,
        "conclusion": "This queue prioritizes trust observations. It does not label an application as malware or safe.",
    }


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


def _change_value(key: str, value: object) -> str:
    if value is None or value == "":
        return "Not available"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value)
    if key == "sha256" and len(text) > 16:
        return f"{text[:16]}..."
    return text


def _platform_version(report: dict[str, Any]) -> str | None:
    platform = str(report.get("metadata", {}).get("platform") or "")
    if platform.startswith("macOS-"):
        return platform.removeprefix("macOS-").split("-", 1)[0] or None
    return None


def _application_change_priority(app: dict[str, Any]) -> str:
    status = str(app.get("status") or "").lower()
    severity = SEVERITY_RANK.get(str(app.get("severity") or "Informational"), 0)
    if status in {"fail", "match", "review"} and severity >= SEVERITY_RANK["High"]:
        return "high"
    if status in {"fail", "match", "review", "unknown"}:
        return "review"
    return "context"


def _permission_risk(value: object) -> int | None:
    try:
        mode = int(str(value), 8)
    except (TypeError, ValueError):
        return None
    if mode & 0o002:
        return 2
    if mode & 0o020:
        return 1
    return 0


def _application_field_changed(key: str, before: object, after: object) -> bool:
    if before == after:
        return False
    if before is not None:
        return True
    if key in {"executable_permissions", "info_plist_permissions"}:
        risk = _permission_risk(after)
        return risk is not None and risk > 0
    if key == "executable_inside_bundle":
        return after is False
    if key in {"executable_changed_during_read", "info_plist_changed_during_read"}:
        return after is True
    return True


def _application_change(
    before: dict[str, Any], after: dict[str, Any], finding_id: str,
    before_macos: str | None = None, after_macos: str | None = None,
    tool_version_changed: bool = False,
) -> dict[str, Any]:
    """Explain an application identity change without treating it as proof of tampering."""
    fields = (
        ("bundle_identifier", "Bundle identifier"),
        ("version", "Version"),
        ("executable_path", "Executable path"),
        ("publisher_team_id", "Team ID"),
        ("signature_valid", "Signature validation"),
        ("signature_type", "Signature type"),
        ("gatekeeper_accepted", "Gatekeeper acceptance"),
        ("notarized", "Notarization"),
        ("hardened_runtime", "Hardened runtime"),
        ("sha256", "Executable SHA-256"),
        ("executable_permissions", "Executable permissions"),
        ("info_plist_permissions", "Info.plist permissions"),
        ("executable_inside_bundle", "Executable remains inside bundle"),
        ("executable_changed_during_read", "Executable changed during collection"),
        ("info_plist_changed_during_read", "Info.plist changed during collection"),
        ("status", "Trust result"),
        ("severity", "Severity"),
    )
    changed_fields = [
        {
            "key": key,
            "label": label,
            "before": _change_value(key, before.get(key)),
            "after": _change_value(key, after.get(key)),
        }
        for key, label in fields if _application_field_changed(key, before.get(key), after.get(key))
    ]
    changed_keys = {item["key"] for item in changed_fields}
    signature_regressed = before.get("signature_valid") is True and after.get("signature_valid") is False
    gatekeeper_regressed = before.get("gatekeeper_accepted") is True and after.get("gatekeeper_accepted") is False
    old_team, new_team = before.get("publisher_team_id"), after.get("publisher_team_id")
    signer_replaced = bool(old_team and new_team and old_team != new_team)
    old_bundle, new_bundle = before.get("bundle_identifier"), after.get("bundle_identifier")
    bundle_replaced = bool(old_bundle and new_bundle and old_bundle != new_bundle)
    path_regressed = before.get("executable_inside_bundle") is True and after.get("executable_inside_bundle") is False
    executable_permission_before = _permission_risk(before.get("executable_permissions"))
    executable_permission_after = _permission_risk(after.get("executable_permissions"))
    metadata_permission_before = _permission_risk(before.get("info_plist_permissions"))
    metadata_permission_after = _permission_risk(after.get("info_plist_permissions"))
    executable_permissions_weakened = (
        executable_permission_before is not None and executable_permission_after is not None
        and executable_permission_after > executable_permission_before
    )
    metadata_permissions_weakened = (
        metadata_permission_before is not None and metadata_permission_after is not None
        and metadata_permission_after > metadata_permission_before
    )
    previous_priority = _application_change_priority(before)
    current_priority = _application_change_priority(after)
    established_field_change = any(
        item["key"] not in {"status", "severity"} and before.get(item["key"]) is not None
        for item in changed_fields
    )
    coverage_reclassification = tool_version_changed and not established_field_change
    apple_system_app = bool(
        str(after.get("path") or "").startswith("/System/")
        or (
            str(after.get("signature_type") or "").startswith("Apple")
            and str(new_bundle or "").startswith("com.apple.")
        )
    )
    system_macos_change = bool(
        apple_system_app and before_macos and after_macos and before_macos != after_macos
    )
    if system_macos_change:
        changed_fields.append({
            "key": "macos_version", "label": "macOS version",
            "before": str(before_macos), "after": str(after_macos),
        })
    trust_recovered = any((
        before.get("signature_valid") is False and after.get("signature_valid") is True,
        before.get("gatekeeper_accepted") is False and after.get("gatekeeper_accepted") is True,
    ))

    if coverage_reclassification and current_priority in {"high", "review"} and previous_priority == "context":
        label, priority = "New concern from expanded checks", current_priority
        signal = next((str(item) for item in after.get("signals", []) if item), "The current result requires review.")
        detail = f"The newer inspector flags current evidence that the earlier version did not evaluate. {signal}"
        next_action = "Validate the current concern, but do not assume the application itself changed without a compared field value showing it."
    elif coverage_reclassification:
        label, priority = "Evidence coverage expanded", "context"
        detail = "The newer report contains different application evidence, but no previously known identity or trust field changed."
        next_action = "Use the current evidence as the new baseline. No application change is established by this difference alone."
    elif signature_regressed or gatekeeper_regressed:
        label, priority = "Trust check regressed", "high"
        failures = []
        if signature_regressed:
            failures.append("signature validation now fails")
        if gatekeeper_regressed:
            failures.append("Gatekeeper no longer accepts the application")
        detail = f"{' and '.join(failures).capitalize()}."
        next_action = "Do not rely on the earlier result. Preserve the current bundle and validate its source before opening it."
    elif signer_replaced:
        label, priority = "Signing identity changed", "high"
        detail = f"Team ID changed from {old_team} to {new_team}."
        next_action = "Confirm that the new signer is expected for this application before treating the change as an update."
    elif bundle_replaced:
        label, priority = "Bundle identity changed", "high"
        detail = f"Bundle identifier changed from {old_bundle} to {new_bundle}."
        next_action = "Confirm the application's expected bundle identifier and source before opening it."
    elif path_regressed:
        label, priority = "Bundle path integrity regressed", "high"
        detail = "The main executable now resolves outside the application bundle."
        next_action = "Do not open the application. Preserve the bundle and inspect the resolved executable path and ownership."
    elif executable_permissions_weakened:
        label = "Executable permissions weakened"
        priority = "high" if executable_permission_after == 2 else "review"
        detail = (
            f"Executable permissions changed from {_change_value('executable_permissions', before.get('executable_permissions'))} "
            f"to {_change_value('executable_permissions', after.get('executable_permissions'))}, allowing broader local modification."
        )
        next_action = "Validate the application's source and ownership, then correct or reinstall it before relying on the executable."
    elif metadata_permissions_weakened:
        label = "Application metadata permissions weakened"
        priority = "high" if metadata_permission_after == 2 else "review"
        detail = (
            f"Info.plist permissions changed from {_change_value('info_plist_permissions', before.get('info_plist_permissions'))} "
            f"to {_change_value('info_plist_permissions', after.get('info_plist_permissions'))}, allowing broader local modification."
        )
        next_action = "Validate the bundle source and ownership, then correct or reinstall the application before relying on its metadata."
    elif current_priority in {"high", "review"} and previous_priority == "context":
        label, priority = "New trust concern detected", current_priority
        before_status = _change_value("status", before.get("status"))
        after_status = _change_value("status", after.get("status"))
        signal = next((str(item) for item in after.get("signals", []) if item), "The current result requires review.")
        detail = f"The trust result changed from {before_status} to {after_status}. {signal}"
        next_action = "Open the current result, validate the reported integrity or trust signal, and preserve evidence before remediation."
    elif current_priority in {"high", "review"} and ({"version", "sha256"} & changed_keys):
        label, priority = "Changed app still needs review", current_priority
        detail = (
            "The application changed, but its current trust result is "
            f"{str(after.get('status') or 'not verified').lower()}."
        )
        next_action = "Open the current result and resolve its signature, Gatekeeper, or integrity issue before accepting the change as an update."
    elif {"version", "sha256"}.issubset(changed_keys) and old_team == new_team and bool(new_team):
        label, priority = "Possible application update", "context"
        detail = (
            f"Version changed from {_change_value('version', before.get('version'))} to "
            f"{_change_value('version', after.get('version'))}, the executable changed, and Team ID {new_team} remained the same."
        )
        next_action = "Confirm that an update was expected and compare the version with the publisher's trusted release information."
    elif system_macos_change and "sha256" in changed_keys:
        label, priority = "Possible macOS update change", "context"
        detail = f"The executable changed while macOS changed from {before_macos} to {after_macos}."
        next_action = "Confirm that the macOS update was expected, then make sure the current signature and Gatekeeper checks still pass."
    elif "sha256" in changed_keys:
        label, priority = "Application contents changed", "review"
        detail = "The executable SHA-256 changed without a matching recorded version change."
        next_action = "Confirm whether the application was updated or reinstalled, then validate the current signer and source."
    elif changed_keys == {"version"}:
        label, priority = "Application version changed", "context"
        detail = (
            f"Version changed from {_change_value('version', before.get('version'))} to "
            f"{_change_value('version', after.get('version'))}."
        )
        next_action = "Confirm that the version change was expected."
    elif trust_recovered:
        label, priority = "Trust check improved", "context"
        detail = "A signature or Gatekeeper check that failed previously now passes."
        next_action = "Confirm whether the application was repaired, replaced, or updated before closing the earlier finding."
    else:
        label, priority = "Application trust evidence changed", "review"
        names = ", ".join(item["label"].lower() for item in changed_fields) or "trust outcome"
        detail = f"Changed evidence: {names}."
        next_action = "Open the current result and compare the changed fields with the expected application identity."
    return {
        "kind": "application-coverage-change" if coverage_reclassification else "changed-application",
        "label": label,
        "priority": priority,
        "title": str(after.get("name") or "Application"),
        "detail": detail,
        "next_action": next_action,
        "changed_fields": changed_fields,
        "finding_id": finding_id,
    }


def analyze_changes(baseline: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    if not baseline:
        return {
            "available": False,
            "baseline_scan_id": None,
            "message": "No earlier scan with the same scope is available yet. This scan can become the baseline.",
            "counts": {}, "highlights": [], "application_changes": [], "comparison_context": {},
        }
    baseline_findings, current_findings = _findings(baseline), _findings(current)
    before_apps, after_apps = _applications(baseline), _applications(current)
    before_macos, after_macos = _platform_version(baseline), _platform_version(current)
    before_tool = str(baseline.get("metadata", {}).get("tool_version") or "").strip()
    after_tool = str(current.get("metadata", {}).get("tool_version") or "").strip()
    tool_version_changed = bool(before_tool and after_tool and before_tool != after_tool)
    comparison_context = {
        "baseline_tool_version": before_tool or None,
        "current_tool_version": after_tool or None,
        "different_tool_versions": tool_version_changed,
        "message": (
            f"These reports were created by macOS Inspector {before_tool} and {after_tool}. "
            "Collector coverage and detection rules can differ, so newly observed evidence does not always mean the system changed."
            if tool_version_changed else ""
        ),
    }
    application_changes: list[dict[str, Any]] = []
    for finding_id in sorted(after_apps.keys() - before_apps.keys()):
        app = after_apps[finding_id]
        priority = _application_change_priority(app)
        application_changes.append({
            "kind": "new-application", "label": "New application", "priority": priority,
            "title": str(app["name"]), "detail": str(app.get("path") or "Application path unavailable"),
            "next_action": (
                "Confirm that this application was installed intentionally, then resolve its current trust result."
                if priority != "context" else
                "Confirm that this application was installed intentionally and review its publisher, source, and activity."
            ),
            "changed_fields": [], "finding_id": finding_id,
        })
    changed_apps = []
    coverage_updates = []
    for finding_id in sorted(after_apps.keys() & before_apps.keys()):
        if after_apps[finding_id]["fingerprint"] != before_apps[finding_id]["fingerprint"]:
            app = after_apps[finding_id]
            change = _application_change(
                before_apps[finding_id], app, finding_id, before_macos, after_macos, tool_version_changed,
            )
            application_changes.append(change)
            if change["kind"] == "application-coverage-change":
                coverage_updates.append(finding_id)
            else:
                changed_apps.append(finding_id)
    highlights = list(application_changes)
    for finding_id in sorted(before_apps.keys() - after_apps.keys()):
        app = before_apps[finding_id]
        highlights.append({
            "kind": "removed-application", "label": "Application no longer present", "priority": "review",
            "title": str(app.get("name") or "Application"),
            "detail": (
                f"{app.get('path')} was present in the earlier scan but was not found in the current application inventory."
                if app.get("path") else
                "The application was present in the earlier scan but was not found in the current application inventory."
            ),
            "next_action": "Confirm that the application was intentionally removed. If not, review recent administrative activity and preserve the earlier report.",
            "changed_fields": [], "finding_id": "",
        })
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
            "application_coverage_changes": len(coverage_updates),
            "removed_applications": len(before_apps.keys() - after_apps.keys()),
            "new_startup_items": len(new_startup_keys),
            "changed_startup_items": len(changed_startup_keys),
            "new_network_listeners": len(after_listeners.keys() - before_listeners.keys()),
            "closed_network_listeners": len(before_listeners.keys() - after_listeners.keys()),
            "changed_controls": len(changed_controls),
            "new_findings": len(new_ids),
            "resolved_findings": len(resolved_ids),
        },
        "highlights": sorted(
            highlights,
            key=lambda item: {"high": 0, "review": 1, "context": 2}.get(str(item.get("priority", "review")), 1),
        )[:50],
        "application_changes": application_changes,
        "comparison_context": comparison_context,
    }


def _process_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[object, ...]] = set()

    def add(row: object, finding_id: str, signal: str) -> None:
        if not isinstance(row, dict) or not row.get("executable"):
            return
        key = (
            finding_id, signal, row.get("pid"), row.get("state"),
            row.get("endpoint"), row.get("executable"),
        )
        if key not in seen:
            seen.add(key)
            rows.append({**row, "finding_id": finding_id, "signal": signal})

    process_finding = _findings(report).get("LIVE-PROCESS-TREE", {})
    process_snapshot = evidence_value(process_finding, "process_snapshot")
    process_key = "running_processes" if isinstance(process_snapshot.get("running_processes"), list) else "review_candidates"
    process_values = process_snapshot.get(process_key, [])
    for row in process_values if isinstance(process_values, list) else []:
        add(row, "LIVE-PROCESS-TREE", "process")

    network_finding = _findings(report).get("LIVE-NETWORK-PROCESSES", {})
    network_snapshot = evidence_value(network_finding, "network_process_snapshot")
    for key in ("listeners", "established", "review_candidates"):
        for row in network_snapshot.get(key, []) if isinstance(network_snapshot.get(key), list) else []:
            add(row, "LIVE-NETWORK-PROCESSES", "network")
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


def _belongs_to_application(executable: object, app_path: str) -> bool:
    """Match only executables inside the exact application bundle path."""
    return bool(app_path and str(executable or "").startswith(f"{app_path}/"))


def _application_activity(
    app_path: str, observed: list[dict[str, Any]], persistence: list[dict[str, Any]],
    coverage: dict[str, bool],
) -> dict[str, Any]:
    """Describe observed app activity without turning activity into a risk verdict."""
    process_rows = [
        row for row in observed
        if row.get("signal") == "process" and _belongs_to_application(row.get("executable"), app_path)
    ]
    network_rows = [
        row for row in observed
        if row.get("signal") == "network" and _belongs_to_application(row.get("executable"), app_path)
    ]
    startup_rows = [
        row for row in persistence
        if _belongs_to_application(row.get("executable"), app_path)
    ]

    processes: dict[str, dict[str, Any]] = {}
    for row in process_rows:
        key = str(row.get("pid") or row.get("executable"))
        processes[key] = {
            "pid": row.get("pid"),
            "state": row.get("stat"),
            "elapsed": row.get("elapsed"),
            "executable": row.get("executable"),
            "finding_id": row.get("finding_id"),
        }
    connections: dict[str, dict[str, Any]] = {}
    for row in network_rows:
        key = f"{row.get('pid')}|{row.get('state')}|{row.get('endpoint')}"
        connections[key] = {
            "pid": row.get("pid"),
            "state": row.get("state"),
            "endpoint": row.get("endpoint"),
            "executable": row.get("executable"),
            "finding_id": row.get("finding_id"),
        }
    startup: dict[str, dict[str, Any]] = {}
    for row in startup_rows:
        key = f"{row.get('finding_id')}|{row.get('executable')}"
        startup[key] = {
            "title": row.get("title"),
            "executable": row.get("executable"),
            "finding_id": row.get("finding_id"),
        }
    running_processes = list(processes.values())[:20]
    network_connections = list(connections.values())[:20]
    startup_items = list(startup.values())[:20]
    counts = {
        "running": len(processes),
        "network": len(connections),
        "startup": len(startup),
    }
    return {
        "running_processes": running_processes,
        "network_connections": network_connections,
        "startup_items": startup_items,
        "counts": counts,
        "coverage": {**coverage, "available": any(coverage.values())},
        "details_truncated": any((
            counts["running"] > len(running_processes),
            counts["network"] > len(network_connections),
            counts["startup"] > len(startup_items),
        )),
        "has_activity": bool(processes or connections or startup),
        "conclusion": "Observed activity provides investigation context. It does not make an application unsafe by itself.",
    }


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
        matched_processes = [row for row in processes if _belongs_to_application(row.get("executable"), app_path)]
        matched_persistence = [row for row in persistence if _belongs_to_application(row.get("executable"), app_path)]
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


def build_user_experience(report: dict[str, Any], guidance: dict[str, Any]) -> dict[str, Any]:
    """Build a concise assessment without turning a rule score into a safety verdict."""
    findings = _findings(report)
    candidates: list[dict[str, Any]] = []
    verdict_rank = {"high-risk": 0, "likely-unwanted": 0, "needs-review": 1, "unable-to-verify": 2}
    for finding_id, guide in guidance.get("findings", {}).items():
        if not isinstance(guide, dict) or finding_id not in findings:
            continue
        investigation = guide.get("investigation", {})
        if isinstance(investigation, dict) and investigation.get("status") in {"Expected", "Resolved"}:
            continue
        verdict = str(guide.get("verdict", "information"))
        if verdict not in verdict_rank:
            continue
        finding = findings[finding_id]
        if verdict == "unable-to-verify":
            not_proof = "An incomplete check is not evidence that the item is malicious or safe."
        elif verdict == "likely-unwanted":
            not_proof = "A rule or indicator match still requires validation before it becomes a security conclusion."
        else:
            not_proof = "This observation raises review priority. It does not prove malware or compromise."
        if finding_id in {"LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"}:
            action_risk = "Reviewing is read-only. Terminating a process can interrupt work or lose unsaved data, so preserve its details first."
        elif finding_id.startswith("APP-TRUST-"):
            action_risk = "Reviewing and rechecking are read-only. Do not delete the application before preserving the evidence you may need."
        else:
            action_risk = "Reviewing the evidence does not change this Mac. Validate the result before changing system settings or removing files."
        next_actions = guide.get("next_actions", [])
        candidates.append({
            "finding_id": finding_id,
            "title": finding.get("title", finding_id),
            "label": guide.get("label", "Review"),
            "verdict": verdict,
            "severity": finding.get("severity", "Informational"),
            "observed": guide.get("simple_explanation") or finding.get("observed_result") or "Evidence was recorded.",
            "why_it_matters": finding.get("why_it_matters") or "Unexpected security-relevant state may require validation.",
            "not_proof": not_proof,
            "verify": next_actions[0] if isinstance(next_actions, list) and next_actions else "Open the result and validate the evidence.",
            "action_risk": action_risk,
        })
    candidates.sort(key=lambda item: (
        verdict_rank[str(item["verdict"])],
        -SEVERITY_RANK.get(str(item["severity"]), 0),
        str(item["title"]),
    ))

    high_priority = any(item["verdict"] in {"high-risk", "likely-unwanted"} for item in candidates)
    review_count = sum(item["verdict"] != "unable-to-verify" for item in candidates)
    unknown_count = sum(item["verdict"] == "unable-to-verify" for item in candidates)
    if high_priority:
        assessment = {
            "id": "action-recommended", "label": "Action recommended",
            "headline": "Review the highest-priority evidence before making changes.",
            "explanation": "At least one result has a high-priority rule outcome. Validate it before containment or removal.",
        }
    elif review_count:
        assessment = {
            "id": "needs-review", "label": "Needs review",
            "headline": f"{review_count} result{'s' if review_count != 1 else ''} need context.",
            "explanation": "The scan found observations that should be checked, but it did not establish compromise.",
        }
    elif unknown_count:
        assessment = {
            "id": "scan-incomplete", "label": "Scan incomplete",
            "headline": "No immediate warning was identified, but some checks did not finish.",
            "explanation": "Do not treat unavailable evidence as a pass. Review the missing checks and rerun them if needed.",
        }
    else:
        assessment = {
            "id": "no-immediate-warning", "label": "No immediate warning identified",
            "headline": "The selected checks did not produce a result that currently needs attention.",
            "explanation": "This is not a guarantee that the Mac is safe. Keep the report as a baseline and investigate unfamiliar behavior.",
        }

    coverage_values = [
        int(value) for value in report.get("summary", {}).get("category_coverage", {}).values()
        if isinstance(value, (int, float))
    ]
    coverage = round(sum(coverage_values) / len(coverage_values)) if coverage_values else 0
    collection_errors = report.get("metadata", {}).get("collection_errors", [])
    coverage_label = "Complete for selected scope" if coverage == 100 and not collection_errors else "Partial for selected scope"
    confidence_levels = [
        str(guidance.get("findings", {}).get(item["finding_id"], {}).get("confidence", {}).get("level", "low"))
        for item in candidates[:3]
    ]
    confidence = "low" if "low" in confidence_levels else "medium" if "medium" in confidence_levels else "high"
    confidence_label = {
        "high": "Strong supporting evidence",
        "medium": "Some supporting evidence is missing",
        "low": "Important evidence is incomplete",
    }[confidence]
    priority_label = "High priority" if high_priority else "Review needed" if review_count else "No immediate priority"
    return {
        "assessment": assessment,
        "next_actions": candidates[:3],
        "axes": {
            "priority": {"label": priority_label, "attention": review_count},
            "coverage": {"label": coverage_label, "percent": coverage, "collection_errors": len(collection_errors)},
            "confidence": {"label": confidence_label, "level": confidence},
        },
        "score_note": "The rule outcome index is not a probability that this Mac is safe or compromised.",
    }


def build_decision_support(
    current: dict[str, Any], baseline: dict[str, Any] | None = None,
    investigations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    guidance = build_guidance(current, investigations)
    for finding_id, finding in _findings(current).items():
        if finding_id in guidance["findings"]:
            guidance["findings"][finding_id]["confidence"] = confidence_for_finding(finding)
    experience = build_user_experience(current, guidance)
    changes = analyze_changes(baseline, current)
    stories = build_stories(current, guidance)
    application_review = build_application_review(current, guidance, changes)
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
        "assessment": experience["assessment"],
        "axes": experience["axes"],
    }
    return {
        "scan_id": current.get("metadata", {}).get("scan_id"),
        "guidance": guidance,
        "changes": changes,
        "stories": stories,
        "application_review": application_review,
        "experience": experience,
        "final_summary": final_summary,
    }


def write_investigation_summary(report: dict[str, Any], decision: dict[str, Any], output: Path) -> Path:
    scan_id = str(report.get("metadata", {}).get("scan_id", "scan"))
    experience = decision.get("experience", {})
    priorities = experience.get("next_actions", [])
    changes = decision["changes"]
    stories = decision["stories"]
    application_review = decision.get("application_review", {})
    state_rows = "".join(
        f"<li><strong>{escape(str(key))}</strong>: {int(value)}</li>"
        for key, value in sorted(decision["final_summary"].get("investigation_states", {}).items())
    )
    priority_rows = "".join(
        f"<article><span>{escape(str(item.get('label', 'Review')))}</span><h3>{escape(str(item.get('title', 'Finding')))}</h3>"
        f"<p>{escape(str(item.get('observed', 'Evidence was recorded.')))}</p>"
        f"<small>Next: {escape(str(item.get('verify', 'Review the finding.')))}</small>"
        f"<small>{escape(str(item.get('not_proof', 'This result requires validation.')))}</small></article>"
        for item in priorities
    ) or "<p>No item currently needs immediate attention.</p>"
    change_rows = "".join(
        f"<article><span>{escape(str(item.get('label', 'Change')))}</span><h3>{escape(str(item.get('title', 'Change')))}</h3>"
        f"<p>{escape(str(item.get('detail', '')))}</p>"
        f"<small>Next: {escape(str(item.get('next_action', 'Review the change against the expected state.')))}</small></article>"
        for item in changes.get("highlights", [])[:20]
    ) or f"<p>{escape(str(changes.get('message', 'No high-signal change was identified.')))}</p>"
    comparison_message = str(changes.get("comparison_context", {}).get("message") or "")
    comparison_html = f"<p><strong>Comparison note:</strong> {escape(comparison_message)}</p>" if comparison_message else ""
    story_rows = "".join(
        f"<article><span>{escape(str(item.get('confidence', 'medium')).title())} confidence correlation</span><h3>{escape(str(item.get('title', 'Investigation story')))}</h3><p>{escape(str(item.get('narrative', '')))}</p></article>"
        for item in stories
    ) or "<p>No multi-signal investigation story was identified.</p>"
    application_rows = ""
    for item in application_review.get("applications", []):
        activity = item.get("activity", {})
        provenance = item.get("provenance", {})
        labels = []
        activity_counts = activity.get("counts", {})
        if activity_counts.get("running"):
            labels.append(f"running processes: {activity_counts['running']}")
        if activity_counts.get("network"):
            labels.append(f"network endpoints: {activity_counts['network']}")
        if activity_counts.get("startup"):
            labels.append(f"startup items: {activity_counts['startup']}")
        if labels:
            activity_html = f"<small>Observed activity: {escape(', '.join(labels))}. Activity alone is not a security verdict.</small>"
        elif activity.get("coverage", {}).get("available"):
            activity_html = "<small>No matching activity was observed in the live or startup evidence collected by this scan.</small>"
        else:
            activity_html = "<small>Activity context was not collected. Include Live Triage or Persistence to correlate behavior.</small>"
        provenance_html = ""
        if provenance:
            publisher = provenance.get("publisher") or "Signing identity unavailable"
            source_hosts = provenance.get("source_hosts", [])
            source = ", ".join(str(host) for host in source_hosts) if source_hosts else "Acquisition source unavailable"
            provenance_html = (
                f"<small>Publisher context: {escape(str(publisher))}. "
                f"Source context: {escape(source)}. These observations do not establish that the publisher or source is trustworthy.</small>"
            )
        application_rows += (
            f"<article><span>{escape(str(item.get('group_label', 'Recorded')))}</span>"
            f"<h3>{escape(str(item.get('name', 'Application')))}</h3>"
            f"<p>{escape(str(item.get('explanation', 'Trust evidence was recorded.')))}</p>"
            f"{provenance_html}{activity_html}<small>{escape(str(item.get('path', 'Location unavailable')))}</small></article>"
        )
    application_rows = application_rows or "<p>No Application Trust result is present in this scan.</p>"
    hostname = escape(str(report.get("metadata", {}).get("hostname", "unknown")))
    target = str(report.get("metadata", {}).get("target_application", ""))
    target_html = f"<p>Target application: {escape(target)}</p>" if target else ""
    application_section = f"<section><h2>Application review queue</h2><p>{escape(str(application_review.get('conclusion', 'Trust observations require context.')))}</p>{application_rows}</section>" if application_review.get("available") else ""
    assessment = experience.get("assessment", {})
    axes = experience.get("axes", {})
    priority_axis = axes.get("priority", {})
    coverage_axis = axes.get("coverage", {})
    confidence_axis = axes.get("confidence", {})
    html = f"""<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Investigation summary {escape(scan_id)}</title><style>body{{margin:0;background:#0d1422;color:#edf3ff;font:15px/1.55 -apple-system,BlinkMacSystemFont,sans-serif}}main{{max-width:980px;margin:auto;padding:32px 18px 64px}}header,section{{margin-bottom:18px;padding:22px;border:1px solid #283954;border-radius:14px;background:#111b2d}}h1,h2,h3,p,small{{overflow-wrap:anywhere}}h1{{font-size:30px}}h2{{font-size:19px}}h3{{margin:5px 0;font-size:15px}}small,p,li{{color:#aebbd0}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px}}.metrics div,article{{padding:13px;border:1px solid #283954;border-radius:10px;background:#16233a}}.metrics strong{{display:block;font-size:18px}}article{{margin-top:9px}}article span{{color:#78aaff;font-size:11px;text-transform:uppercase}}article small{{display:block;margin-top:7px}}@media print{{body{{background:white;color:#111}}header,section,article,.metrics div{{background:white;border-color:#bbb}}small,p,li{{color:#333}}}}</style></head><body><main><header><small>MACOS INSPECTOR | INVESTIGATION SUMMARY</small><h1>{escape(str(assessment.get('label', decision['final_summary']['headline'])))}</h1><p>{escape(str(assessment.get('headline', decision['final_summary']['headline'])))}</p><p>Scan {escape(scan_id)} | Host {hostname}</p>{target_html}<p>{escape(str(decision['final_summary']['conclusion']))}</p></header><section><h2>Current assessment</h2><div class=\"metrics\"><div><strong>{escape(str(priority_axis.get('label', 'Not calculated')))}</strong>review priority</div><div><strong>{escape(str(coverage_axis.get('percent', 0)))}%</strong>{escape(str(coverage_axis.get('label', 'coverage unknown')))}</div><div><strong>{escape(str(confidence_axis.get('label', 'Not calculated')))}</strong>evidence confidence</div></div><p>{escape(str(experience.get('score_note', 'Priority, coverage, and confidence answer different questions.')))}</p></section>{application_section}<section><h2>What to do next</h2>{priority_rows}</section><section><h2>Changes since the previous comparable scan</h2>{comparison_html}{change_rows}</section><section><h2>Correlated investigation stories</h2>{story_rows}</section><section><h2>Investigation state</h2><ul>{state_rows}</ul><p>Technical evidence remains in the original signed or exported scan report.</p></section></main></body></html>"""
    path = output / f"macos-inspector-{scan_id}-investigation-summary.html"
    secure_write_text(path, html)
    return path
