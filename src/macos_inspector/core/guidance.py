from __future__ import annotations

import hashlib
import json
from typing import Any


SEVERITY_RANK = {
    "Informational": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def _evidence(finding: dict[str, Any], kind: str) -> dict[str, Any]:
    for item in finding.get("evidence", []):
        if isinstance(item, dict) and item.get("kind") == kind and isinstance(item.get("value"), dict):
            return item["value"]
    return {}


def _process_identities(finding: dict[str, Any]) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    for item in finding.get("evidence", []):
        if not isinstance(item, dict) or not isinstance(item.get("value"), dict):
            continue
        candidates = item["value"].get("review_candidates", [])
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            identities.append({
                "uid": candidate.get("uid"),
                "user": candidate.get("user"),
                "executable": candidate.get("executable"),
                "reason": candidate.get("reason"),
                "priority": candidate.get("priority"),
                "zombie": bool(candidate.get("zombie", False)),
            })
    return identities


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Fingerprint the security identity of a finding without volatile timestamps or PIDs."""
    identity: dict[str, Any] = {
        "finding_id": finding.get("finding_id"),
        "severity": finding.get("severity"),
        "status": finding.get("status"),
    }
    finding_id = str(finding.get("finding_id", ""))
    if finding_id.startswith("APP-TRUST-"):
        app = _evidence(finding, "application_bundle")
        signature = _evidence(finding, "code_signature")
        executable = _evidence(finding, "executable_integrity")
        gatekeeper = _evidence(finding, "gatekeeper_assessment")
        identity["application"] = {
            "bundle_identifier": app.get("bundle_identifier"),
            "version": app.get("version"),
            "executable": app.get("executable"),
            "team_identifier": signature.get("team_identifier"),
            "signature_valid": signature.get("valid"),
            "signature_type": signature.get("signature_type"),
            "hardened_runtime": signature.get("hardened_runtime"),
            "sha256": executable.get("sha256"),
            "gatekeeper_accepted": gatekeeper.get("accepted"),
            "notarized": gatekeeper.get("notarized"),
        }
    elif finding_id in {"LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"}:
        identity["processes"] = _process_identities(finding)
    else:
        identity["observed_result"] = finding.get("observed_result")
        identity["evidence"] = [
            {"kind": item.get("kind"), "source": item.get("source"), "value": item.get("value")}
            for item in finding.get("evidence", [])
            if isinstance(item, dict)
        ]
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verdict(finding: dict[str, Any]) -> tuple[str, str]:
    status = str(finding.get("status", "")).lower()
    severity = SEVERITY_RANK.get(str(finding.get("severity", "")), 0)
    category = str(finding.get("category", "")).lower()
    finding_id = str(finding.get("finding_id", "")).lower()
    if status == "unknown":
        return "unable-to-verify", "Unable to verify"
    if status in {"pass", "not applicable"}:
        return "looks-normal", "Looks normal"
    indicator_result = "ioc" in category or "yara" in category or "ioc" in finding_id or "yara" in finding_id
    if indicator_result and status == "match" and severity >= 2:
        return "indicator-match", "Indicator match to validate"
    if status == "fail" and severity >= 3:
        if finding_id.startswith("app-trust-"):
            return "high-priority", "High-priority trust issue"
        return "high-priority", "High-priority finding"
    if status in {"fail", "review", "match"} or severity >= 2:
        return "needs-review", "Needs review"
    return "information", "Information"


def _next_actions(finding: dict[str, Any], verdict: str) -> list[str]:
    finding_id = str(finding.get("finding_id", ""))
    if verdict == "unable-to-verify":
        return [
            "Open the technical details to see what could not be checked.",
            "Grant only the macOS permission needed for this check, then run it again.",
        ]
    if verdict == "looks-normal":
        return ["No immediate action is required. Review the technical details if this item is unfamiliar."]
    if verdict == "information":
        return ["This is recorded context. No action is required unless the item is unfamiliar or unexpected."]
    if finding_id.startswith("APP-TRUST-"):
        return [
            "Confirm that you installed this application and recognize its publisher.",
            "Review the signature, Gatekeeper result, permissions, and executable hash.",
            "Reinstall from the publisher if integrity checks fail or the source is uncertain.",
        ]
    if finding_id in {"LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"}:
        return [
            "Review the executable path, owner, parent process, and network activity.",
            "Preserve the process details before containment.",
            "Terminate only when the process is unexpected, then run Live Triage again.",
        ]
    return [
        "Read why this item was flagged and confirm whether it is expected on this Mac.",
        "Review the evidence before changing or removing anything.",
        "Run the same audit again after any remediation.",
    ]


def _simple_explanation(finding: dict[str, Any], verdict: str) -> str:
    finding_id = str(finding.get("finding_id", ""))
    observed = str(finding.get("observed_result") or finding.get("description") or "No explanation is available.")
    if finding_id.startswith("APP-TRUST-"):
        if verdict == "looks-normal":
            return "The available signature and macOS policy checks did not identify a trust problem."
        if verdict == "unable-to-verify":
            return "One or more application trust checks could not be completed."
        lowered = observed.lower()
        if "world-writable" in lowered:
            return "macOS accepts this app, but one or more app files can be modified by other local users."
        if "sealed resources" in lowered or "signature" in lowered and "invalid" in lowered:
            return "The app failed an integrity check because signed files are missing, changed, or invalid."
        if "gatekeeper did not accept" in lowered:
            return "macOS Gatekeeper did not accept this app. Confirm where it came from before opening it."
        return "This app has a trust or integrity result that needs validation before you rely on it."
    if finding_id in {"LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"}:
        if verdict == "information":
            return "Running processes and network activity were recorded. No high-priority candidate was identified."
        if verdict == "unable-to-verify":
            return "Some live process or network information could not be checked."
        return "One or more running processes need validation before any containment action."
    return observed


def _context(finding: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(finding.get("finding_id", ""))
    if finding_id.startswith("APP-TRUST-"):
        app = _evidence(finding, "application_bundle")
        signature = _evidence(finding, "code_signature")
        executable = _evidence(finding, "executable_integrity")
        gatekeeper = _evidence(finding, "gatekeeper_assessment")
        return {
            "kind": "application",
            "name": app.get("name"),
            "version": app.get("version"),
            "path": next((item.get("source") for item in finding.get("evidence", []) if isinstance(item, dict) and item.get("kind") == "application_bundle"), None),
            "publisher_team_id": signature.get("team_identifier"),
            "signature_valid": signature.get("valid"),
            "gatekeeper_accepted": gatekeeper.get("accepted"),
            "executable_sha256": executable.get("sha256"),
        }
    if finding_id in {"LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"}:
        return {"kind": "process", "candidates": _process_identities(finding)}
    return {"kind": "general"}


def build_guidance(report: dict[str, Any], investigations: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    investigations = investigations or {}
    findings = [item for item in report.get("findings", []) if isinstance(item, dict)]
    guided: dict[str, dict[str, Any]] = {}
    attention: list[dict[str, Any]] = []
    normal = 0
    unknown = 0
    observations = 0
    for finding in findings:
        finding_id = str(finding.get("finding_id", ""))
        verdict, label = _verdict(finding)
        investigation = investigations.get(finding_id, {"status": "New", "current": True, "note": ""})
        item = {
            "verdict": verdict,
            "label": label,
            "simple_explanation": _simple_explanation(finding, verdict),
            "next_actions": _next_actions(finding, verdict),
            "context": _context(finding),
            "investigation": investigation,
        }
        guided[finding_id] = item
        state = str(investigation.get("status", "New"))
        if verdict == "looks-normal" or state in {"Expected", "Resolved"}:
            normal += 1
        elif verdict == "unable-to-verify":
            unknown += 1
        elif verdict != "information":
            attention.append({
                "finding_id": finding_id,
                "title": finding.get("title", finding_id),
                "severity": finding.get("severity", "Informational"),
                "verdict": verdict,
                "label": label,
                "next_action": item["next_actions"][0],
            })
        else:
            observations += 1
    attention.sort(key=lambda item: (-SEVERITY_RANK.get(str(item["severity"]), 0), str(item["title"])))
    if attention:
        headline = f"{len(attention)} item{'s' if len(attention) != 1 else ''} need your attention."
    elif unknown:
        headline = "No immediate concern was found, but some checks could not be completed."
    else:
        headline = "No item currently needs your attention."
    return {
        "scan_id": report.get("metadata", {}).get("scan_id"),
        "headline": headline,
        "plain_language_note": "A review result is a reason to investigate, not proof of malware.",
        "counts": {"attention": len(attention), "unable_to_verify": unknown, "looks_normal_or_resolved": normal, "recorded_observations": observations},
        "priorities": attention[:5],
        "workflow": ["Detect", "Understand", "Validate", "Preserve", "Contain", "Rescan", "Close"],
        "findings": guided,
    }
