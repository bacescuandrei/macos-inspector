from __future__ import annotations

import hashlib
import json
from pathlib import Path

from macos_inspector import __version__
from macos_inspector.collectors.application_trust import SignatureDetails, classify_trust
from macos_inspector.core.io import read_bytes_limited
from macos_inspector.core.response_history import evaluate_response_recheck
from macos_inspector.core.runner import CommandResult


DEFAULT_SCENARIOS = Path(__file__).with_name("validation-scenarios.json")


def evaluate_scenario(case: dict) -> str:
    if case["kind"] == "trust":
        signature = CommandResult(("codesign",), case["signature_rc"], "", case.get("signature_output", ""), case.get("signature_timed_out", False))
        gatekeeper = CommandResult(("spctl",), case["gatekeeper_rc"], "", case.get("gatekeeper_output", "accepted"))
        details = SignatureDetails(signature_type=case.get("signature_type", "Developer ID"),
            authority=case.get("authority", "Example Publisher"), identifier=case.get("identifier", "org.example.fixture"))
        return classify_trust(case.get("executable_exists", True), signature, gatekeeper, details)[1]
    if case["kind"] != "response":
        raise ValueError("Unsupported scenario kind")
    action = {"pid": 4242, "uid": 501, "process_start": "synthetic-start", "executable": "/synthetic/tool",
              "hostname": "synthetic-host", "timestamp": "2026-01-01T00:00:00Z"}
    row = dict(action)
    state = case["state"]
    if state == "reused":
        row["process_start"] = "different-start"
    if state == "zombie":
        row["zombie"] = True
    if state == "legacy":
        row.pop("process_start")
    if state in {"other_pid", "other_owner"}:
        row["pid"] = 5000
    if state == "other_owner":
        row["uid"] = 502
    rows = [] if state in {"absent", "truncated"} else [row]
    if state == "duplicate_pid":
        rows.append(dict(row))
    metadata = {"hostname": "synthetic-host", "started_at": "2026-01-01T00:01:00Z",
                "completed_at": "2026-01-01T00:02:00Z", "collection_errors": []}
    if state == "prior_scan":
        metadata.update(started_at="2025-12-31T23:58:00Z", completed_at="2025-12-31T23:59:00Z")
    if state == "overlapping_scan":
        metadata["started_at"] = "2025-12-31T23:59:00Z"
    if state == "different_host":
        metadata["hostname"] = "other-synthetic-host"
    if state == "naive_time":
        metadata["started_at"] = "2026-01-01T00:01:00"
    report = {"metadata": metadata, "findings": [{"finding_id": "LIVE-PROCESS-TREE", "status": "Observed", "evidence": [{"kind": "process_snapshot",
        "collected_at": None if state == "missing_snapshot_time" else "2026-01-01T00:01:30Z",
        "value": {"running_processes": rows, "process_count": len(rows), "inventory_complete": True, "snapshot_truncated": state == "truncated"}}]}]}
    return evaluate_response_recheck(action, report)[0]


def validate_detections(path: Path = DEFAULT_SCENARIOS) -> dict:
    raw = read_bytes_limited(path, 1024 * 1024)
    payload = json.loads(raw)
    if payload.get("schema_version") != 1 or not isinstance(payload.get("scenarios"), list) or len(payload["scenarios"]) > 1000:
        raise ValueError("Unsupported or oversized validation scenario set")
    cases = payload["scenarios"]
    results = [{"id": case["id"], "kind": case["kind"], "expected": case["expected"], "observed": evaluate_scenario(case)} for case in cases]
    for row in results:
        row["passed"] = row["expected"] == row["observed"]
    alerts = {"Fail", "Review", "Match"}
    return {"tool_version": __version__, "scenario_sha256": hashlib.sha256(raw).hexdigest(), "scenario_count": len(results),
        "passed": sum(row["passed"] for row in results), "failed": sum(not row["passed"] for row in results),
        "false_alerts_in_expected_pass_cases": sum(row["kind"] == "trust" and row["expected"] == "Pass" and row["observed"] in alerts for row in results),
        "missed_review_in_declared_review_cases": sum(row["kind"] == "trust" and row["expected"] in alerts and row["observed"] not in alerts for row in results),
        "limitation": "Synthetic regression fixtures only. These counts are not real-world malware sensitivity, specificity, or an independent product evaluation.",
        "results": results}
