from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .io import read_bytes_limited


MAX_RESPONSE_LOG_BYTES = 4 * 1024 * 1024


def append_response_event(directory: Path, record: dict) -> None:
    """Append under the dashboard lock; retain one previous bounded log."""
    path = directory / "response-actions.jsonl"
    if path.is_file() and path.stat().st_size >= MAX_RESPONSE_LOG_BYTES:
        previous = directory / "response-actions.previous.jsonl"
        previous.unlink(missing_ok=True)
        os.replace(path, previous)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        data = (json.dumps(record, ensure_ascii=False) + "\n").encode()
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_response_history(directory: Path) -> dict:
    actions, checks, limitations = {}, {}, []
    for name in ("response-actions.previous.jsonl", "response-actions.jsonl"):
        try:
            lines = read_bytes_limited(directory / name, MAX_RESPONSE_LOG_BYTES + 65536).decode().splitlines()
        except FileNotFoundError:
            continue
        except (OSError, ValueError, UnicodeError):
            limitations.append(f"{name} could not be read within the safety limit.")
            continue
        for line in lines:
            try:
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("Invalid event")
                if item.get("event") == "recheck":
                    if not all(isinstance(item.get(key), str) for key in ("action_id", "scan_id", "timestamp", "outcome", "explanation")):
                        raise ValueError("Invalid recheck")
                    checks[item["action_id"]] = {key: item[key][:2048] for key in ("scan_id", "timestamp", "outcome", "explanation")}
                elif item.get("status") == "signal_sent":
                    if type(item.get("pid")) is not int or item["pid"] <= 1 or item.get("signal") not in {"SIGTERM", "SIGKILL"}:
                        raise ValueError("Invalid action")
                    if not all(isinstance(item.get(key), str) for key in ("scan_id", "timestamp", "executable")):
                        raise ValueError("Invalid identity")
                    action_id = item.get("action_id") or hashlib.sha256(line.encode()).hexdigest()
                    if not isinstance(action_id, str) or len(action_id) > 64:
                        raise ValueError("Invalid action ID")
                    actions[action_id] = {key: item.get(key) for key in ("pid", "uid", "process_start", "mode", "signal", "status")}
                    actions[action_id].update({key: item[key][:2048] for key in ("scan_id", "timestamp", "executable")})
                    actions[action_id]["action_id"] = action_id
            except (ValueError, TypeError):
                if "Malformed local log entries were skipped." not in limitations:
                    limitations.append("Malformed local log entries were skipped.")
    ordered = sorted(actions.values(), key=lambda row: row["timestamp"], reverse=True)
    for row in ordered[:50]:
        row["recheck"] = checks.get(row["action_id"])
    return {"actions": ordered[:50], "retained_action_count": len(ordered), "limitations": limitations,
            "note": "Local response records are not tamper-proof. Sending a signal does not confirm exit or resolve an investigation. One previous log is retained; up to 50 recent actions are shown."}


def evaluate_response_recheck(action: dict, report: dict) -> tuple[str, str]:
    """Describe a later bounded snapshot without claiming causality or remediation."""
    unknown = ("unable_to_verify", "The later snapshot cannot establish this process identity or absence. Review collection gaps and repeat Live Triage.")
    if not action.get("process_start") or type(action.get("uid")) is not int:
        return unknown
    finding = next((row for row in report.get("findings", []) if row.get("finding_id") == "LIVE-PROCESS-TREE"), {})
    snapshot = next((item.get("value") for item in finding.get("evidence", []) if item.get("kind") == "process_snapshot"), None)
    if not isinstance(snapshot, dict) or finding.get("status") not in {"Pass", "Review"}:
        return unknown
    rows = snapshot.get("running_processes")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return unknown
    current = next((row for row in rows if row.get("pid") == action["pid"]), None)
    if current:
        if not current.get("process_start") or type(current.get("uid")) is not int:
            return unknown
        if any(current.get(key) != action.get(key) for key in ("uid", "process_start", "executable")):
            return "pid_reused", "The PID is present with a different recorded identity. This is not the original process; do not repeat an action from the old report."
        if current.get("zombie") or "Z" in str(current.get("stat", "")).upper():
            return "zombie_observed", "The same process identity is now a zombie. It has exited but its parent has not reaped it. Another signal will not help."
        return "still_observed", "The same process identity was still observed in the later snapshot. Review its current activity before considering another action."
    if snapshot.get("snapshot_truncated") is not False or type(snapshot.get("process_count")) is not int or snapshot["process_count"] != len(rows):
        return unknown
    if any(str(error).startswith("live-triage:") for error in report.get("metadata", {}).get("collection_errors", [])):
        return unknown
    return "not_observed", "The original PID was not observed in this later complete process snapshot. This does not prove that related activity stopped or that the finding is resolved."
