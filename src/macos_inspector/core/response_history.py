from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
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
                    actions[action_id] = {key: item.get(key) for key in ("pid", "uid", "process_start", "hostname", "mode", "signal", "status")}
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
    if not isinstance(action, dict) or not isinstance(report, dict):
        return unknown
    if (type(action.get("pid")) is not int or action["pid"] <= 1
            or type(action.get("uid")) is not int or action["uid"] < 0
            or not isinstance(action.get("process_start"), str) or not action["process_start"].strip()
            or not isinstance(action.get("executable"), str) or not action["executable"].startswith("/")):
        return unknown
    metadata = report.get("metadata")
    if (not isinstance(metadata, dict) or not isinstance(action.get("hostname"), str)
            or not action["hostname"].strip() or metadata.get("hostname") != action["hostname"]):
        return "unable_to_verify", "The action and follow-up do not have matching recorded host context. Legacy logs without a host remain unverifiable; hostnames are not authenticated identities."
    action_time = _recorded_time(action.get("timestamp"))
    started = _recorded_time(metadata.get("started_at"))
    completed = _recorded_time(metadata.get("completed_at"))
    if action_time is None or started is None or completed is None or started < action_time or completed < started:
        return "unable_to_verify", "The follow-up needs a valid, timezone-aware collection window starting after the recorded signal. A prior or overlapping scan cannot establish the later outcome."
    findings = report.get("findings")
    if not isinstance(findings, (list, tuple)) or any(not isinstance(row, dict) for row in findings):
        return unknown
    matches = [row for row in findings if row.get("finding_id") == "LIVE-PROCESS-TREE"]
    if len(matches) != 1:
        return unknown
    finding = matches[0]
    evidence = finding.get("evidence")
    if not isinstance(evidence, (list, tuple)) or any(not isinstance(item, dict) for item in evidence):
        return unknown
    snapshots = [item for item in evidence if item.get("kind") == "process_snapshot"]
    if len(snapshots) != 1:
        return unknown
    snapshot = snapshots[0].get("value")
    collected = _recorded_time(snapshots[0].get("collected_at"))
    if collected is None or not started <= collected <= completed:
        return "unable_to_verify", "The process snapshot has no valid collection time within the later scan. Repeat Live Triage before interpreting the outcome."
    if not isinstance(snapshot, dict) or finding.get("status") not in {"Pass", "Review", "Observed"}:
        return unknown
    rows = snapshot.get("running_processes")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return unknown
    pids = [row.get("pid") for row in rows]
    if any(type(pid) is not int or pid < 1 for pid in pids) or len(set(pids)) != len(pids):
        return "unable_to_verify", "The later process inventory contains invalid or duplicate PIDs. Repeat Live Triage; conflicting identities cannot establish an outcome."
    current = next((row for row in rows if row.get("pid") == action["pid"]), None)
    if current:
        if (not isinstance(current.get("process_start"), str) or not current["process_start"].strip()
                or type(current.get("uid")) is not int or current["uid"] < 0
                or not isinstance(current.get("executable"), str) or not current["executable"].startswith("/")):
            return unknown
        if any(current.get(key) != action.get(key) for key in ("uid", "process_start", "executable")):
            return "pid_reused", "The PID is present with a different recorded identity. This is not the original process; do not repeat an action from the old report."
        if current.get("zombie") is True or "Z" in str(current.get("stat", "")).upper():
            return "zombie_observed", "The same process identity is now a zombie. It has exited but its parent has not reaped it. Another signal will not help."
        return "still_observed", "The same process identity was still observed in the later snapshot. Review its current activity before considering another action."
    if (snapshot.get("snapshot_truncated") is not False or snapshot.get("inventory_complete") is not True
            or type(snapshot.get("process_count")) is not int or snapshot["process_count"] != len(rows)):
        return unknown
    errors = metadata.get("collection_errors")
    if not isinstance(errors, (list, tuple)) or any(not isinstance(error, str) or error.startswith("live-triage:") for error in errors):
        return unknown
    same_executable = [row for row in rows if type(row.get("uid")) is int
                       and row["uid"] == action["uid"] and row.get("executable") == action["executable"]]
    if same_executable:
        shown = ", ".join(str(row["pid"]) for row in same_executable[:5])
        extra = f" and {len(same_executable) - 5} more" if len(same_executable) > 5 else ""
        return "executable_observed", f"The original PID was not observed, but the same executable path and owner were recorded under PID(s) {shown}{extra}. These may be existing instances or a restart; the snapshot does not prove which. A matching path does not establish identical file contents or malicious activity. Review the later snapshot; no further signal is automatic."
    return "not_observed", "The original PID was not observed in this later complete process snapshot. This does not prove that related activity stopped or that the finding is resolved."


def _recorded_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None
    except ValueError:
        return None
