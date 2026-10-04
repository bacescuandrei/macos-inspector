from __future__ import annotations

import os
import signal
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from macos_inspector.collectors.live_triage import parse_processes, parse_process_starts
from macos_inspector.core.runner import CommandRunner


PROCESS_FINDINGS = {"LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"}
PROCESS_CANDIDATE_KEYS = ("review_candidates",)
MAX_RESPONSE_SNAPSHOT_AGE_SECONDS = 15 * 60


def review_process_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return unique process candidates explicitly surfaced by Live Triage."""
    candidates: dict[int, dict[str, Any]] = {}
    for finding in report.get("findings", []):
        if not isinstance(finding, dict) or finding.get("finding_id") not in PROCESS_FINDINGS:
            continue
        if finding.get("status") != "Review":
            continue
        for evidence in finding.get("evidence", []):
            value = evidence.get("value") if isinstance(evidence, dict) else None
            if not isinstance(value, dict):
                continue
            for key in PROCESS_CANDIDATE_KEYS:
                rows = value.get(key, [])
                if not isinstance(rows, list):
                    continue
                for row in rows:
                    if not isinstance(row, dict) or isinstance(row.get("pid"), bool):
                        continue
                    try:
                        pid = int(row["pid"])
                    except (KeyError, TypeError, ValueError):
                        continue
                    if pid > 1 and isinstance(row.get("executable"), str):
                        candidates.setdefault(pid, {**row, "snapshot_at": evidence.get("collected_at")})
    return [candidates[pid] for pid in sorted(candidates)]


def inspect_process(pid: int, runner: CommandRunner | None = None) -> dict[str, Any] | None:
    command_runner = runner or CommandRunner(timeout=3)
    result = command_runner.run(("ps", "-p", str(pid), "-o", "pid=,ppid=,uid=,user=,stat=,comm="))
    if result.returncode not in {0, 1}:
        raise RuntimeError(result.stderr or "Current process identity could not be verified.")
    current = next((item for item in parse_processes(result.stdout) if item.get("pid") == pid), None)
    if current is None:
        return None
    start_result = command_runner.run(("ps", "-p", str(pid), "-o", "pid=,lstart="))
    if start_result.returncode != 0:
        raise RuntimeError(start_result.stderr or "Current process start time could not be verified.")
    current["process_start"] = parse_process_starts(start_result.stdout).get(pid)
    return current


def terminate_reported_process(
    report: dict[str, Any],
    pid: int,
    mode: str,
    *,
    runner: CommandRunner | None = None,
    kill_process: Callable[[int, int], None] = os.kill,
    effective_uid: int | None = None,
    protected_pids: set[int] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Signal a current-user process only when it still matches a reported review candidate."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        raise ValueError("Process ID must be an integer greater than 1.")
    if mode not in {"terminate", "kill"}:
        raise ValueError("Process action must be terminate or kill.")

    uid = os.geteuid() if effective_uid is None else effective_uid
    if uid == 0:
        raise PermissionError("Process response is disabled when the dashboard runs as root.")
    protected = protected_pids if protected_pids is not None else {1, os.getpid(), os.getppid()}
    if pid in protected:
        raise PermissionError("The dashboard and its parent process are protected from termination.")

    candidate = next((item for item in review_process_candidates(report) if int(item["pid"]) == pid), None)
    if candidate is None:
        raise PermissionError("The process is not an authorized Live Triage review candidate.")
    candidate_uid = candidate.get("uid")
    if isinstance(candidate_uid, bool) or not isinstance(candidate_uid, int):
        raise ValueError("The report does not contain a numeric process owner. Run Live Triage again.")
    if candidate_uid != uid:
        raise PermissionError("Only processes owned by the dashboard user can be terminated.")
    process_start = candidate.get("process_start")
    if not isinstance(process_start, str) or not process_start.strip():
        raise RuntimeError("The report has no process start identity. Run Live Triage again before acting.")
    snapshot_at = candidate.get("snapshot_at")
    try:
        snapshot_time = datetime.fromisoformat(str(snapshot_at).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("The Live Triage snapshot has no valid timestamp. Run Live Triage again.") from exc
    if snapshot_time.tzinfo is None:
        raise RuntimeError("The Live Triage snapshot has no timezone. Run Live Triage again.")
    clock = now or datetime.now(timezone.utc)
    age = (clock - snapshot_time).total_seconds()
    if age < -30 or age > MAX_RESPONSE_SNAPSHOT_AGE_SECONDS:
        raise RuntimeError("The Live Triage snapshot is too old or has an invalid time. Run Live Triage again.")
    if bool(candidate.get("zombie")) or "Z" in str(candidate.get("stat", "")).upper():
        raise RuntimeError("A zombie has already exited and cannot receive another signal. Review its parent process instead.")

    current = inspect_process(pid, runner)
    if current is None:
        raise ProcessLookupError("The process is no longer running.")
    if (
        current.get("uid") != candidate_uid
        or current.get("executable") != candidate.get("executable")
        or current.get("ppid") != candidate.get("ppid")
        or current.get("process_start") != process_start
    ):
        raise RuntimeError("The PID now belongs to a different process. Run Live Triage again before acting.")
    if bool(current.get("zombie")) or "Z" in str(current.get("stat", "")).upper():
        raise RuntimeError("The process is now a zombie and cannot receive another signal. Review its parent process instead.")

    selected_signal = signal.SIGTERM if mode == "terminate" else signal.SIGKILL
    kill_process(pid, selected_signal)
    return {
        "pid": pid,
        "mode": mode,
        "signal": signal.Signals(selected_signal).name,
        "executable": str(candidate["executable"]),
        "uid": candidate_uid,
        "process_start": process_start,
        "status": "signal_sent",
    }
