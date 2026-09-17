from __future__ import annotations

import os
import signal
from collections.abc import Callable
from typing import Any

from macos_inspector.collectors.live_triage import parse_processes
from macos_inspector.core.runner import CommandRunner


PROCESS_FINDINGS = {"LIVE-PROCESS-TREE", "LIVE-NETWORK-PROCESSES"}
PROCESS_CANDIDATE_KEYS = ("review_candidates",)


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
                        candidates.setdefault(pid, row)
    return [candidates[pid] for pid in sorted(candidates)]


def inspect_process(pid: int, runner: CommandRunner | None = None) -> dict[str, Any] | None:
    command_runner = runner or CommandRunner(timeout=3)
    result = command_runner.run(("ps", "-p", str(pid), "-o", "pid=,ppid=,uid=,user=,stat=,comm="))
    if result.returncode not in {0, 1}:
        raise RuntimeError(result.stderr or "Current process identity could not be verified.")
    return next((item for item in parse_processes(result.stdout) if item.get("pid") == pid), None)


def terminate_reported_process(
    report: dict[str, Any],
    pid: int,
    mode: str,
    *,
    runner: CommandRunner | None = None,
    kill_process: Callable[[int, int], None] = os.kill,
    effective_uid: int | None = None,
    protected_pids: set[int] | None = None,
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
    if bool(candidate.get("zombie")) or "Z" in str(candidate.get("stat", "")).upper():
        raise RuntimeError("A zombie has already exited and cannot receive another signal. Review its parent process instead.")

    current = inspect_process(pid, runner)
    if current is None:
        raise ProcessLookupError("The process is no longer running.")
    if current.get("uid") != candidate_uid or current.get("executable") != candidate.get("executable"):
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
        "status": "signal_sent",
    }
