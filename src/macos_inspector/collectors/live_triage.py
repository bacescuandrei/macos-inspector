from __future__ import annotations

import hashlib
from pathlib import Path

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


MAX_PROCESSES = 4_000
MAX_CONNECTIONS = 8_000
MAX_EXECUTABLE_HASH_BYTES = 64 * 1024 * 1024
WRITABLE_EXECUTION_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/")


def parse_processes(text: str) -> list[dict[str, object]]:
    processes = []
    for line in text.splitlines()[:MAX_PROCESSES]:
        parts = line.strip().split(None, 3)
        if len(parts) != 4:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        processes.append({"pid": pid, "ppid": ppid, "user": parts[2], "executable": parts[3]})
    return processes


def parse_lsof_fields(text: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    current: dict[str, object] = {}
    endpoint: dict[str, str] | None = None

    def flush_endpoint() -> None:
        nonlocal endpoint
        if endpoint and current.get("pid") is not None:
            records.append({**current, **endpoint})
        endpoint = None

    for raw in text.splitlines():
        if not raw:
            continue
        field, value = raw[0], raw[1:]
        if field == "p":
            flush_endpoint()
            try:
                current = {"pid": int(value)}
            except ValueError:
                current = {}
        elif field == "c":
            current["command"] = value
        elif field == "n":
            flush_endpoint()
            endpoint = {"endpoint": value, "state": ""}
        elif field == "T" and endpoint is not None and value.startswith("ST="):
            endpoint["state"] = value[3:]
    flush_endpoint()
    return records[:MAX_CONNECTIONS]


def _hash_executable(path: str) -> str | None:
    try:
        candidate = Path(path)
        if not candidate.is_file() or candidate.stat().st_size > MAX_EXECUTABLE_HASH_BYTES:
            return None
        digest = hashlib.sha256()
        with candidate.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def suspicious_processes(processes: list[dict[str, object]]) -> list[dict[str, object]]:
    pids = {int(item["pid"]) for item in processes}
    home = str(Path.home()) + "/"
    rows = []
    for item in processes:
        executable = str(item["executable"])
        reasons = []
        if executable.startswith(WRITABLE_EXECUTION_PREFIXES):
            reasons.append("executes from a shared temporary or writable directory")
        if "/." in executable and executable.startswith(home):
            reasons.append("executes from a hidden path in the user profile")
        if str(item["user"]) == "root" and executable.startswith(home):
            reasons.append("root process executes from a user-profile path")
        ppid = int(item["ppid"])
        if ppid not in {0, 1} and ppid not in pids:
            reasons.append("parent process is not present in this point-in-time snapshot")
        if reasons:
            rows.append({**item, "reasons": reasons, "sha256": _hash_executable(executable)})
    return rows[:200]


class LiveTriageCollector(Collector):
    collector_id = "live-triage"
    title = "Live incident triage"
    description = "Snapshots running processes, parent relationships, listeners and active network connections."

    def collect(self) -> list[Finding]:
        process_result = self.runner.run(("ps", "-axo", "pid=,ppid=,user=,comm="))
        network_result = self.runner.run(("lsof", "-nP", "-i", "-FpcnT"))
        processes = parse_processes(process_result.stdout) if process_result.returncode == 0 else []
        connections = parse_lsof_fields(network_result.stdout) if network_result.returncode in {0, 1} else []
        suspicious = suspicious_processes(processes)
        by_pid = {int(item["pid"]): item for item in processes}
        correlated = [{**row, "executable": by_pid.get(int(row["pid"]), {}).get("executable", "unknown")} for row in connections]
        suspicious_pids = {int(item["pid"]) for item in suspicious}
        suspicious_connections = [row for row in correlated if int(row["pid"]) in suspicious_pids]
        return [
            self._process_finding(process_result.command, processes, suspicious, process_result.stderr),
            self._network_finding(network_result.command, correlated, suspicious_connections, network_result.stderr),
        ]

    def _process_finding(self, command: str, processes: list[dict], suspicious: list[dict], error: str) -> Finding:
        available = bool(processes)
        return Finding(
            finding_id="LIVE-PROCESS-TREE", category="Live Triage", title="Running process tree snapshot",
            severity=Severity.MEDIUM if suspicious else Severity.INFORMATIONAL,
            status="Review" if suspicious else ("Observed" if available else "Unknown"),
            description="Captures PID, parent PID, user and executable path without modifying process state.",
            why_it_matters="Unexpected execution paths and missing parent relationships can identify activity that warrants preservation and deeper analysis.",
            what_was_checked="Current process table",
            expected_result="Processes run from expected protected locations with explainable parent relationships.",
            observed_result=f"Observed {len(processes)} processes and {len(suspicious)} review candidate(s)." if available else (error or "Process table unavailable."),
            recommendation="Validate review candidates against expected software, preserve volatile evidence and inspect code signatures before remediation.",
            evidence=(Evidence("process_snapshot", "local", {"process_count": len(processes), "review_candidates": suspicious, "snapshot_truncated": len(processes) >= MAX_PROCESSES}),),
            commands_used=(command,),
        )

    def _network_finding(self, command: str, connections: list[dict], suspicious: list[dict], error: str) -> Finding:
        listeners = [item for item in connections if item.get("state") == "LISTEN"]
        established = [item for item in connections if item.get("state") == "ESTABLISHED"]
        available = bool(connections) or not error
        return Finding(
            finding_id="LIVE-NETWORK-PROCESSES", category="Live Triage", title="Process and network connection correlation",
            severity=Severity.HIGH if suspicious else Severity.INFORMATIONAL,
            status="Review" if suspicious else ("Observed" if available else "Unknown"),
            description="Correlates current listeners and network endpoints with owning processes.",
            why_it_matters="A network-facing process executing from an unexpected writable path has higher investigative priority than either signal alone.",
            what_was_checked="Current IPv4/IPv6 sockets reported by lsof",
            expected_result="Network endpoints are owned by expected processes running from trusted locations.",
            observed_result=f"Observed {len(listeners)} listener(s), {len(established)} established connection(s), and {len(suspicious)} high-priority correlation(s)." if available else (error or "Network process correlation unavailable."),
            recommendation="Preserve endpoint and process evidence, validate destination ownership and inspect the executable signature/hash before containment.",
            evidence=(Evidence("network_process_snapshot", "local", {"listeners": listeners[:500], "established": established[:1000], "review_candidates": suspicious[:200], "snapshot_truncated": len(connections) >= MAX_CONNECTIONS}),),
            commands_used=(command,),
        )
