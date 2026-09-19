from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
from collections import Counter
from pathlib import Path

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


MAX_PROCESSES = 4_000
MAX_CONNECTIONS = 8_000
MAX_EXECUTABLE_HASH_BYTES = 64 * 1024 * 1024
MAX_CWD_PIDS = 500
WRITABLE_EXECUTION_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/")
MAX_COMMAND_LINE_CHARS = 2_048
SENSITIVE_ARGUMENT_PARTS = {
    "apikey", "auth", "authorization", "cookie", "credential", "credentials",
    "pass", "passwd", "password", "secret", "token",
}


def _elapsed_seconds(value: str | None) -> int | None:
    if not value:
        return None
    try:
        days, clock = (value.split("-", 1) if "-" in value else ("0", value))
        fields = [int(part) for part in clock.split(":")]
        if len(fields) == 2:
            hours, minutes, seconds = 0, fields[0], fields[1]
        elif len(fields) == 3:
            hours, minutes, seconds = fields
        else:
            return None
        return int(days) * 86400 + hours * 3600 + minutes * 60 + seconds
    except (TypeError, ValueError):
        return None


def parse_processes(text: str) -> list[dict[str, object]]:
    """Parse PID metadata while preserving executable paths that contain spaces."""
    processes = []
    for line in text.splitlines()[:MAX_PROCESSES]:
        parts = line.strip().split(None, 5)
        if len(parts) not in {4, 6}:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
            uid = int(parts[2]) if len(parts) == 6 else None
        except ValueError:
            continue
        user, process_state, executable = (
            (parts[3], parts[4], parts[5]) if len(parts) == 6 else (parts[2], "", parts[3])
        )
        processes.append({
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "user": user,
            "stat": process_state,
            "zombie": "Z" in process_state.upper(),
            "elapsed": None,
            "elapsed_seconds": None,
            "executable": executable,
            "command_line": executable,
        })
    return processes


def parse_process_context(text: str) -> dict[int, dict[str, object]]:
    """Parse a separate ps view so variable-width command lines cannot corrupt executable paths."""
    context: dict[int, dict[str, object]] = {}
    for line in text.splitlines()[:MAX_PROCESSES]:
        parts = line.strip().split(None, 2)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        elapsed = parts[1]
        command_line, redacted = sanitize_command_line(parts[2] if len(parts) == 3 else "")
        context[pid] = {
            "elapsed": elapsed,
            "elapsed_seconds": _elapsed_seconds(elapsed),
            "command_line": command_line,
            "command_line_redacted": redacted,
        }
    return context


def merge_process_context(
    processes: list[dict[str, object]], context: dict[int, dict[str, object]]
) -> list[dict[str, object]]:
    return [{**item, **context.get(int(item["pid"]), {})} for item in processes]


def sanitize_command_line(value: str) -> tuple[str, bool]:
    """Bound command evidence and redact common secret-bearing arguments before persistence."""
    truncated = len(value) > MAX_COMMAND_LINE_CHARS
    bounded = value[:MAX_COMMAND_LINE_CHARS]
    try:
        tokens = shlex.split(bounded, posix=True)
    except ValueError:
        tokens = bounded.split()
    output: list[str] = []
    redact_next = False
    redacted = truncated
    for token in tokens:
        if redact_next:
            output.append("<redacted>")
            redact_next = False
            redacted = True
            continue
        name = token.split("=", 1)[0].lstrip("-/").lower()
        parts = {part for part in re.split(r"[-_.]+", name) if part}
        collapsed = re.sub(r"[-_.]+", "", name)
        sensitive = bool(parts & SENSITIVE_ARGUMENT_PARTS) or collapsed.endswith((
            "apikey", "authkey", "accesskey", "privatekey", "clientsecret",
        ))
        if sensitive:
            if "=" in token:
                output.append(f"{token.split('=', 1)[0]}=<redacted>")
            else:
                output.append(token)
                redact_next = True
            redacted = True
            continue
        output.append(token)
    if truncated:
        output.append("<truncated>")
    return " ".join(output), redacted


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


def parse_cwd_fields(text: str) -> dict[int, str]:
    result: dict[int, str] = {}
    pid: int | None = None
    for raw in text.splitlines():
        if not raw:
            continue
        if raw[0] == "p":
            try:
                pid = int(raw[1:])
            except ValueError:
                pid = None
        elif raw[0] == "n" and pid is not None and not raw[1:].startswith("cwd|"):
            result[pid] = raw[1:]
    return result


def deduplicate_connections(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Collapse equivalent IPv4/IPv6 lsof rows while preserving the socket count."""
    unique: dict[tuple[object, ...], dict[str, object]] = {}
    for row in rows:
        key = (row.get("pid"), row.get("command"), row.get("endpoint"), row.get("state"))
        if key in unique:
            unique[key]["socket_count"] = int(unique[key].get("socket_count", 1)) + 1
        else:
            unique[key] = {**row, "socket_count": 1}
    return list(unique.values())


def _endpoint_host(endpoint: str, state: str) -> str | None:
    value = endpoint.rsplit("->", 1)[-1] if state == "ESTABLISHED" and "->" in endpoint else endpoint
    value = value.strip()
    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]
    if ":" not in value:
        return None
    return value.rsplit(":", 1)[0]


def socket_exposure(endpoint: str, state: str) -> str:
    host = _endpoint_host(endpoint, state)
    if host is None:
        return "unknown"
    normalized = host.strip().lower().split("%", 1)[0]
    if normalized in {"*", "0.0.0.0", "::", "localhost"}:
        return "wildcard" if normalized != "localhost" else "loopback"
    try:
        return "loopback" if ipaddress.ip_address(normalized).is_loopback else "non-loopback"
    except ValueError:
        return "unknown"


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
    rows = []
    for item in processes:
        executable = str(item["executable"])
        reasons = []
        risk_score = 0
        if executable.startswith(WRITABLE_EXECUTION_PREFIXES):
            reasons.append("executes from a shared temporary or writable directory")
            risk_score += 3
        if "/." in executable and executable.startswith("/Users/"):
            reasons.append("executes from a hidden path in the user profile")
            risk_score += 1
        if str(item["user"]) == "root" and executable.startswith("/Users/"):
            reasons.append("root process executes from a user-profile path")
            risk_score += 4
        if bool(item.get("zombie")):
            reasons.append("process is a zombie awaiting collection by its parent")
            risk_score += 2
        ppid = int(item["ppid"])
        if ppid not in {0, 1} and ppid not in pids:
            reasons.append("parent process is not present in this point-in-time snapshot")
            risk_score += 1
        if reasons:
            priority = "high" if risk_score >= 4 else ("medium" if risk_score >= 2 else "low")
            rows.append({
                **item,
                "priority": priority,
                "reasons": reasons,
                "risk_score": risk_score,
                "sha256": _hash_executable(executable),
            })
    return rows[:200]


def _is_simple_development_server(command_line: str) -> bool:
    value = f" {command_line.lower()} "
    return any(marker in value for marker in (
        " -m http.server ",
        " ruby -run -e httpd ",
        " php -s ",
        " busybox httpd ",
        " http-server ",
        " npx serve ",
    ))


def network_risk_candidates(
    connections: list[dict[str, object]],
    processes: list[dict[str, object]],
    suspicious: list[dict[str, object]],
    cwds: dict[int, str] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    """Return high, medium, and local-only correlations using combined signals."""
    by_pid = {int(item["pid"]): item for item in processes}
    suspicious_by_pid = {int(item["pid"]): item for item in suspicious}
    high: list[dict[str, object]] = []
    medium: list[dict[str, object]] = []
    local_only: list[dict[str, object]] = []
    cwds = cwds or {}

    for socket in connections:
        pid = int(socket["pid"])
        process = by_pid.get(pid, {})
        process_signal = suspicious_by_pid.get(pid)
        state = str(socket.get("state", ""))
        exposure = socket_exposure(str(socket.get("endpoint", "")), state)
        command_line = str(process.get("command_line", ""))
        simple_server = state == "LISTEN" and _is_simple_development_server(command_line)
        remotely_reachable = exposure in {"wildcard", "non-loopback"}
        reasons: list[str] = []
        priority: str | None = None

        if process_signal and exposure == "loopback":
            local_only.append({
                **socket,
                **{key: value for key, value in process.items() if key not in {"pid"}},
                "exposure": exposure,
                "reasons": [*process_signal["reasons"], "socket is restricted to the local host"],
                "cwd": cwds.get(pid),
            })
            continue

        if simple_server and remotely_reachable:
            reasons.append("a basic development file server listens beyond the local host")
            elapsed = process.get("elapsed_seconds")
            if isinstance(elapsed, int) and elapsed >= 3600:
                reasons.append("the development server has remained active for at least one hour")
                priority = "high"
            else:
                priority = "medium"
            cwd = cwds.get(pid)
            if cwd and cwd.startswith(WRITABLE_EXECUTION_PREFIXES):
                reasons.append("the server publishes content from a shared temporary or writable directory")
                priority = "high"
            if int(process.get("ppid", 0) or 0) == 1:
                reasons.append("the development server is detached from its original parent process")

        if process_signal and remotely_reachable:
            reasons.extend(str(reason) for reason in process_signal["reasons"])
            reasons.append("the process owns a socket that is not restricted to loopback")
            signal_score = int(process_signal.get("risk_score", 0))
            candidate_priority = "high" if signal_score >= 3 else "medium"
            if priority != "high":
                priority = candidate_priority

        if priority:
            candidate = {
                **socket,
                **{key: value for key, value in process.items() if key not in {"pid"}},
                "exposure": exposure,
                "priority": priority,
                "reasons": list(dict.fromkeys(reasons)),
                "cwd": cwds.get(pid),
                "sha256": process_signal.get("sha256") if process_signal else _hash_executable(str(process.get("executable", ""))),
            }
            (high if priority == "high" else medium).append(candidate)
    return high[:200], medium[:200], local_only[:200]


class LiveTriageCollector(Collector):
    collector_id = "live-triage"
    title = "Live incident triage"
    description = "Snapshots running processes, parent relationships, listeners and active network connections."

    def collect(self) -> list[Finding]:
        process_result = self.runner.run(("ps", "-axo", "pid=,ppid=,uid=,user=,stat=,comm="))
        context_result = self.runner.run(("ps", "-axo", "pid=,etime=,args="))
        network_result = self.runner.run(("lsof", "-nP", "-i", "-FpcnT"))
        processes = parse_processes(process_result.stdout) if process_result.returncode == 0 else []
        if context_result.returncode == 0:
            processes = merge_process_context(processes, parse_process_context(context_result.stdout))
        connections = deduplicate_connections(
            parse_lsof_fields(network_result.stdout) if network_result.returncode in {0, 1} else []
        )
        suspicious = suspicious_processes(processes)
        by_pid = {int(item["pid"]): item for item in processes}
        correlated = [
            {**row, "executable": by_pid.get(int(row["pid"]), {}).get("executable", "unknown")}
            for row in connections
        ]

        listener_pids = sorted({int(row["pid"]) for row in correlated if row.get("state") == "LISTEN"})[:MAX_CWD_PIDS]
        cwd_result = None
        cwds: dict[int, str] = {}
        if listener_pids:
            cwd_result = self.runner.run(("lsof", "-a", "-p", ",".join(str(pid) for pid in listener_pids), "-d", "cwd", "-Fn"))
            if cwd_result.returncode in {0, 1}:
                cwds = parse_cwd_fields(cwd_result.stdout)

        high, medium, local_only = network_risk_candidates(correlated, processes, suspicious, cwds)
        network_commands = (network_result.command,) + ((cwd_result.command,) if cwd_result else ())
        return [
            self._process_finding((process_result.command, context_result.command), processes, suspicious, process_result.stderr),
            self._network_finding(network_commands, correlated, high, medium, local_only, network_result.stderr),
        ]

    def _process_finding(self, commands: tuple[str, ...], processes: list[dict], suspicious: list[dict], error: str) -> Finding:
        available = bool(processes)
        priority_counts = Counter(str(item.get("priority", "low")) for item in suspicious)
        severity = (
            Severity.HIGH if priority_counts["high"]
            else Severity.MEDIUM if priority_counts["medium"]
            else Severity.LOW if suspicious
            else Severity.INFORMATIONAL
        )
        return Finding(
            finding_id="LIVE-PROCESS-TREE", category="Live Triage", title="Running process tree snapshot",
            severity=severity,
            status="Review" if suspicious else ("Observed" if available else "Unknown"),
            description="Captures PID, parent PID, numeric owner, process state, runtime, executable path and command line without modifying process state.",
            why_it_matters="Unexpected execution paths and missing parent relationships can identify activity that warrants preservation and deeper analysis.",
            what_was_checked="Current process table",
            expected_result="Processes run from expected protected locations with explainable parent relationships.",
            observed_result=(
                f"Observed {len(processes)} processes and {len(suspicious)} review candidate(s): "
                f"{priority_counts['high']} high, {priority_counts['medium']} medium and {priority_counts['low']} low priority."
            ) if available else (error or "Process table unavailable."),
            recommendation="Validate review candidates against expected software, preserve volatile evidence and inspect code signatures before remediation.",
            evidence=(Evidence("process_snapshot", "local", {
                "process_count": len(processes),
                "running_processes": [
                    {
                        key: process.get(key)
                        for key in ("pid", "ppid", "stat", "zombie", "elapsed", "elapsed_seconds", "executable")
                    }
                    for process in processes[:MAX_PROCESSES]
                ],
                "priority_summary": dict(sorted(priority_counts.items())),
                "review_candidates": suspicious,
                "snapshot_truncated": len(processes) >= MAX_PROCESSES,
            }),),
            commands_used=commands,
        )

    def _network_finding(
        self,
        commands: tuple[str, ...],
        connections: list[dict],
        high: list[dict],
        medium: list[dict],
        local_only: list[dict],
        error: str,
    ) -> Finding:
        listeners = [item for item in connections if item.get("state") == "LISTEN"]
        established = [item for item in connections if item.get("state") == "ESTABLISHED"]
        available = bool(connections) or not error
        exposure_counts = Counter(socket_exposure(str(item.get("endpoint", "")), str(item.get("state", ""))) for item in listeners)
        candidates = [*high, *medium]
        severity = Severity.HIGH if high else (Severity.MEDIUM if medium else Severity.INFORMATIONAL)
        return Finding(
            finding_id="LIVE-NETWORK-PROCESSES", category="Live Triage", title="Process and network connection correlation",
            severity=severity,
            status="Review" if candidates else ("Observed" if available else "Unknown"),
            description="Correlates deduplicated network endpoints with process paths, full command lines, runtime, parent state, listener exposure and working directory.",
            why_it_matters="Remote-reachable development servers and processes combining suspicious execution paths with non-loopback sockets deserve more attention than loopback-only tooling.",
            what_was_checked="Current IPv4/IPv6 sockets reported by lsof and bounded process context",
            expected_result="Network endpoints are owned by expected processes, exposed only as intended, and running from trusted locations.",
            observed_result=(
                f"Observed {len(listeners)} unique listener(s), {len(established)} unique established connection(s), "
                f"{len(high)} high-priority and {len(medium)} medium-priority candidate(s); "
                f"{len(local_only)} suspicious-path correlation(s) were limited to loopback."
            ) if available else (error or "Network process correlation unavailable."),
            recommendation="Review high-priority candidates first. Stop stale development servers through their owning application, restrict intended services to loopback when remote access is unnecessary, and validate signatures, hashes and destinations before containment.",
            evidence=(Evidence("network_process_snapshot", "local", {
                "listeners": listeners[:500],
                "listener_exposure_summary": dict(sorted(exposure_counts.items())),
                "established": established[:1000],
                "review_candidates": candidates,
                "high_priority_candidates": high,
                "medium_priority_candidates": medium,
                "local_only_correlations": local_only,
                "snapshot_truncated": len(connections) >= MAX_CONNECTIONS,
            }),),
            commands_used=commands,
        )
