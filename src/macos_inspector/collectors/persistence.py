from __future__ import annotations

import hashlib
import os
import plistlib
import stat
from xml.parsers.expat import ExpatError
from pathlib import Path
from typing import Any

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


LAUNCH_PATHS = (
    Path("/System/Library/LaunchAgents"),
    Path("/System/Library/LaunchDaemons"),
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
)
SHELL_PROFILES = (".zshrc", ".zprofile", ".bash_profile", ".bashrc", ".profile")
SUSPICIOUS_ROOTS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/")


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def _program_from_plist(data: dict[str, Any]) -> str | None:
    program = data.get("Program")
    if isinstance(program, str):
        return program
    arguments = data.get("ProgramArguments")
    if isinstance(arguments, list) and arguments and isinstance(arguments[0], str):
        return arguments[0]
    return None


class PersistenceCollector(Collector):
    collector_id = "persistence"
    title = "Persistence mechanisms"

    def collect(self) -> list[Finding]:
        findings = self._launchd_findings()
        findings.extend(self._cron_findings())
        findings.extend(self._shell_profile_findings())
        return findings

    def _launchd_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        paths = list(LAUNCH_PATHS)
        user_agents = Path.home() / "Library/LaunchAgents"
        paths.append(user_agents)
        for directory in paths:
            try:
                plists = sorted(directory.glob("*.plist"))
            except OSError:
                continue
            for plist_path in plists:
                try:
                    raw = plist_path.read_bytes()
                    data = plistlib.loads(raw)
                    if not isinstance(data, dict):
                        raise ValueError("plist root is not a dictionary")
                except (OSError, plistlib.InvalidFileException, ExpatError, ValueError) as exc:
                    fallback = self.runner.run(("plutil", "-convert", "xml1", "-o", "-", str(plist_path)))
                    try:
                        if fallback.returncode != 0:
                            raise ValueError(fallback.stderr or str(exc))
                        data = plistlib.loads(fallback.stdout.encode())
                        if not isinstance(data, dict):
                            raise ValueError("plist root is not a dictionary")
                    except (plistlib.InvalidFileException, ExpatError, ValueError) as fallback_exc:
                        findings.append(self._invalid_plist(plist_path, str(fallback_exc)))
                        continue
                executable_text = _program_from_plist(data)
                if not executable_text:
                    continue
                executable = Path(os.path.expanduser(executable_text))
                absolute = executable.is_absolute()
                exists = absolute and executable.exists()
                suspicious = any(str(executable).startswith(root) for root in SUSPICIOUS_ROOTS)
                world_writable = group_writable = False
                mode = None
                owner = None
                group = None
                if exists:
                    try:
                        metadata = executable.stat()
                        mode = stat.filemode(metadata.st_mode)
                        owner = metadata.st_uid
                        group = metadata.st_gid
                        world_writable = bool(metadata.st_mode & stat.S_IWOTH)
                        group_writable = bool(metadata.st_mode & stat.S_IWGRP)
                    except OSError:
                        pass
                apple_definition = str(plist_path).startswith("/System/Library/")
                if suspicious or world_writable:
                    severity, status = Severity.HIGH, "Fail"
                elif not absolute or group_writable:
                    severity, status = Severity.MEDIUM, "Fail"
                elif not exists and apple_definition:
                    severity, status = Severity.INFORMATIONAL, "Unknown"
                elif not exists:
                    severity, status = Severity.MEDIUM, "Fail"
                else:
                    severity, status = Severity.INFORMATIONAL, "Observed"
                observed = f"{plist_path} executes {executable}; exists={exists}"
                findings.append(Finding(
                    finding_id=f"PERSIST-LAUNCHD-{hashlib.sha256(str(plist_path).encode()).hexdigest()[:12].upper()}",
                    category="Persistence",
                    title=f"launchd item: {data.get('Label', plist_path.stem)}",
                    severity=severity,
                    status=status,
                    description="A launchd property list can start a process at boot or user login.",
                    why_it_matters="LaunchAgents and LaunchDaemons are common legitimate service mechanisms and a frequently abused persistence technique.",
                    what_was_checked="Property-list validity, executable presence, path, ownership, permissions, and SHA-256 where accessible.",
                    expected_result="The executable exists in a trusted, non-temporary location and is not writable by untrusted users.",
                    observed_result=observed,
                    recommendation="Validate the publisher and business purpose. Investigate missing, temporary, or broadly writable executables; do not remove artifacts before preserving evidence.",
                    evidence=(Evidence("plist", str(plist_path), {"label": data.get("Label"), "program": executable_text}), Evidence("file_metadata", str(executable), {"exists": exists, "absolute": absolute, "mode": mode, "uid": owner, "gid": group, "world_writable": world_writable, "group_writable": group_writable, "sha256": _sha256(executable) if exists and executable.is_file() else None})),
                    mitre_attack=("T1543.001 - Launch Agent", "T1543.004 - Launch Daemon"),
                    references=("https://attack.mitre.org/techniques/T1543/001/",),
                ))
        return findings

    def _invalid_plist(self, path: Path, error: str) -> Finding:
        return Finding(
            finding_id=f"PERSIST-PLIST-{hashlib.sha256(str(path).encode()).hexdigest()[:12].upper()}", category="Persistence",
            title=f"Unreadable launchd property list: {path.name}", severity=Severity.LOW, status="Unknown",
            description="A launchd definition could not be parsed.", why_it_matters="Malformed or inaccessible persistence metadata prevents complete validation.",
            what_was_checked="Binary/XML plist parsing.", expected_result="The plist is readable and structurally valid.", observed_result=error,
            recommendation="Preserve and inspect the file with an approved forensic workflow.", evidence=(Evidence("error", str(path), error),),
            mitre_attack=("T1543 - Create or Modify System Process",),
        )

    def _cron_findings(self) -> list[Finding]:
        findings = []
        for path in (Path("/etc/crontab"), Path("/usr/lib/cron/tabs") / os.environ.get("USER", "")):
            try:
                present = path.is_file()
            except OSError as exc:
                findings.append(Finding(
                    finding_id=f"PERSIST-CRON-ACCESS-{hashlib.sha256(str(path).encode()).hexdigest()[:12].upper()}", category="Persistence",
                    title=f"Cron path inaccessible: {path}", severity=Severity.INFORMATIONAL, status="Unknown",
                    description="A known cron persistence path could not be inspected with current privileges.",
                    why_it_matters="Incomplete access limits the assurance provided by the persistence audit.", what_was_checked=str(path),
                    expected_result="The path can be evaluated under the approved evidence-access policy.", observed_result=str(exc),
                    recommendation="If required by the engagement, collect this artifact separately using approved forensic access procedures.",
                    evidence=(Evidence("access_error", str(path), str(exc)),), mitre_attack=("T1053.003 - Cron",),
                ))
                continue
            if not present:
                continue
            try:
                content = path.read_text(errors="replace")
            except OSError as exc:
                content = f"Unreadable: {exc}"
            findings.append(Finding(
                finding_id=f"PERSIST-CRON-{hashlib.sha256(str(path).encode()).hexdigest()[:12].upper()}", category="Persistence",
                title=f"Cron persistence present: {path}", severity=Severity.LOW, status="Review",
                description="Cron can execute commands on a schedule.", why_it_matters="Scheduled tasks can provide recurring execution and persistence.",
                what_was_checked="Known system and current-user crontab paths.", expected_result="Every scheduled task has a known owner and purpose.",
                observed_result=f"A cron configuration exists at {path}.", recommendation="Review commands, owners, frequency, and referenced executables.",
                evidence=(Evidence("file", str(path), content[:20000]),), mitre_attack=("T1053.003 - Cron",),
            ))
        return findings

    def _shell_profile_findings(self) -> list[Finding]:
        findings = []
        for name in SHELL_PROFILES:
            path = Path.home() / name
            if not path.is_file():
                continue
            try:
                content = path.read_text(errors="replace")
            except OSError as exc:
                content = f"Unreadable: {exc}"
            suspicious_lines = [line.strip() for line in content.splitlines() if any(token in line for token in ("DYLD_", "curl ", "wget ", "osascript", "/tmp/"))]
            severity = Severity.MEDIUM if suspicious_lines else Severity.INFORMATIONAL
            findings.append(Finding(
                finding_id=f"PERSIST-SHELL-{name.upper().replace('.', '')}", category="Persistence", title=f"Shell profile: {name}",
                severity=severity, status="Review" if suspicious_lines else "Observed", description="Shell profiles execute commands when interactive or login shells start.",
                why_it_matters="Attackers may add environment injection, download, or execution commands to profile files.",
                what_was_checked="Current-user shell profiles and high-signal execution strings.", expected_result="Profiles contain only expected environment and shell customization.",
                observed_result=f"{len(suspicious_lines)} high-signal line(s) require review.", recommendation="Review flagged lines in context and preserve timestamps before making changes.",
                evidence=(Evidence("file_metadata", str(path), {"sha256": _sha256(path), "flagged_lines": suspicious_lines}),), mitre_attack=("T1546.004 - Unix Shell Configuration Modification",),
            ))
        return findings
