from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity
from macos_inspector.core.runner import CommandResult


LABEL_RE = re.compile(r'"([^"]+)"\s*=>\s*(enabled|disabled)', re.IGNORECASE)
APPLE_PREFIXES = ("com.apple.",)


def parse_disabled_services(output: str) -> list[tuple[str, str]]:
    """Extract labels from launchctl print-disabled without guessing semantics."""
    return [(match.group(1), match.group(2).lower()) for match in LABEL_RE.finditer(output)]


def _finding_id(source: str) -> str:
    return f"BACKGROUND-{hashlib.sha256(source.encode()).hexdigest()[:12].upper()}"


def _command_unknown(result: CommandResult) -> bool:
    return result.returncode in {124, 126, 127} or result.timed_out


class BackgroundItemsCollector(Collector):
    collector_id = "background-items"
    title = "Login & background items"

    def collect(self) -> list[Finding]:
        findings = [self._background_task_finding()]
        findings.append(self._launchctl_finding("user", ("launchctl", "print-disabled", f"user/{os.getuid()}")))
        findings.append(self._launchctl_finding("system", ("launchctl", "print-disabled", "system")))
        return findings

    def _background_task_finding(self) -> Finding:
        result = self.runner.run(("sfltool", "dumpbtm"))
        if result.returncode != 0:
            status = "Unknown"
            severity = Severity.INFORMATIONAL
            observed = result.stderr or result.stdout or f"Command returned exit status {result.returncode}."
        else:
            status = "Observed"
            severity = Severity.INFORMATIONAL
            observed = "Background Task Management data was collected."
        return Finding(
            finding_id=_finding_id("sfltool:dumpbtm"), category="Background Items",
            title="Background Task Management database", severity=severity, status=status,
            description="Collects macOS Login Item and Background Task Management output without changing it.",
            why_it_matters="Background items can launch code at login, after installation, or when a user session changes.",
            what_was_checked=result.command, expected_result="The source can be collected under the approved evidence-access policy.",
            observed_result=observed,
            recommendation="Review unknown or unexpected background items and validate their publisher before disabling anything.",
            evidence=(Evidence("command_output", result.command, {
                "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                "timed_out": result.timed_out,
            }),), commands_used=(result.command,),
            mitre_attack=("T1547.015 - Login Items",),
            references=("https://support.apple.com/guide/security/managing-login-items-sec6b1c5b6c4e/web",),
        )

    def _launchctl_finding(self, scope: str, argv: tuple[str, ...]) -> Finding:
        result = self.runner.run(argv)
        entries = parse_disabled_services(f"{result.stdout}\n{result.stderr}")
        if _command_unknown(result) or result.returncode != 0:
            return Finding(
                finding_id=_finding_id("launchctl:" + scope), category="Background Items",
                title=f"ServiceManagement disabled map: {scope}", severity=Severity.INFORMATIONAL, status="Unknown",
                description="Reads launchd's disabled-service map for the selected scope.",
                why_it_matters="ServiceManagement state can suppress or enable persistent background services.",
                what_was_checked=result.command, expected_result="The disabled-service map is readable.",
                observed_result=result.stderr or result.stdout or f"Command returned exit status {result.returncode}.",
                recommendation="Collect the map with an approved local account and review unexpected entries in context.",
                evidence=(Evidence("command_output", result.command, {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timed_out": result.timed_out}),),
                commands_used=(result.command,), mitre_attack=("T1543 - Create or Modify System Process",),
            )
        third_party = [entry for entry in entries if not entry[0].startswith(APPLE_PREFIXES)]
        enabled_third_party = [entry for entry in third_party if entry[1] == "enabled"]
        disabled_third_party = [entry for entry in third_party if entry[1] == "disabled"]
        severity = Severity.MEDIUM if enabled_third_party else Severity.INFORMATIONAL
        status = "Review" if enabled_third_party else "Observed"
        observed = (
            f"{len(entries)} service state(s) observed; {len(enabled_third_party)} enabled non-Apple label(s) require review"
            f" and {len(disabled_third_party)} disabled non-Apple label(s) were retained as context."
        )
        return Finding(
            finding_id=_finding_id("launchctl:" + scope), category="Background Items",
            title=f"ServiceManagement disabled map: {scope}", severity=severity, status=status,
            description="Reads launchd's disabled-service map for the selected scope.",
            why_it_matters="ServiceManagement state can suppress or enable persistent background services.",
            what_was_checked=result.command, expected_result="Every non-Apple service state has a known owner and purpose.",
            observed_result=observed,
            recommendation="Review non-Apple labels against installed software and preserve evidence before changing ServiceManagement state.",
            evidence=(Evidence("launchctl_services", result.command, {
                "scope": scope,
                "entries": [{"label": label, "state": state} for label, state in entries],
                "review_candidates": [{"label": label, "state": state} for label, state in enabled_third_party],
                "disabled_third_party_context": [{"label": label, "state": state} for label, state in disabled_third_party],
            }),), commands_used=(result.command,),
            mitre_attack=("T1543 - Create or Modify System Process",),
        )
