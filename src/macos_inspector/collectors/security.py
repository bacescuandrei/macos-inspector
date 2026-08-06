from __future__ import annotations

import json
from dataclasses import dataclass

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


@dataclass(frozen=True)
class Control:
    finding_id: str
    title: str
    argv: tuple[str, ...]
    good_tokens: tuple[str, ...]
    severity: Severity
    recommendation: str
    failure_status: str = "Fail"


CONTROLS = (
    Control("CONTROL-SIP", "System Integrity Protection", ("csrutil", "status"), ("enabled",), Severity.HIGH, "Enable SIP through the supported macOS Recovery workflow after assessing operational requirements."),
    Control("CONTROL-FILEVAULT", "FileVault disk encryption", ("fdesetup", "status"), ("filevault is on",), Severity.HIGH, "Enable FileVault using the organization's approved key escrow and recovery process."),
    Control("CONTROL-GATEKEEPER", "Gatekeeper assessment", ("spctl", "--status"), ("assessments enabled",), Severity.HIGH, "Enable Gatekeeper and investigate unauthorized configuration changes."),
    Control("CONTROL-FIREWALL", "Application firewall", ("socketfilterfw", "--getglobalstate"), ("state = 1", "state = 2", "enabled"), Severity.MEDIUM, "Enable the macOS application firewall according to organizational policy."),
    Control("CONTROL-AUTOMATIC-UPDATES", "Automatic update checks", ("softwareupdate", "--schedule"), ("automatic checking for updates is turned on", "automatic check is on"), Severity.MEDIUM, "Enable automatic update checking and use the organization's approved macOS update deployment policy."),
    Control("CONTROL-FIREWALL-STEALTH", "Firewall stealth mode", ("socketfilterfw", "--getstealthmode"), ("stealth mode is on", "stealth mode enabled"), Severity.LOW, "Consider enabling firewall stealth mode when it matches the host's network exposure and operational policy.", "Review"),
)


class SecurityControlsCollector(Collector):
    collector_id = "security"
    title = "Security controls"

    def collect(self) -> list[Finding]:
        findings = []
        for control in CONTROLS:
            result = self.runner.run(control.argv)
            combined = f"{result.stdout}\n{result.stderr}".strip()
            accessible = result.returncode == 0
            passes = accessible and bool(control.good_tokens) and any(token in combined.lower() for token in control.good_tokens)
            if not accessible:
                severity, status = Severity.INFORMATIONAL, "Unknown"
            elif not control.good_tokens:
                severity, status = Severity.INFORMATIONAL, "Observed"
            elif passes:
                severity, status = Severity.INFORMATIONAL, "Pass"
            else:
                severity, status = control.severity, control.failure_status
            findings.append(Finding(
                finding_id=control.finding_id, category="System Hardening", title=control.title, severity=severity, status=status,
                description=f"Checks the current state of {control.title} using a native macOS read-only query.",
                why_it_matters="macOS platform controls reduce the likelihood or impact of unauthorized execution, access, and data exposure.",
                what_was_checked=result.command, expected_result="The security control is enabled or configured according to policy.",
                observed_result=combined or f"Command returned exit status {result.returncode} with no output.", recommendation=control.recommendation,
                evidence=(Evidence("command_output", result.command, {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timed_out": result.timed_out}),),
                commands_used=(result.command,), references=("https://support.apple.com/guide/security/welcome/web",),
            ))
        findings.append(self._remote_login())
        return findings

    def _remote_login(self) -> Finding:
        argv = ("system_profiler", "SPSharingDataType", "-json", "-detailLevel", "mini")
        result = self.runner.run(argv)
        enabled = None
        if result.returncode == 0:
            try:
                payload = json.loads(result.stdout)
                text = json.dumps(payload, ensure_ascii=False).lower()
                enabled = "remote login" in text or "remote_login" in text or "sshd" in text
            except json.JSONDecodeError:
                enabled = None
        if enabled is False:
            severity, status, observed = Severity.INFORMATIONAL, "Pass", "Remote Login is not listed among enabled sharing services."
        elif enabled is True:
            severity, status, observed = Severity.LOW, "Review", "Remote Login appears among enabled sharing services."
        else:
            severity, status = Severity.INFORMATIONAL, "Unknown"
            observed = result.stderr or result.stdout or f"Command returned exit status {result.returncode}."
        return Finding(
            finding_id="CONTROL-REMOTELOGIN", category="System Hardening", title="Remote Login",
            severity=severity, status=status,
            description="Checks whether Remote Login is exposed through macOS Sharing services.",
            why_it_matters="Remote shell access expands the host's remotely reachable attack surface.",
            what_was_checked=result.command, expected_result="Remote Login is disabled unless explicitly authorized by policy.",
            observed_result=observed,
            recommendation="Disable Remote Login when it is not required, or restrict and monitor authorized SSH access.",
            evidence=(Evidence("command_output", result.command, {
                "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                "timed_out": result.timed_out, "enabled": enabled,
            }),), commands_used=(result.command,),
            references=("https://support.apple.com/guide/mac-help/allow-a-remote-computer-to-access-your-mac-mchlp1066/mac",),
        )
