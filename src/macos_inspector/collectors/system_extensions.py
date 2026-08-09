from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


STATE_RE = re.compile(
    r"^\s*(?:(?P<enabled>\*)\s+(?P<active>\*)\s+)?"
    r"(?:(?P<state>enabled(?:\s+active)?|active|activated|deactivated|terminated|uninstalling|waiting|replaced|failed)\s+)?"
    r"(?:(?P<team>[A-Z0-9]{6,12})\s+)?"
    r"(?P<bundle>[A-Za-z0-9][A-Za-z0-9._-]+)\s+\((?P<version>[^)]+)\)"
    r"(?:.*?\[(?P<bracket_state>[^]]+)])?\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SystemExtension:
    state: str
    team_id: str | None
    bundle_id: str
    version: str


def parse_system_extensions(output: str) -> list[SystemExtension]:
    extensions: list[SystemExtension] = []
    for line in output.splitlines():
        if "teamID" in line and "bundleID" in line:
            continue
        match = STATE_RE.search(line)
        if match:
            state = match.group("bracket_state") or match.group("state")
            if not state and match.group("enabled") and match.group("active"):
                state = "enabled active"
            if not state:
                state = "observed"
            extensions.append(SystemExtension(
                state.lower(), match.group("team"), match.group("bundle"), match.group("version").strip(),
            ))
    return extensions


def _finding_id(source: str) -> str:
    return f"SYSTEMEXT-{hashlib.sha256(source.encode()).hexdigest()[:12].upper()}"


class SystemExtensionsCollector(Collector):
    collector_id = "system-extensions"
    title = "System extensions"

    def collect(self) -> list[Finding]:
        result = self.runner.run(("systemextensionsctl", "list"))
        output = f"{result.stdout}\n{result.stderr}".strip()
        extensions = parse_system_extensions(result.stdout)
        if result.returncode != 0 or result.timed_out:
            status, severity = "Unknown", Severity.INFORMATIONAL
            observed = output or f"Command returned exit status {result.returncode}."
        elif not extensions:
            status, severity = "Unknown", Severity.INFORMATIONAL
            observed = "The command succeeded but returned no parseable system extensions."
        else:
            third_party = [item for item in extensions if not item.bundle_id.startswith("com.apple.")]
            status = "Review" if third_party else "Observed"
            severity = Severity.MEDIUM if third_party else Severity.INFORMATIONAL
            observed = f"{len(extensions)} system extension(s) observed; {len(third_party)} non-Apple extension(s) require review."
        evidence = {
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "timed_out": result.timed_out,
            "extensions": [item.__dict__ for item in extensions],
        }
        return [Finding(
            finding_id=_finding_id(result.command), category="System Extensions", title="Installed system extensions",
            severity=severity, status=status,
            description="Collects the locally registered macOS system extensions without changing their state.",
            why_it_matters="Network filters, endpoint security products, VPNs, drivers, and other extensions run with powerful system integration.",
            what_was_checked=result.command,
            expected_result="Every installed extension has a known publisher, business purpose, and approved lifecycle state.",
            observed_result=observed,
            recommendation="Validate non-Apple extensions against the approved software inventory and preserve evidence before removal or deactivation.",
            evidence=(Evidence("system_extensions", result.command, evidence),), commands_used=(result.command,),
            references=("https://support.apple.com/guide/security/system-extensions-sec8e5f4e8f77/web",),
        )]
