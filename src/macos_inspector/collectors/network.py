from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


CERT_HASH_RE = re.compile(r"(?:SHA-?256 hash|SHA-1 hash):\s*([0-9A-Fa-f]{40,64})")


@dataclass(frozen=True)
class Query:
    finding_id: str
    title: str
    argv: tuple[str, ...]
    expected: str
    recommendation: str


QUERIES = (
    Query("NETWORK-DNS", "DNS resolver configuration", ("scutil", "--dns"), "The active resolver configuration is available for review.", "Review unexpected resolvers, search domains, and per-interface DNS settings."),
    Query("NETWORK-NWI", "Network interface state", ("scutil", "--nwi"), "The local network interface/reachability state is available for review.", "Review unexpected interfaces, routes, and reachability changes against the host baseline."),
    Query("NETWORK-CERTS", "System keychain certificates", ("security", "find-certificate", "-a", "-Z", "/Library/Keychains/System.keychain"), "The system keychain certificate inventory is available for review.", "Validate unexpected anchors and certificates against the organization trust policy; preserve evidence before removal."),
)


def parse_certificate_hashes(output: str) -> list[str]:
    return sorted({match.group(1).upper() for match in CERT_HASH_RE.finditer(output)})


def _finding_id(prefix: str, source: str) -> str:
    return f"{prefix}-{hashlib.sha256(source.encode()).hexdigest()[:12].upper()}"


class NetworkCollector(Collector):
    collector_id = "network"
    title = "Network & certificates"

    def collect(self) -> list[Finding]:
        findings = []
        for query in QUERIES:
            result = self.runner.run(query.argv)
            output = f"{result.stdout}\n{result.stderr}".strip()
            accessible = result.returncode == 0 and not result.timed_out
            certificate_hashes = parse_certificate_hashes(output) if query.finding_id == "NETWORK-CERTS" else []
            if not accessible:
                severity, status = Severity.INFORMATIONAL, "Unknown"
                observed = output or f"Command returned exit status {result.returncode}."
            elif query.finding_id == "NETWORK-CERTS" and not certificate_hashes:
                severity, status = Severity.INFORMATIONAL, "Unknown"
                observed = "The keychain query returned no parseable certificate fingerprints."
            else:
                severity, status = Severity.INFORMATIONAL, "Observed"
                if query.finding_id == "NETWORK-CERTS":
                    observed = f"{len(certificate_hashes)} certificate fingerprint(s) observed in the system keychain."
                else:
                    observed = "Configuration data was collected for review."
            evidence_value = {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "timed_out": result.timed_out}
            if query.finding_id == "NETWORK-CERTS":
                evidence_value["sha256_fingerprints"] = certificate_hashes
            findings.append(Finding(
                finding_id=_finding_id(query.finding_id, result.command), category="Network & Certificates",
                title=query.title, severity=severity, status=status,
                description=f"Collects {query.title.lower()} with a native read-only macOS query.",
                why_it_matters="Network paths and trust anchors influence where a host connects and which certificates it accepts.",
                what_was_checked=result.command, expected_result=query.expected, observed_result=observed,
                recommendation=query.recommendation,
                evidence=(Evidence("command_output", result.command, evidence_value),),
                commands_used=(result.command,), references=("https://support.apple.com/guide/security/welcome/web",),
            ))
        return findings
