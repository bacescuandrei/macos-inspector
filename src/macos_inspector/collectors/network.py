from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


CERT_HASH_RE = re.compile(r"(?:SHA-?256 hash|SHA-1 hash):\s*([0-9A-Fa-f]{40,64})")
SCUTIL_VALUE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9]+)\s*:\s*(.*?)\s*$")
PROXY_ENABLE_KEYS = {
    "HTTPEnable": "HTTP",
    "HTTPSEnable": "HTTPS",
    "FTPEnable": "FTP",
    "SOCKSEnable": "SOCKS",
    "RTSPEnable": "RTSP",
    "GopherEnable": "Gopher",
    "ProxyAutoConfigEnable": "PAC",
    "ProxyAutoDiscoveryEnable": "Auto discovery",
}


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


def _redact_proxy_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.netloc:
            return value
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        userinfo = "redacted@" if parsed.username or parsed.password else ""
        query = "redacted" if parsed.query else ""
        fragment = "redacted" if parsed.fragment else ""
        return urlunsplit((parsed.scheme, f"{userinfo}{hostname}{port}", parsed.path, query, fragment))
    except ValueError:
        return "unparseable URL"


def parse_proxy_configuration(output: str) -> dict[str, object]:
    settings: dict[str, object] = {}
    for line in output.splitlines():
        match = SCUTIL_VALUE_RE.match(line)
        if not match:
            continue
        key, value = match.groups()
        parsed_value: object = int(value) if value.isdigit() else value
        if key.lower().endswith("urlstring") and isinstance(parsed_value, str):
            parsed_value = _redact_proxy_url(parsed_value)
        settings[key] = parsed_value
    return settings


def enabled_proxy_types(settings: dict[str, object]) -> tuple[str, ...]:
    return tuple(label for key, label in PROXY_ENABLE_KEYS.items() if settings.get(key) == 1)


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
        findings.append(self._proxy_finding())
        return findings

    def _proxy_finding(self) -> Finding:
        result = self.runner.run(("scutil", "--proxy"))
        settings = parse_proxy_configuration(result.stdout) if result.returncode == 0 and not result.timed_out else {}
        enabled = enabled_proxy_types(settings)
        if result.returncode != 0 or result.timed_out:
            severity, status = Severity.INFORMATIONAL, "Unknown"
            observed = result.stderr or f"Command returned exit status {result.returncode}."
        elif enabled:
            severity, status = Severity.LOW, "Review"
            endpoints = []
            for prefix in ("HTTP", "HTTPS", "FTP", "SOCKS", "RTSP", "Gopher"):
                host = settings.get(f"{prefix}Proxy")
                port = settings.get(f"{prefix}Port")
                if host:
                    endpoints.append(f"{prefix}={host}{f':{port}' if port is not None else ''}")
            pac = settings.get("ProxyAutoConfigURLString")
            if pac:
                endpoints.append(f"PAC={pac}")
            observed = f"Enabled proxy mechanism(s): {', '.join(enabled)}."
            if endpoints:
                observed += f" Configured endpoint(s): {', '.join(str(value) for value in endpoints)}."
        else:
            severity, status = Severity.INFORMATIONAL, "Pass"
            observed = "No enabled system proxy mechanism was observed."
        return Finding(
            finding_id="NETWORK-PROXY", category="Network & Certificates", title="System proxy configuration",
            severity=severity, status=status,
            description="Interprets the active macOS HTTP, HTTPS, SOCKS, legacy proxy, PAC, and automatic proxy-discovery settings.",
            why_it_matters="Unexpected proxy or PAC configuration can redirect, inspect, or alter host network traffic.",
            what_was_checked=result.command,
            expected_result="Every enabled proxy mechanism and endpoint is authorized and attributable to the host's network policy.",
            observed_result=observed,
            recommendation="Validate enabled proxies and PAC sources against the approved network or VPN configuration; preserve evidence before changing them.",
            evidence=(Evidence("proxy_configuration", result.command, {
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "enabled_types": enabled,
                "settings": settings,
                "stderr": result.stderr,
            }),),
            commands_used=(result.command,),
            mitre_attack=("T1090 - Proxy",),
            references=("https://support.apple.com/guide/mac-help/change-proxy-settings-on-mac-mchlp2591/mac",),
        )
