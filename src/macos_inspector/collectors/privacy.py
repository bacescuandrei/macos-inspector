from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


DEFAULT_TCC_DATABASES = (
    Path("/Library/Application Support/com.apple.TCC/TCC.db"),
    Path.home() / "Library/Application Support/com.apple.TCC/TCC.db",
)

SENSITIVE_SERVICES = {
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServiceAppleEvents": "Automation / Apple Events",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
    "kTCCServiceSystemPolicyDesktopFolder": "Desktop folder",
    "kTCCServiceSystemPolicyDocumentsFolder": "Documents folder",
    "kTCCServiceSystemPolicyDownloadsFolder": "Downloads folder",
    "kTCCServiceSystemPolicyNetworkVolumes": "Network volumes",
    "kTCCServiceSystemPolicyRemovableVolumes": "Removable volumes",
}


@dataclass(frozen=True)
class TCCGrant:
    service: str
    client: str
    auth_value: int | None
    auth_reason: int | None
    last_modified: int | None

    @property
    def allowed(self) -> bool:
        return self.auth_value in {2, 3}


def _finding_id(database: Path, service: str) -> str:
    value = f"{database}:{service}".encode("utf-8", "surrogateescape")
    return f"PRIVACY-TCC-{hashlib.sha256(value).hexdigest()[:12].upper()}"


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _read_tcc(database: Path) -> tuple[list[TCCGrant], str | None]:
    if not database.is_file():
        return [], "Database does not exist or is not visible to the current user."
    try:
        # URI mode=ro prevents sqlite from creating or modifying the evidence source.
        uri = f"file:{database}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as connection:
            connection.row_factory = sqlite3.Row
            columns = {row[1] for row in connection.execute("PRAGMA table_info(access)")}
            required = {"service", "client", "auth_value"}
            if not required <= columns:
                return [], f"TCC schema is missing required columns: {', '.join(sorted(required - columns))}."
            optional = [name for name in ("auth_reason", "last_modified") if name in columns]
            selected = ", ".join(["service", "client", "auth_value", *optional])
            rows = connection.execute(f"SELECT {selected} FROM access").fetchall()
            grants = []
            for row in rows:
                grants.append(TCCGrant(
                    str(row["service"]), str(row["client"]), _integer(row["auth_value"]),
                    _integer(row["auth_reason"]) if "auth_reason" in optional else None,
                    _integer(row["last_modified"]) if "last_modified" in optional else None,
                ))
            return grants, None
    except (OSError, sqlite3.Error) as exc:
        return [], f"{type(exc).__name__}: {exc}"


class PrivacyCollector(Collector):
    collector_id = "privacy"
    title = "TCC & privacy permissions"

    def __init__(self, runner, databases: tuple[Path, ...] | None = None) -> None:
        super().__init__(runner)
        self.databases = DEFAULT_TCC_DATABASES if databases is None else databases

    def collect(self) -> list[Finding]:
        findings: list[Finding] = []
        for database in self.databases:
            grants, error = _read_tcc(database)
            if error:
                findings.append(self._unknown(database, error))
                continue
            findings.extend(self._service_findings(database, grants))
        return findings

    def _unknown(self, database: Path, error: str) -> Finding:
        return Finding(
            finding_id=_finding_id(database, "database"), category="Privacy & TCC",
            title=f"TCC database unavailable: {database}", severity=Severity.INFORMATIONAL, status="Unknown",
            description="The macOS Transparency, Consent, and Control database could not be inspected read-only.",
            why_it_matters="Without TCC evidence, grants for sensitive data and device access cannot be independently validated.",
            what_was_checked="Read-only access to the system and current-user TCC databases.",
            expected_result="The database is available under the approved evidence-access policy.", observed_result=error,
            recommendation="Collect the database through an approved Full Disk Access or forensic workflow; do not alter the source database.",
            evidence=(Evidence("access_error", str(database), error),),
            references=("https://support.apple.com/guide/security/controlling-app-access-to-user-data-secddd1d86a6/web",),
        )

    def _service_findings(self, database: Path, grants: list[TCCGrant]) -> list[Finding]:
        grouped: dict[str, list[TCCGrant]] = defaultdict(list)
        for grant in grants:
            if grant.service in SENSITIVE_SERVICES:
                grouped[grant.service].append(grant)
        findings = []
        for service, service_grants in sorted(grouped.items()):
            allowed = [grant for grant in service_grants if grant.allowed]
            unknown = [grant for grant in service_grants if grant.auth_value not in {0, 2, 3}]
            label = SENSITIVE_SERVICES[service]
            if unknown:
                severity, status = Severity.INFORMATIONAL, "Unknown"
                conclusion = f"{len(unknown)} grant(s) have an unrecognized authorization value."
            elif allowed:
                severity, status = Severity.MEDIUM, "Review"
                conclusion = f"{len(allowed)} client grant(s) allow access."
            else:
                severity, status = Severity.INFORMATIONAL, "Pass"
                conclusion = "No allowed client grants were observed."
            sample = [{
                "client": grant.client, "auth_value": grant.auth_value,
                "auth_reason": grant.auth_reason, "last_modified": grant.last_modified,
            } for grant in service_grants[:50]]
            findings.append(Finding(
                finding_id=_finding_id(database, service), category="Privacy & TCC",
                title=f"TCC permission: {label}", severity=severity, status=status,
                description=f"Summarizes TCC grants for the sensitive service {label}.",
                why_it_matters="Privacy permissions can expose files, sensors, input, screens, or automation to applications.",
                what_was_checked=f"The access table in {database}; {len(service_grants)} row(s) for {service}.",
                expected_result="Sensitive access is explicitly authorized, attributable to known clients, and limited to business need.",
                observed_result=conclusion,
                recommendation="Review each allowed client, validate its publisher and business need, and revoke unnecessary access through approved macOS controls.",
                evidence=(Evidence("tcc_grants", str(database), {"service": service, "label": label, "rows": sample}),),
                references=("https://support.apple.com/guide/security/controlling-app-access-to-user-data-secddd1d86a6/web",),
            ))
        if not findings:
            findings.append(Finding(
                finding_id=_finding_id(database, "no-sensitive-services"), category="Privacy & TCC",
                title=f"TCC sensitive services: none observed in {database.name}", severity=Severity.INFORMATIONAL, status="Observed",
                description="The readable TCC database contained no rows for the sensitive services tracked by this collector.",
                why_it_matters="An empty result may indicate a clean database or a schema/collection scope that does not expose all grants.",
                what_was_checked="Tracked sensitive services in the TCC access table.", expected_result="The database can be read and its relevant grants are understood.",
                observed_result="No tracked sensitive-service rows were observed.", recommendation="Confirm collection scope and review the source database if privacy access is suspected.",
                evidence=(Evidence("tcc_grants", str(database), {"tracked_services": sorted(SENSITIVE_SERVICES), "row_count": 0}),),
                references=("https://support.apple.com/guide/security/controlling-app-access-to-user-data-secddd1d86a6/web",),
            ))
        return findings
