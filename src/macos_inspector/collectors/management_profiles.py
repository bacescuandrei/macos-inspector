from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


ENROLLMENT_RE = re.compile(
    r"^\s*(Enrolled via DEP|MDM enrollment)\s*:\s*(Yes|No)(?:\s*\([^\r\n]*\))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class EnrollmentStatus:
    dep_enrolled: bool | None = None
    mdm_enrolled: bool | None = None


def parse_configuration_profile_status(output: str) -> bool | None:
    normalized = " ".join(output.lower().split())
    if "no configuration profiles" in normalized and "installed" in normalized:
        return False
    if "configuration profiles" in normalized and "installed" in normalized:
        return True
    return None


def parse_enrollment_status(output: str) -> EnrollmentStatus:
    values = {label.lower(): value.lower() == "yes" for label, value in ENROLLMENT_RE.findall(output)}
    return EnrollmentStatus(values.get("enrolled via dep"), values.get("mdm enrollment"))


class ManagementProfilesCollector(Collector):
    collector_id = "management-profiles"
    title = "Management & configuration profiles"

    def collect(self) -> list[Finding]:
        return [self._configuration_profiles(), self._enrollment()]

    def _configuration_profiles(self) -> Finding:
        result = self.runner.run(("profiles", "status", "-type", "configuration"))
        installed = parse_configuration_profile_status(f"{result.stdout}\n{result.stderr}") if result.returncode == 0 and not result.timed_out else None
        if installed is True:
            severity, status = Severity.LOW, "Review"
            observed = "One or more configuration profiles are installed."
        elif installed is False:
            severity, status = Severity.INFORMATIONAL, "Pass"
            observed = "No configuration profiles are installed."
        else:
            severity, status = Severity.INFORMATIONAL, "Unknown"
            observed = result.stderr or result.stdout or f"Command returned exit status {result.returncode}."
        return Finding(
            finding_id="MANAGEMENT-CONFIGURATION-PROFILES", category="Device Management",
            title="Installed configuration profiles", severity=severity, status=status,
            description="Checks whether macOS configuration profiles are installed without requesting their potentially sensitive payloads.",
            why_it_matters="Configuration profiles can enforce certificates, proxies, VPNs, privacy permissions, restrictions, and security settings.",
            what_was_checked=result.command,
            expected_result="Every installed configuration profile is authorized, attributable, and consistent with the device-management policy.",
            observed_result=observed,
            recommendation="If profiles are present, review them through the approved device-management workflow and preserve attribution before removal.",
            evidence=(Evidence("configuration_profile_status", result.command, {
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "installed": installed,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }),),
            commands_used=(result.command,),
            references=("https://support.apple.com/guide/deployment/intro-to-mdm-profiles-depc0aadd3fe/web",),
        )

    def _enrollment(self) -> Finding:
        result = self.runner.run(("profiles", "status", "-type", "enrollment"))
        enrollment = parse_enrollment_status(f"{result.stdout}\n{result.stderr}") if result.returncode == 0 and not result.timed_out else EnrollmentStatus()
        known = enrollment.dep_enrolled is not None and enrollment.mdm_enrolled is not None
        if known:
            severity, status = Severity.INFORMATIONAL, "Observed"
            observed = (
                f"Automated Device Enrollment={'yes' if enrollment.dep_enrolled else 'no'}; "
                f"MDM enrollment={'yes' if enrollment.mdm_enrolled else 'no'}."
            )
        else:
            severity, status = Severity.INFORMATIONAL, "Unknown"
            observed = result.stderr or result.stdout or f"Command returned exit status {result.returncode}."
        return Finding(
            finding_id="MANAGEMENT-ENROLLMENT", category="Device Management",
            title="MDM and Automated Device Enrollment", severity=severity, status=status,
            description="Reads the local MDM and Automated Device Enrollment status without contacting or synchronizing with a management server.",
            why_it_matters="Device-management enrollment can remotely enforce configuration, install profiles, and change the host's security posture.",
            what_was_checked=result.command,
            expected_result="Enrollment state is known and attributable to the device owner or organization.",
            observed_result=observed,
            recommendation="Validate any enrollment against asset ownership and the approved MDM tenant; investigate unexpected management before making changes.",
            evidence=(Evidence("device_management_enrollment", result.command, {
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "dep_enrolled": enrollment.dep_enrolled,
                "mdm_enrolled": enrollment.mdm_enrolled,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }),),
            commands_used=(result.command,),
            references=("https://support.apple.com/guide/deployment/intro-to-mdm-profiles-depc0aadd3fe/web",),
        )
