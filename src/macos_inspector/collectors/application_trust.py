from __future__ import annotations

import hashlib
import os
import plistlib
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity
from macos_inspector.core.runner import CommandResult


DEFAULT_APPLICATION_ROOTS = (
    Path("/Applications"),
    Path("/System/Applications"),
    Path.home() / "Applications",
)


@dataclass(frozen=True)
class SignatureDetails:
    identifier: str | None = None
    team_identifier: str | None = None
    authority: tuple[str, ...] = ()
    designated_requirement: str | None = None
    hardened_runtime: bool = False
    signature_type: str | None = None


@dataclass(frozen=True)
class GatekeeperDetails:
    source: str | None = None
    origin: str | None = None
    notarized: bool | None = None


@dataclass(frozen=True)
class QuarantineDetails:
    flags: str | None = None
    timestamp: int | None = None
    timestamp_iso: str | None = None
    agent: str | None = None
    origin_uuid: str | None = None


@dataclass(frozen=True)
class FileIntegrityDetails:
    sha256: str | None = None
    size_bytes: int | None = None
    modified_at: str | None = None
    permissions: str | None = None
    owner_uid: int | None = None
    owner_gid: int | None = None
    is_symlink: bool = False
    changed_during_read: bool = False
    error: str | None = None


@dataclass(frozen=True)
class BundlePathDetails:
    bundle_is_symlink: bool = False
    contents_is_symlink: bool = False
    macos_directory_is_symlink: bool = False
    info_plist_is_symlink: bool = False
    executable_resolves_within_bundle: bool | None = None
    resolved_executable: str | None = None
    resolution_error: str | None = None


SENSITIVE_ENTITLEMENTS = {
    "com.apple.security.get-task-allow": Severity.MEDIUM,
    "com.apple.security.cs.allow-unsigned-executable-memory": Severity.MEDIUM,
    "com.apple.security.cs.allow-dyld-environment-variables": Severity.MEDIUM,
    "com.apple.security.cs.disable-library-validation": Severity.LOW,
}

# Runtime exceptions are common in browsers, virtual machines, and Electron apps.
# Preserve them as evidence, but only a production-debug entitlement changes trust scoring by itself.
SCORE_AFFECTING_ENTITLEMENTS = {"com.apple.security.get-task-allow": Severity.MEDIUM}
MAX_INFO_PLIST_BYTES = 16 * 1024 * 1024


def parse_codesign_details(output: str) -> SignatureDetails:
    """Parse stable fields from codesign's mixed stdout/stderr output."""
    identifier = team_identifier = requirement = None
    authorities: list[str] = []
    hardened_runtime = False
    signature_value = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("Identifier="):
            identifier = line.partition("=")[2] or None
        elif line.startswith("TeamIdentifier="):
            value = line.partition("=")[2]
            team_identifier = None if value in {"", "not set"} else value
        elif line.startswith("Authority="):
            authorities.append(line.partition("=")[2])
        elif line.startswith("designated =>"):
            requirement = line
        elif line.startswith("Signature="):
            signature_value = line.partition("=")[2] or None
        elif line.startswith("Runtime Version=") or ("runtime" in line.lower() and line.startswith("flags=")):
            hardened_runtime = True
    usable_authorities = [authority for authority in authorities if authority.strip().lower() not in {"", "(unavailable)", "unavailable"}]
    authority_text = " ".join(usable_authorities).lower()
    if signature_value and "adhoc" in signature_value.lower():
        signature_type = "Ad hoc"
    elif "developer id application" in authority_text:
        signature_type = "Developer ID"
    elif "apple distribution" in authority_text or "apple development" in authority_text:
        signature_type = "Apple development/distribution"
    elif any("apple" in authority.lower() for authority in usable_authorities):
        signature_type = "Apple"
    elif usable_authorities:
        signature_type = usable_authorities[0]
    else:
        signature_type = None
    return SignatureDetails(identifier, team_identifier, tuple(authorities), requirement, hardened_runtime, signature_type)


def parse_gatekeeper_details(output: str) -> GatekeeperDetails:
    source = origin = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("source="):
            source = line.partition("=")[2] or None
        elif line.lower().startswith("origin="):
            origin = line.partition("=")[2] or None
    notarized = None if source is None else "notarized" in source.lower()
    return GatekeeperDetails(source, origin, notarized)


def _json_safe_plist(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe_plist(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_plist(item) for item in value]
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def parse_entitlements(output: str) -> tuple[dict[str, Any], str | None]:
    """Extract XML or modern abstract-format entitlements from codesign output."""
    starts = [index for marker in ("<?xml", "<plist") if (index := output.find(marker)) >= 0]
    end = output.rfind("</plist>")
    if starts and end >= 0:
        try:
            payload = plistlib.loads(output[min(starts):end + len("</plist>")].encode("utf-8"))
            if not isinstance(payload, dict):
                return {}, "Entitlement plist is not a dictionary."
            return _json_safe_plist(payload), None
        except (ValueError, plistlib.InvalidFileException) as exc:
            return {}, f"{type(exc).__name__}: {exc}"

    tokens: list[tuple[int, str, str]] = []
    for raw_line in output.splitlines():
        match = re.match(r"^(\s*)\[([^]]+)](?:\s(.*))?$", raw_line)
        if match:
            tokens.append((len(match.group(1).expandtabs(4)), match.group(2), match.group(3) or ""))
    root = next((index for index, (_, tag, _) in enumerate(tokens) if tag == "Dict"), None)
    if root is None:
        return {}, None

    def parse_node(index: int) -> tuple[Any, int]:
        indent, tag, text = tokens[index]
        if tag == "Bool":
            return text.strip().lower() == "true", index + 1
        if tag == "Int":
            try:
                return int(text.strip()), index + 1
            except ValueError:
                return text, index + 1
        if tag == "Real":
            try:
                return float(text.strip()), index + 1
            except ValueError:
                return text, index + 1
        if tag in {"String", "Date", "Data"}:
            return text, index + 1
        if tag == "Array":
            values = []
            cursor = index + 1
            while cursor < len(tokens) and tokens[cursor][0] > indent:
                value, cursor = parse_node(cursor)
                values.append(value)
            return values, cursor
        if tag == "Dict":
            values = {}
            cursor = index + 1
            while cursor < len(tokens) and tokens[cursor][0] > indent:
                key_indent, key_tag, key = tokens[cursor]
                if key_tag != "Key":
                    cursor += 1
                    continue
                cursor += 1
                if cursor >= len(tokens) or tokens[cursor][1] != "Value" or tokens[cursor][0] != key_indent:
                    values[key] = None
                    continue
                cursor += 1
                if cursor >= len(tokens) or tokens[cursor][0] <= key_indent:
                    values[key] = None
                    continue
                values[key], cursor = parse_node(cursor)
            return values, cursor
        return text, index + 1

    payload, _ = parse_node(root)
    return (_json_safe_plist(payload), None) if isinstance(payload, dict) else ({}, "Entitlement output is not a dictionary.")


def assess_entitlements(entitlements: dict[str, Any]) -> tuple[tuple[str, ...], Severity | None]:
    sensitive = tuple(sorted(name for name in SENSITIVE_ENTITLEMENTS if entitlements.get(name) is True))
    severity = max((SCORE_AFFECTING_ENTITLEMENTS[name] for name in sensitive if name in SCORE_AFFECTING_ENTITLEMENTS), default=None)
    return sensitive, severity


def parse_quarantine(value: str) -> QuarantineDetails:
    parts = value.strip().split(";")
    parts += [""] * (4 - len(parts))
    timestamp = None
    timestamp_iso = None
    try:
        timestamp = int(parts[1], 16)
        timestamp_iso = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    except (ValueError, OSError, OverflowError):
        pass
    return QuarantineDetails(
        flags=parts[0] or None,
        timestamp=timestamp,
        timestamp_iso=timestamp_iso,
        agent=parts[2] or None,
        origin_uuid=parts[3] or None,
    )


def parse_where_froms_hex(output: str) -> tuple[tuple[str, ...], str | None]:
    try:
        payload = plistlib.loads(bytes.fromhex("".join(output.split())))
        if not isinstance(payload, list):
            return (), "Download-source metadata is not a list."
        return tuple(str(item) for item in payload[:20]), None
    except (ValueError, plistlib.InvalidFileException) as exc:
        return (), f"{type(exc).__name__}: {exc}"


def inspect_file_integrity(path: Path | None) -> FileIntegrityDetails:
    """Hash a file without following mutable path metadata after it is opened."""
    if path is None:
        return FileIntegrityDetails(error="No executable was declared by the application bundle.")
    is_symlink = path.is_symlink()
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(handle.fileno())
        changed = (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns)
        return FileIntegrityDetails(
            sha256=digest.hexdigest(),
            size_bytes=before.st_size,
            modified_at=datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(),
            permissions=f"{stat.S_IMODE(before.st_mode):04o}",
            owner_uid=before.st_uid,
            owner_gid=before.st_gid,
            is_symlink=is_symlink,
            changed_during_read=changed,
        )
    except OSError as exc:
        return FileIntegrityDetails(is_symlink=is_symlink, error=f"{type(exc).__name__}: {exc}")


def assess_file_integrity(details: FileIntegrityDetails) -> tuple[tuple[Severity, str, str], ...]:
    """Return explicit trust concerns without treating collection gaps as compliance."""
    if details.error or not details.sha256:
        return ((
            Severity.INFORMATIONAL,
            "Unknown",
            "The main executable could not be hashed, so file-integrity coverage is incomplete.",
        ),)

    assessments: list[tuple[Severity, str, str]] = []
    if details.changed_during_read:
        assessments.append((
            Severity.MEDIUM,
            "Review",
            "The main executable changed while it was being hashed; reacquire it before relying on the digest.",
        ))

    mode = None
    if details.permissions:
        try:
            mode = int(details.permissions, 8)
        except ValueError:
            assessments.append((
                Severity.INFORMATIONAL,
                "Unknown",
                "The main executable's permission mode could not be interpreted.",
            ))
    if mode is not None:
        if not mode & 0o111:
            assessments.append((
                Severity.MEDIUM,
                "Review",
                "The declared main executable has no executable permission bits.",
            ))
        if mode & 0o002:
            assessments.append((
                Severity.HIGH,
                "Review",
                "The main executable is world-writable and can be replaced by other local users.",
            ))
        elif mode & 0o020:
            assessments.append((
                Severity.MEDIUM,
                "Review",
                "The main executable is group-writable and its ownership context requires review.",
            ))
    if details.is_symlink:
        assessments.append((
            Severity.LOW,
            "Review",
            "The declared main executable is a symbolic link; validate the resolved target and ownership.",
        ))
    return tuple(assessments)


def inspect_bundle_paths(bundle: Path, executable: Path | None) -> BundlePathDetails:
    info_path = bundle / "Contents" / "Info.plist"
    contents = bundle / "Contents"
    macos_directory = contents / "MacOS"
    inside = None
    resolved_executable = None
    resolution_error = None
    if executable is not None:
        try:
            resolved_bundle = bundle.resolve(strict=True)
            resolved_path = executable.resolve(strict=True)
            resolved_executable = str(resolved_path)
            inside = resolved_path == resolved_bundle or resolved_bundle in resolved_path.parents
        except OSError as exc:
            resolution_error = f"{type(exc).__name__}: {exc}"
    return BundlePathDetails(
        bundle_is_symlink=bundle.is_symlink(),
        contents_is_symlink=contents.is_symlink(),
        macos_directory_is_symlink=macos_directory.is_symlink(),
        info_plist_is_symlink=info_path.is_symlink(),
        executable_resolves_within_bundle=inside,
        resolved_executable=resolved_executable,
        resolution_error=resolution_error,
    )


def assess_bundle_paths(details: BundlePathDetails) -> tuple[tuple[Severity, str, str], ...]:
    assessments: list[tuple[Severity, str, str]] = []
    if details.resolution_error:
        assessments.append((
            Severity.INFORMATIONAL,
            "Unknown",
            "The main executable's resolved path could not be verified.",
        ))
    elif details.executable_resolves_within_bundle is False:
        assessments.append((
            Severity.HIGH,
            "Review",
            "The declared main executable resolves outside the application bundle.",
        ))
    if details.bundle_is_symlink:
        assessments.append((
            Severity.LOW,
            "Review",
            "The application bundle itself is a symbolic link; validate its resolved location.",
        ))
    if details.contents_is_symlink or details.macos_directory_is_symlink:
        assessments.append((
            Severity.MEDIUM,
            "Review",
            "An application code directory is a symbolic link and redirects the expected bundle structure.",
        ))
    if details.info_plist_is_symlink:
        assessments.append((
            Severity.LOW,
            "Review",
            "Info.plist is a symbolic link; validate its resolved source and ownership.",
        ))
    return tuple(assessments)


def assess_metadata_integrity(details: FileIntegrityDetails) -> tuple[tuple[Severity, str, str], ...]:
    if details.error or not details.sha256:
        return ((
            Severity.INFORMATIONAL,
            "Unknown",
            "Info.plist could not be captured and hashed reliably.",
        ),)
    assessments: list[tuple[Severity, str, str]] = []
    if details.changed_during_read:
        assessments.append((
            Severity.MEDIUM,
            "Review",
            "Info.plist changed while it was being read; reacquire bundle metadata.",
        ))
    if details.permissions:
        try:
            mode = int(details.permissions, 8)
            if mode & 0o002:
                assessments.append((
                    Severity.HIGH,
                    "Review",
                    "Info.plist is world-writable and can be altered by other local users.",
                ))
            elif mode & 0o020:
                assessments.append((
                    Severity.MEDIUM,
                    "Review",
                    "Info.plist is group-writable and its ownership context requires review.",
                ))
        except ValueError:
            assessments.append((
                Severity.INFORMATIONAL,
                "Unknown",
                "Info.plist permission mode could not be interpreted.",
            ))
    return tuple(assessments)


def merge_trust_assessments(
    base: tuple[Severity, str, str],
    assessments: tuple[tuple[Severity, str, str], ...],
) -> tuple[Severity, str, str]:
    severity, status, conclusion = base
    for candidate_severity, candidate_status, reason in assessments:
        conclusion = f"{conclusion} {reason}"
        if status == "Fail":
            continue
        if candidate_status == "Review" and (status != "Review" or candidate_severity > severity):
            severity, status = candidate_severity, candidate_status
        elif candidate_status == "Unknown" and status == "Pass":
            severity, status = candidate_severity, candidate_status
    return severity, status, conclusion


def classify_trust(
    executable_exists: bool,
    signature_result: CommandResult,
    assessment_result: CommandResult,
    details: SignatureDetails | None = None,
    gatekeeper: GatekeeperDetails | None = None,
) -> tuple[Severity, str, str]:
    combined = f"{signature_result.stdout}\n{signature_result.stderr}".lower()
    assessment_output = f"{assessment_result.stdout}\n{assessment_result.stderr}".lower()
    unsigned = "code object is not signed" in combined or "not signed at all" in combined
    if not executable_exists:
        return Severity.HIGH, "Fail", "The application bundle's declared executable is missing."
    if signature_result.timed_out or signature_result.returncode in {124, 126, 127}:
        return Severity.INFORMATIONAL, "Unknown", "Code-signature verification was unavailable or timed out."
    if any(token in combined for token in (
        "cssmerr_tp_not_trusted", "internal error in code signing subsystem", "resource temporarily unavailable",
    )):
        return Severity.INFORMATIONAL, "Unknown", "The local code-signing trust service could not complete verification."
    if signature_result.returncode != 0:
        reason = "The application is unsigned." if unsigned else "The code signature is invalid or could not be verified."
        return Severity.HIGH, "Fail", reason
    if assessment_result.timed_out or assessment_result.returncode in {124, 126, 127} or "internal error" in assessment_output:
        return Severity.INFORMATIONAL, "Unknown", "Gatekeeper assessment was unavailable or returned an internal error."
    if assessment_result.returncode != 0 and "rejected" in assessment_output:
        return Severity.MEDIUM, "Fail", "Gatekeeper did not accept the application."
    if assessment_result.returncode != 0:
        return Severity.INFORMATIONAL, "Unknown", "Gatekeeper did not return a definitive assessment."
    if details and details.signature_type == "Ad hoc":
        return Severity.LOW, "Review", "The signature is valid and Gatekeeper accepted the application, but the bundle uses an ad-hoc signing identity."
    if details and not details.authority and not details.team_identifier:
        return Severity.LOW, "Review", "The signature is valid and Gatekeeper accepted the application, but no signing authority or team identity was reported."
    return Severity.INFORMATIONAL, "Pass", "The signature is valid and Gatekeeper accepted the application."


def discover_applications(roots: tuple[Path, ...] = DEFAULT_APPLICATION_ROOTS) -> list[Path]:
    """Return top-level apps and apps grouped one directory below a root."""
    applications: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        try:
            children = tuple(root.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_dir() and child.suffix.lower() == ".app":
                applications.add(child)
                continue
            if not child.is_dir():
                continue
            try:
                applications.update(item for item in child.iterdir() if item.is_dir() and item.suffix.lower() == ".app")
            except OSError:
                continue
    return sorted(applications, key=lambda path: str(path).casefold())


def _bundle_metadata_with_integrity(bundle: Path) -> tuple[dict[str, object], str | None, FileIntegrityDetails]:
    info_path = bundle / "Contents" / "Info.plist"
    is_symlink = info_path.is_symlink()
    try:
        with info_path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > MAX_INFO_PLIST_BYTES:
                error = f"Info.plist exceeds the {MAX_INFO_PLIST_BYTES}-byte safety limit."
                return {}, error, FileIntegrityDetails(
                    size_bytes=before.st_size,
                    modified_at=datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(),
                    permissions=f"{stat.S_IMODE(before.st_mode):04o}",
                    owner_uid=before.st_uid,
                    owner_gid=before.st_gid,
                    is_symlink=is_symlink,
                    error=error,
                )
            raw = stream.read(MAX_INFO_PLIST_BYTES + 1)
            after = os.fstat(stream.fileno())
        changed = (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns)
        integrity = FileIntegrityDetails(
            sha256=hashlib.sha256(raw).hexdigest(),
            size_bytes=before.st_size,
            modified_at=datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(),
            permissions=f"{stat.S_IMODE(before.st_mode):04o}",
            owner_uid=before.st_uid,
            owner_gid=before.st_gid,
            is_symlink=is_symlink,
            changed_during_read=changed,
        )
        value = plistlib.loads(raw)
        error = None if isinstance(value, dict) else "Info.plist root is not a dictionary."
        return (value if isinstance(value, dict) else {}), error, integrity
    except (OSError, plistlib.InvalidFileException) as exc:
        error = f"{type(exc).__name__}: {exc}"
        return {}, error, FileIntegrityDetails(is_symlink=is_symlink, error=error)


def _bundle_metadata(bundle: Path) -> tuple[dict[str, object], str | None]:
    metadata, error, _ = _bundle_metadata_with_integrity(bundle)
    return metadata, error


def _finding_id(bundle: Path) -> str:
    digest = hashlib.sha256(str(bundle).encode("utf-8", "surrogateescape")).hexdigest()[:12].upper()
    return f"APP-TRUST-{digest}"


class ApplicationTrustCollector(Collector):
    collector_id = "application-trust"
    title = "Application trust"

    def __init__(self, runner, roots: tuple[Path, ...] | None = None) -> None:
        super().__init__(runner)
        self.roots = roots if roots is not None else DEFAULT_APPLICATION_ROOTS

    def collect(self) -> list[Finding]:
        applications = discover_applications(self.roots)
        findings = []
        for index, bundle in enumerate(applications, start=1):
            self.report_progress(bundle.name, index - 1, len(applications))
            findings.append(self._inspect(bundle))
        self.report_progress(None, len(applications), len(applications))
        return findings

    def _inspect(self, bundle: Path) -> Finding:
        metadata, plist_error, plist_integrity = _bundle_metadata_with_integrity(bundle)
        executable_name = metadata.get("CFBundleExecutable")
        executable = bundle / "Contents" / "MacOS" / str(executable_name) if executable_name else None
        executable_exists = bool(executable and executable.is_file())
        executable_integrity = inspect_file_integrity(executable)
        bundle_paths = inspect_bundle_paths(bundle, executable)

        signature = self.runner.run(("codesign", "--verify", "--deep", "--strict", "--verbose=2", str(bundle)))
        details_result = self.runner.run(("codesign", "--display", "--verbose=4", "--requirements", "-", str(bundle)))
        entitlements_result = self.runner.run(("codesign", "--display", "--entitlements", "-", str(bundle)))
        assessment = self.runner.run(("spctl", "--assess", "--type", "execute", "--verbose=4", str(bundle)))
        quarantine = self.runner.run(("xattr", "-p", "com.apple.quarantine", str(bundle)))
        where_froms = self.runner.run(("xattr", "-px", "com.apple.metadata:kMDItemWhereFroms", str(bundle)))
        details_output = f"{details_result.stdout}\n{details_result.stderr}"
        details = parse_codesign_details(details_output)
        entitlements_output = f"{entitlements_result.stdout}\n{entitlements_result.stderr}"
        entitlements, entitlements_error = parse_entitlements(entitlements_output)
        sensitive_entitlements, entitlement_severity = assess_entitlements(entitlements)
        gatekeeper = parse_gatekeeper_details(f"{assessment.stdout}\n{assessment.stderr}")
        quarantine_details = parse_quarantine(quarantine.stdout) if quarantine.returncode == 0 else QuarantineDetails()
        download_sources, download_sources_error = parse_where_froms_hex(where_froms.stdout) if where_froms.returncode == 0 else ((), None)
        supplemental_assessments = list(assess_file_integrity(executable_integrity))
        supplemental_assessments.extend(assess_bundle_paths(bundle_paths))
        supplemental_assessments.extend(assess_metadata_integrity(plist_integrity))
        if entitlement_severity is not None:
            supplemental_assessments.append((
                entitlement_severity,
                "Review",
                "The application requests security-sensitive entitlements that warrant review.",
            ))
        severity, status, conclusion = merge_trust_assessments(
            classify_trust(executable_exists, signature, assessment, details, gatekeeper),
            tuple(supplemental_assessments),
        )

        display_name = metadata.get("CFBundleDisplayName") or metadata.get("CFBundleName") or bundle.stem
        version = metadata.get("CFBundleShortVersionString") or metadata.get("CFBundleVersion")
        observed = (
            f"{conclusion} Identifier={details.identifier or metadata.get('CFBundleIdentifier') or 'unknown'}; "
            f"team={details.team_identifier or 'none'}; version={version or 'unknown'}; "
            f"signature={details.signature_type or 'unknown'}; hardened_runtime={'yes' if details.hardened_runtime else 'no'}; "
            f"executable_sha256={executable_integrity.sha256 or 'unavailable'}; "
            f"executable_mode={executable_integrity.permissions or 'unknown'}; "
            f"executable_owner={executable_integrity.owner_uid if executable_integrity.owner_uid is not None else 'unknown'}:"
            f"{executable_integrity.owner_gid if executable_integrity.owner_gid is not None else 'unknown'}; "
            f"info_plist_sha256={plist_integrity.sha256 or 'unavailable'}; "
            f"executable_inside_bundle={('yes' if bundle_paths.executable_resolves_within_bundle else 'no') if bundle_paths.executable_resolves_within_bundle is not None else 'unknown'}; "
            f"gatekeeper_source={gatekeeper.source or 'unknown'}; notarized={('yes' if gatekeeper.notarized else 'no') if gatekeeper.notarized is not None else 'unknown'}; "
            f"sensitive_entitlements={','.join(sensitive_entitlements) or 'none'}; "
            f"quarantine={'present' if quarantine.returncode == 0 else 'absent or inaccessible'}; "
            f"download_source={download_sources[0] if download_sources else 'unknown'}."
        )
        evidence = (
            Evidence("application_bundle", str(bundle), {
                "name": str(display_name), "version": version, "bundle_identifier": metadata.get("CFBundleIdentifier"),
                "executable": str(executable) if executable else None, "executable_exists": executable_exists,
                "info_plist_error": plist_error,
            }),
            Evidence("bundle_path_integrity", str(bundle), {
                "bundle_is_symlink": bundle_paths.bundle_is_symlink,
                "contents_is_symlink": bundle_paths.contents_is_symlink,
                "macos_directory_is_symlink": bundle_paths.macos_directory_is_symlink,
                "info_plist_is_symlink": bundle_paths.info_plist_is_symlink,
                "executable_resolves_within_bundle": bundle_paths.executable_resolves_within_bundle,
                "resolved_executable": bundle_paths.resolved_executable,
                "resolution_error": bundle_paths.resolution_error,
            }),
            Evidence("info_plist_integrity", str(bundle / "Contents" / "Info.plist"), {
                "sha256": plist_integrity.sha256,
                "size_bytes": plist_integrity.size_bytes,
                "modified_at": plist_integrity.modified_at,
                "permissions": plist_integrity.permissions,
                "owner_uid": plist_integrity.owner_uid,
                "owner_gid": plist_integrity.owner_gid,
                "is_symlink": plist_integrity.is_symlink,
                "changed_during_read": plist_integrity.changed_during_read,
                "error": plist_integrity.error,
            }),
            Evidence("code_signature", str(bundle), {
                "valid": signature.returncode == 0, "identifier": details.identifier,
                "team_identifier": details.team_identifier, "authority": details.authority,
                "designated_requirement": details.designated_requirement, "hardened_runtime": details.hardened_runtime,
                "signature_type": details.signature_type,
                "verify_stdout": signature.stdout, "verify_stderr": signature.stderr,
            }),
            Evidence("executable_integrity", str(executable) if executable else str(bundle), {
                "sha256": executable_integrity.sha256,
                "size_bytes": executable_integrity.size_bytes,
                "modified_at": executable_integrity.modified_at,
                "permissions": executable_integrity.permissions,
                "owner_uid": executable_integrity.owner_uid,
                "owner_gid": executable_integrity.owner_gid,
                "is_symlink": executable_integrity.is_symlink,
                "changed_during_read": executable_integrity.changed_during_read,
                "error": executable_integrity.error,
            }),
            Evidence("code_entitlements", str(bundle), {
                "count": len(entitlements), "values": entitlements, "sensitive": sensitive_entitlements,
                "parse_error": entitlements_error, "command_returncode": entitlements_result.returncode,
            }),
            Evidence("gatekeeper_assessment", str(bundle), {
                "accepted": assessment.returncode == 0, "stdout": assessment.stdout, "stderr": assessment.stderr,
                "source": gatekeeper.source, "origin": gatekeeper.origin, "notarized": gatekeeper.notarized,
            }),
            Evidence("quarantine_attribute", str(bundle), {
                "present": quarantine.returncode == 0, "raw": quarantine.stdout if quarantine.returncode == 0 else None,
                "flags": quarantine_details.flags, "timestamp": quarantine_details.timestamp,
                "timestamp_iso": quarantine_details.timestamp_iso, "agent": quarantine_details.agent,
                "origin_uuid": quarantine_details.origin_uuid,
            }),
            Evidence("download_sources", str(bundle), {
                "sources": download_sources, "parse_error": download_sources_error,
            }),
        )
        return Finding(
            finding_id=_finding_id(bundle), category="Application Trust", title=f"Application trust: {display_name}",
            severity=severity, status=status,
            description="Validates an installed application's bundle metadata, executable hash and filesystem integrity, code signature, entitlements, acquisition source, and Gatekeeper assessment.",
            why_it_matters="Unsigned, modified, or policy-rejected applications can indicate untrusted software or post-installation tampering.",
            what_was_checked="Main executable and Info.plist SHA-256, ownership, permissions and read stability; bundle path containment; signature integrity and identity; code entitlements; Gatekeeper policy; quarantine metadata; and recorded download sources.",
            expected_result="The declared executable remains inside the bundle, executable and metadata files can be hashed without changing, neither is group/world-writable, the code signature is valid, and Gatekeeper accepts the application.",
            observed_result=observed,
            recommendation="For failures or integrity reviews, preserve the bundle and metadata, reacquire unstable hashes, validate path resolution, filesystem ownership, publisher and acquisition source, and investigate before execution or removal.",
            evidence=evidence,
            commands_used=(signature.command, details_result.command, entitlements_result.command, assessment.command, quarantine.command, where_froms.command),
            mitre_attack=("T1553.001 - Gatekeeper Bypass", "T1036 - Masquerading", "T1222.002 - Linux and Mac File and Directory Permissions Modification"),
            references=("https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web",),
        )
