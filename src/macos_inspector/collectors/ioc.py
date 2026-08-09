from __future__ import annotations

import hashlib
import json
import os
import plistlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .application_trust import DEFAULT_APPLICATION_ROOTS, _bundle_metadata, discover_applications
from .base import Collector
from .persistence import LAUNCH_PATHS
from macos_inspector.core.models import Evidence, Finding, Severity
from macos_inspector.core.storage import application_data_dir


MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024
SUPPORTED_TYPES = {"path", "sha256", "bundle_id", "launchd_label"}


@dataclass(frozen=True)
class IOCIndicator:
    indicator_id: str
    indicator_type: str
    value: str
    severity: Severity
    description: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class IOCPack:
    name: str
    version: str
    source: str
    updated_at: str
    path: Path
    indicators: tuple[IOCIndicator, ...]


def _parse_updated_at(value: Any) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_ioc_pack(path: Path) -> tuple[IOCPack | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("pack root must be an object")
        if payload.get("enabled", True) is False:
            return None, None
        if str(payload.get("schema_version")) != "1":
            raise ValueError("schema_version must be 1")
        name, version = str(payload["name"]).strip(), str(payload["version"]).strip()
        source_value = payload["source"]
        if isinstance(source_value, dict):
            source = str(source_value.get("url") or source_value.get("name") or "").strip()
        else:
            source = str(source_value).strip()
        updated_at = _parse_updated_at(payload["updated_at"]).isoformat()
        if not name or not version or not source:
            raise ValueError("name, version, and source must be non-empty")
        indicators = []
        for index, item in enumerate(payload.get("indicators", [])):
            if not isinstance(item, dict):
                raise ValueError(f"indicator {index} must be an object")
            indicator_type = str(item.get("type", "")).lower()
            if indicator_type not in SUPPORTED_TYPES:
                raise ValueError(f"indicator {index} has unsupported type: {indicator_type}")
            value = str(item.get("value", "")).strip()
            if not value:
                raise ValueError(f"indicator {index} has an empty value")
            indicator_id = str(item.get("id") or f"indicator-{index + 1}")
            severity = Severity.parse(str(item.get("severity", "high")))
            paths_value = item.get("paths", [])
            if isinstance(paths_value, str):
                paths_value = [paths_value]
            indicators.append(IOCIndicator(
                indicator_id, indicator_type, value, severity, str(item.get("description", "IOC match")),
                tuple(str(value) for value in paths_value),
            ))
        return IOCPack(name, version, source, updated_at, path, tuple(indicators)), None
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def discover_ioc_packs(directories: tuple[Path, ...]) -> tuple[list[IOCPack], list[tuple[Path, str]]]:
    packs, errors = [], []
    seen: set[Path] = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        try:
            candidates = sorted(directory.glob("*.json"))
        except OSError:
            continue
        for path in candidates:
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            pack, error = load_ioc_pack(path)
            if error:
                errors.append((path, error))
            elif pack:
                packs.append(pack)
    return packs, errors


def _file_sha256(path: Path) -> tuple[str | None, str | None]:
    try:
        size = path.stat().st_size
        if not path.is_file():
            return None, "Target is not a regular file."
        if size > MAX_HASH_BYTES:
            return None, f"Target exceeds the {MAX_HASH_BYTES}-byte hashing limit."
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest(), None
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _finding_id(pack: str, indicator: str) -> str:
    digest = hashlib.sha256(f"{pack}:{indicator}".encode()).hexdigest()[:12].upper()
    return f"IOC-{digest}"


class IOCCollector(Collector):
    collector_id = "ioc"
    title = "IOC packs"

    def __init__(self, runner, directories: tuple[Path, ...] | None = None) -> None:
        super().__init__(runner)
        self.directories = (
            Path.cwd() / "ioc-packs",
            application_data_dir() / "ioc-packs",
        ) if directories is None else directories
        self._bundle_ids: dict[str, list[str]] | None = None
        self._launchd_labels: dict[str, list[str]] | None = None

    def collect(self) -> list[Finding]:
        packs, errors = discover_ioc_packs(self.directories)
        findings = [self._pack_error(path, error) for path, error in errors]
        for pack in packs:
            findings.append(self._metadata_finding(pack))
            findings.extend(self._evaluate(pack, indicator) for indicator in pack.indicators)
        if not packs and not errors:
            findings.append(Finding(
                finding_id="IOC-NO-PACKS", category="IOC Matches", title="IOC packs",
                severity=Severity.INFORMATIONAL, status="Not Applicable",
                description="No enabled IOC packs were discovered.", why_it_matters="IOC provenance is required for reproducible threat matching.",
                what_was_checked=", ".join(str(path) for path in self.directories), expected_result="Approved IOC packs are present when IOC matching is required.",
                observed_result="No enabled IOC packs were found.", recommendation="Add a versioned JSON IOC pack with an explicit source and update date.",
                evidence=(Evidence("ioc_pack_discovery", "local", [str(path) for path in self.directories]),),
            ))
        return findings

    def _pack_error(self, path: Path, error: str) -> Finding:
        return Finding(
            finding_id=_finding_id(str(path), "error"), category="IOC Matches", title=f"Invalid IOC pack: {path.name}",
            severity=Severity.LOW, status="Unknown", description="An IOC pack could not be validated.",
            why_it_matters="Malformed or unprovenanced indicators can produce unreliable security conclusions.",
            what_was_checked=str(path), expected_result="The pack follows schema version 1 and declares provenance.", observed_result=error,
            recommendation="Correct or disable the pack before relying on IOC results.", evidence=(Evidence("ioc_pack_error", str(path), error),),
        )

    def _metadata_finding(self, pack: IOCPack) -> Finding:
        updated = _parse_updated_at(pack.updated_at)
        age_days = max(0, (datetime.now(timezone.utc) - updated).days)
        stale = age_days > 365
        return Finding(
            finding_id=_finding_id(pack.name, "metadata"), category="IOC Matches", title=f"IOC pack: {pack.name}",
            severity=Severity.LOW if stale else Severity.INFORMATIONAL, status="Review" if stale else "Pass",
            description="Validates IOC pack schema, provenance, version, and update date.", why_it_matters="Stale or unattributed indicators can create false confidence and false positives.",
            what_was_checked=str(pack.path), expected_result="The pack has explicit provenance and was updated within 365 days.",
            observed_result=f"Version {pack.version}; source={pack.source}; updated={pack.updated_at}; age={age_days} days; indicators={len(pack.indicators)}.",
            recommendation="Refresh stale packs from their authoritative source and preserve the prior version for reproducibility.",
            evidence=(Evidence("ioc_pack_metadata", str(pack.path), {"name": pack.name, "version": pack.version, "source": pack.source, "updated_at": pack.updated_at, "age_days": age_days}),),
        )

    def _evaluate(self, pack: IOCPack, indicator: IOCIndicator) -> Finding:
        matched, observed, evidence_value, unknown = self._match(indicator)
        severity = Severity.INFORMATIONAL if unknown or not matched else indicator.severity
        status = "Unknown" if unknown else ("Match" if matched else "Pass")
        return Finding(
            finding_id=_finding_id(pack.name, indicator.indicator_id), category="IOC Matches",
            title=f"IOC {indicator.indicator_type}: {indicator.indicator_id}", severity=severity, status=status,
            description=indicator.description, why_it_matters="A verified IOC match can connect host evidence to a documented threat source.",
            what_was_checked=f"{indicator.indicator_type}={indicator.value}", expected_result="No local artifact matches the indicator.",
            observed_result=observed,
            recommendation="For matches, preserve the source artifact, validate pack provenance, and investigate related activity before remediation.",
            evidence=(Evidence("ioc_evaluation", str(pack.path), {"pack": pack.name, "source": pack.source, "updated_at": pack.updated_at, "indicator": indicator.__dict__, "result": evidence_value}),),
        )

    def _match(self, indicator: IOCIndicator) -> tuple[bool, str, Any, bool]:
        if indicator.indicator_type == "path":
            path = Path(os.path.expanduser(indicator.value))
            exists = path.exists()
            return exists, f"Path {'exists' if exists else 'was not observed'}: {path}", {"path": str(path), "exists": exists}, False
        if indicator.indicator_type == "sha256":
            if not indicator.paths:
                return False, "SHA-256 indicator has no explicit target paths; unrestricted disk scanning is not performed.", {"paths": []}, True
            results = []
            matched = False
            for value in indicator.paths[:20]:
                path = Path(os.path.expanduser(value))
                digest, error = _file_sha256(path)
                current_match = bool(digest and digest.lower() == indicator.value.lower())
                matched = matched or current_match
                results.append({"path": str(path), "sha256": digest, "error": error, "match": current_match})
            return matched, f"SHA-256 {'matched' if matched else 'did not match'} across {len(results)} explicit target(s).", results, False
        if indicator.indicator_type == "bundle_id":
            matches = self._application_bundle_ids().get(indicator.value, [])
            return bool(matches), f"Bundle identifier matched {len(matches)} installed application(s).", matches, False
        matches = self._labels().get(indicator.value, [])
        return bool(matches), f"launchd label matched {len(matches)} property list(s).", matches, False

    def _application_bundle_ids(self) -> dict[str, list[str]]:
        if self._bundle_ids is None:
            values: dict[str, list[str]] = {}
            for bundle in discover_applications(DEFAULT_APPLICATION_ROOTS):
                metadata, _ = _bundle_metadata(bundle)
                identifier = metadata.get("CFBundleIdentifier")
                if identifier:
                    values.setdefault(str(identifier), []).append(str(bundle))
            self._bundle_ids = values
        return self._bundle_ids

    def _labels(self) -> dict[str, list[str]]:
        if self._launchd_labels is None:
            values: dict[str, list[str]] = {}
            directories = (*LAUNCH_PATHS, Path.home() / "Library/LaunchAgents")
            for directory in directories:
                try:
                    candidates = directory.glob("*.plist")
                    for path in candidates:
                        try:
                            data = plistlib.loads(path.read_bytes())
                            label = data.get("Label") if isinstance(data, dict) else None
                            if label:
                                values.setdefault(str(label), []).append(str(path))
                        except (OSError, plistlib.InvalidFileException):
                            continue
                except OSError:
                    continue
            self._launchd_labels = values
        return self._launchd_labels
