from __future__ import annotations

import hashlib
import json
import plistlib
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity


MAX_RECENT_ROWS = 50
MAX_EXTENSIONS = 100


@dataclass(frozen=True)
class BrowserProfile:
    browser: str
    name: str
    kind: str
    path: Path
    history_path: Path
    extensions_path: Path | None = None


def discover_browser_profiles(home: Path = Path.home()) -> list[BrowserProfile]:
    profiles: list[BrowserProfile] = []
    safari = home / "Library/Safari"
    if safari.exists():
        profiles.append(BrowserProfile("Safari", "Default", "safari", safari, safari / "History.db", safari / "Extensions"))

    application_support = home / "Library/Application Support"
    chromium_roots = {
        "Google Chrome": application_support / "Google/Chrome",
        "Brave Browser": application_support / "BraveSoftware/Brave-Browser",
        "Microsoft Edge": application_support / "Microsoft Edge",
        "Chromium": application_support / "Chromium",
    }
    for browser, root in chromium_roots.items():
        if not root.is_dir():
            continue
        try:
            candidates = sorted(root.iterdir())
        except OSError:
            continue
        for candidate in candidates:
            if not candidate.is_dir() or not (candidate.name == "Default" or candidate.name.startswith("Profile ")):
                continue
            history = candidate / "History"
            extensions = candidate / "Extensions"
            if history.exists() or extensions.exists():
                profiles.append(BrowserProfile(browser, candidate.name, "chromium", candidate, history, extensions))

    firefox_root = application_support / "Firefox/Profiles"
    if firefox_root.is_dir():
        try:
            candidates = sorted(path for path in firefox_root.iterdir() if path.is_dir())
        except OSError:
            candidates = []
        for candidate in candidates:
            history = candidate / "places.sqlite"
            extensions = candidate / "extensions.json"
            if history.exists() or extensions.exists():
                profiles.append(BrowserProfile("Firefox", candidate.name, "firefox", candidate, history, extensions))
    return profiles


def _rows(database: Path, query: str) -> tuple[list[dict[str, Any]], str | None]:
    if not database.is_file():
        return [], "History database is not present."
    try:
        with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            return [dict(row) for row in connection.execute(query).fetchmany(MAX_RECENT_ROWS)], None
    except (OSError, sqlite3.Error) as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _iso_timestamp(value: Any, epoch: str) -> str | None:
    try:
        number = float(value)
        if epoch == "apple":
            timestamp = datetime(2001, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=number)
        elif epoch == "chromium":
            timestamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=number)
        else:
            timestamp = datetime.fromtimestamp(number / 1_000_000, tz=timezone.utc)
        return timestamp.isoformat()
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _chromium_extensions(path: Path | None) -> tuple[list[dict[str, str]], str | None]:
    if path is None or not path.is_dir():
        return [], None
    extensions = []
    try:
        identifiers = sorted(item for item in path.iterdir() if item.is_dir())
        for identifier in identifiers[:MAX_EXTENSIONS]:
            versions = sorted((item.name for item in identifier.iterdir() if item.is_dir()), reverse=True)
            extensions.append({"id": identifier.name, "version": versions[0] if versions else "unknown"})
        return extensions, None
    except OSError as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _firefox_extensions(path: Path | None) -> tuple[list[dict[str, Any]], str | None]:
    if path is None or not path.is_file():
        return [], None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        addons = payload.get("addons", []) if isinstance(payload, dict) else []
        return [{
            "id": addon.get("id"), "version": addon.get("version"), "active": addon.get("active"), "type": addon.get("type"),
        } for addon in addons[:MAX_EXTENSIONS] if isinstance(addon, dict)], None
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _safari_downloads(profile: BrowserProfile) -> tuple[list[dict[str, Any]], str | None]:
    path = profile.path / "Downloads.plist"
    if not path.is_file():
        return [], None
    try:
        payload = plistlib.loads(path.read_bytes())
        entries = payload.get("DownloadHistory", []) if isinstance(payload, dict) else []
        return [entry for entry in entries[:MAX_RECENT_ROWS] if isinstance(entry, dict)], None
    except (OSError, plistlib.InvalidFileException) as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _finding_id(profile: BrowserProfile) -> str:
    value = f"{profile.browser}:{profile.path}".encode("utf-8", "surrogateescape")
    return f"BROWSER-{hashlib.sha256(value).hexdigest()[:12].upper()}"


class BrowserArtifactsCollector(Collector):
    collector_id = "browser-artifacts"
    title = "Browser artifacts"

    def __init__(self, runner, home: Path | None = None) -> None:
        super().__init__(runner)
        self.home = Path.home() if home is None else home

    def collect(self) -> list[Finding]:
        profiles = discover_browser_profiles(self.home)
        if not profiles:
            return [Finding(
                finding_id="BROWSER-NO-PROFILES", category="Browser Artifacts", title="Supported browser profiles",
                severity=Severity.INFORMATIONAL, status="Not Applicable",
                description="No Safari, Chromium-family, or Firefox profile was visible for the current user.",
                why_it_matters="Browser profiles contain high-value execution, download, and navigation evidence.",
                what_was_checked="Known current-user browser profile locations.", expected_result="Installed browser profiles are discoverable.",
                observed_result="No supported browser profiles were observed.", recommendation="Confirm the user scope if browser activity is expected.",
                evidence=(Evidence("browser_profiles", str(self.home), []),),
            )]
        return [self._inspect(profile) for profile in profiles]

    def _inspect(self, profile: BrowserProfile) -> Finding:
        if profile.kind == "chromium":
            history, history_error = _rows(profile.history_path, "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50")
            for row in history:
                row["last_visit_at"] = _iso_timestamp(row.get("last_visit_time"), "chromium")
            downloads, downloads_error = _rows(profile.history_path, "SELECT target_path, tab_url, start_time, state, danger_type FROM downloads ORDER BY start_time DESC LIMIT 50")
            for row in downloads:
                row["started_at"] = _iso_timestamp(row.get("start_time"), "chromium")
            extensions, extensions_error = _chromium_extensions(profile.extensions_path)
        elif profile.kind == "firefox":
            history, history_error = _rows(profile.history_path, "SELECT p.url, p.title, p.visit_count, v.visit_date FROM moz_places p JOIN moz_historyvisits v ON v.place_id=p.id ORDER BY v.visit_date DESC LIMIT 50")
            for row in history:
                row["visited_at"] = _iso_timestamp(row.get("visit_date"), "unix-microseconds")
            downloads, downloads_error = [], None
            extensions, extensions_error = _firefox_extensions(profile.extensions_path)
        else:
            history, history_error = _rows(profile.history_path, "SELECT i.url, i.visit_count, v.title, v.visit_time FROM history_items i JOIN history_visits v ON v.history_item=i.id ORDER BY v.visit_time DESC LIMIT 50")
            for row in history:
                row["visited_at"] = _iso_timestamp(row.get("visit_time"), "apple")
            downloads, downloads_error = _safari_downloads(profile)
            extensions, extensions_error = _chromium_extensions(profile.extensions_path)

        errors = [error for error in (history_error, downloads_error, extensions_error) if error]
        accessible_sources = sum(error is None for error in (history_error, downloads_error, extensions_error))
        if accessible_sources == 0:
            status, severity = "Unknown", Severity.INFORMATIONAL
        elif extensions:
            status, severity = "Review", Severity.LOW
        else:
            status, severity = "Observed", Severity.INFORMATIONAL
        observed = f"{len(history)} recent history row(s), {len(downloads)} download row(s), and {len(extensions)} extension(s) observed."
        if errors:
            observed += f" {len(errors)} source(s) were unavailable."
        evidence = {
            "browser": profile.browser, "profile": profile.name, "path": str(profile.path),
            "recent_history": history, "recent_downloads": downloads, "extensions": extensions,
            "collection_notes": errors,
        }
        return Finding(
            finding_id=_finding_id(profile), category="Browser Artifacts", title=f"{profile.browser} profile: {profile.name}",
            severity=severity, status=status,
            description="Collects a bounded, read-only inventory of recent browser history, downloads, and extensions.",
            why_it_matters="Browser artifacts can establish user activity, downloaded payloads, phishing exposure, and extension-based persistence.",
            what_was_checked=f"Profile sources under {profile.path}; at most {MAX_RECENT_ROWS} recent rows per artifact type.",
            expected_result="Browser activity and extensions are attributable to expected users and approved software.", observed_result=observed,
            recommendation="Review unexpected downloads, navigation, and extensions; preserve the source profile before remediation.",
            evidence=(Evidence("browser_profile", str(profile.path), evidence),),
            mitre_attack=("T1185 - Browser Session Cookie", "T1176 - Browser Extensions"),
        )
