from __future__ import annotations

import importlib.util
import os
import platform
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from macos_inspector.collectors.application_trust import DEFAULT_APPLICATION_ROOTS, discover_applications
from macos_inspector.collectors.browser_artifacts import discover_browser_profiles
from macos_inspector.core.runner import CommandRunner


def _probe_sqlite_readable(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=0.5)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA schema_version").fetchone()
        return True
    except (OSError, sqlite3.Error):
        return False


def _available_commands() -> tuple[list[str], list[str]]:
    available, missing = [], []
    for name, executable in sorted(CommandRunner.ALLOWED.items()):
        target = Path(executable)
        (available if target.is_file() and os.access(target, os.X_OK) else missing).append(name)
    return available, missing


def _dependency_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _tcc_database_paths(home: Path) -> tuple[Path, Path]:
    return (
        Path("/Library/Application Support/com.apple.TCC/TCC.db"),
        home / "Library/Application Support/com.apple.TCC/TCC.db",
    )


def collect_readiness(output: Path, home: Path | None = None) -> dict:
    """Return bounded preflight diagnostics without exposing evidence content or paths."""
    home = Path.home() if home is None else home
    checks = []

    is_macos = platform.system() == "Darwin"
    checks.append({
        "id": "platform", "title": "macOS environment", "status": "ready" if is_macos else "unavailable",
        "detail": f"Detected {platform.system()} {platform.release()}.",
        "impact": "Collectors use macOS-specific system tools.",
        "action": "Run collection on a supported macOS host." if not is_macos else "No action required.",
    })

    python_ready = sys.version_info >= (3, 10)
    checks.append({
        "id": "python", "title": "Python runtime", "status": "ready" if python_ready else "unavailable",
        "detail": f"Python {platform.python_version()} is active.",
        "impact": "The dashboard requires Python 3.10 or newer.",
        "action": "Install Python 3.10 or newer." if not python_ready else "No action required.",
    })

    available, missing = _available_commands()
    checks.append({
        "id": "commands", "title": "Read-only system tools", "status": "ready" if not missing else "limited",
        "detail": f"{len(available)} of {len(CommandRunner.ALLOWED)} trusted commands are available."
        + (f" Missing: {', '.join(missing)}." if missing else ""),
        "impact": "Missing tools produce Unknown findings for the affected checks.",
        "action": "Use the standard macOS system installation." if missing else "No action required.",
    })

    output_ready = output.is_dir() and os.access(output, os.W_OK | os.X_OK)
    checks.append({
        "id": "output", "title": "Report storage", "status": "ready" if output_ready else "unavailable",
        "detail": "The private report directory is writable." if output_ready else "The report directory is not writable.",
        "impact": "Completed reports and job recovery data require local write access.",
        "action": "Choose a writable local directory." if not output_ready else "No action required.",
    })

    applications = discover_applications(DEFAULT_APPLICATION_ROOTS) if is_macos else []
    checks.append({
        "id": "applications", "title": "Application inventory", "status": "ready" if applications else "limited",
        "detail": f"{len(applications)} application bundle(s) are visible to Application Trust.",
        "impact": "Only visible application bundles can be assessed.",
        "action": "Confirm the current user and mounted-volume scope." if not applications else "No action required.",
    })

    tcc_databases = _tcc_database_paths(home)
    visible_tcc = [path for path in tcc_databases if path.is_file()]
    readable_tcc = sum(_probe_sqlite_readable(path) for path in visible_tcc)
    tcc_ready = bool(visible_tcc) and readable_tcc == len(visible_tcc)
    checks.append({
        "id": "tcc", "title": "TCC evidence access", "status": "ready" if tcc_ready else "limited",
        "detail": f"{readable_tcc} of {len(visible_tcc)} visible TCC database(s) can be opened read-only.",
        "impact": "Unavailable databases limit privacy-permission findings but do not stop other collectors.",
        "action": "If required by the case policy, grant the launcher Full Disk Access and restart it." if not tcc_ready else "No action required.",
    })

    profiles = discover_browser_profiles(home)
    history_databases = [profile.history_path for profile in profiles if profile.history_path.is_file()]
    readable_histories = sum(_probe_sqlite_readable(path) for path in history_databases)
    browser_ready = not profiles or (bool(history_databases) and readable_histories == len(history_databases))
    checks.append({
        "id": "browser", "title": "Browser evidence access", "status": "ready" if browser_ready else "limited",
        "detail": f"{len(profiles)} supported profile(s) are visible; {readable_histories} of {len(history_databases)} history database(s) are readable.",
        "impact": "Protected or locked databases reduce browser history and download coverage.",
        "action": "Close affected browsers or approve Full Disk Access when the collection policy allows it." if not browser_ready else "No action required.",
    })

    checks.append({
        "id": "pdf", "title": "PDF export", "status": "ready",
        "detail": "The built-in portable PDF engine is available.",
        "impact": "PDF reports can be generated without installing extra packages.",
        "action": "No action required.",
    })

    for identifier, title, dependency, impact, action in (
        ("signing", "Asymmetric evidence signing", "cryptography", "Unsigned and HMAC manifests remain available.", "Install the optional 'signing' dependency for Ed25519, RSA or EC signatures."),
    ):
        available = _dependency_available(dependency)
        checks.append({
            "id": identifier, "title": title, "status": "ready" if available else "optional",
            "detail": "Optional dependency is installed." if available else "Optional dependency is not installed.",
            "impact": impact, "action": "No action required." if available else action,
        })

    counts = {status: sum(check["status"] == status for check in checks) for status in ("ready", "limited", "unavailable", "optional")}
    overall = "unavailable" if counts["unavailable"] else "limited" if counts["limited"] else "ready"
    return {
        "schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall": overall, "summary": counts, "checks": checks,
    }
