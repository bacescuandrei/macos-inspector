from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from macos_inspector.core.io import read_json_limited
from macos_inspector.reporters.common import secure_write_text


MAX_TEXT = 2_000
MAX_STORE_BYTES = 8 * 1024 * 1024
CASE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$")


def application_data_dir() -> Path:
    override = os.environ.get("MACOS_INSPECTOR_DATA_DIR")
    if override:
        root = Path(override).expanduser()
    elif os.uname().sysname == "Darwin":
        root = Path.home() / "Library" / "Application Support" / "macOS Inspector"
    else:
        root = Path.home() / ".config" / "macos-inspector"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    return root


def _read_object(path: Path) -> dict[str, Any]:
    try:
        payload = read_json_limited(path, MAX_STORE_BYTES)
        return payload if isinstance(payload, dict) else {}
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {}


class SettingsStore:
    DEFAULTS: dict[str, Any] = {
        "schema_version": 1,
        "cache_hours": 24,
        "providers": {
            "cisa": {"enabled": True},
            "apple": {"enabled": True},
            "epss": {"enabled": True},
            "nvd": {"enabled": True, "api_key": ""},
            "threatfox": {"enabled": False, "auth_key": ""},
        },
        "yara": {
            "enabled": False,
            "targets": ["~/Downloads", "~/Library/LaunchAgents", "/Library/LaunchDaemons"],
        },
        "signing": {"enabled": False, "key_path": "", "algorithm": ""},
    }

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or application_data_dir()).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.path = self.root / "settings.json"

    def load(self) -> dict[str, Any]:
        raw = _read_object(self.path)
        defaults = json.loads(json.dumps(self.DEFAULTS))
        cache_hours = raw.get("cache_hours", defaults["cache_hours"])
        defaults["cache_hours"] = max(1, min(168, int(cache_hours))) if isinstance(cache_hours, int) else 24
        for name, provider in defaults["providers"].items():
            supplied = raw.get("providers", {}).get(name, {}) if isinstance(raw.get("providers"), dict) else {}
            if isinstance(supplied, dict):
                provider["enabled"] = bool(supplied.get("enabled", provider["enabled"]))
                for secret in ("api_key", "auth_key"):
                    if secret in provider and isinstance(supplied.get(secret), str):
                        provider[secret] = supplied[secret][:512]
        yara = raw.get("yara") if isinstance(raw.get("yara"), dict) else {}
        defaults["yara"]["enabled"] = bool(yara.get("enabled", False))
        targets = yara.get("targets")
        if isinstance(targets, list):
            defaults["yara"]["targets"] = [str(item)[:1024] for item in targets[:10] if str(item).strip()]
        signing = raw.get("signing") if isinstance(raw.get("signing"), dict) else {}
        defaults["signing"]["enabled"] = bool(signing.get("enabled", False))
        if isinstance(signing.get("key_path"), str):
            defaults["signing"]["key_path"] = signing["key_path"][:1024]
        if signing.get("algorithm") in {"HMAC-SHA256", "Ed25519"}:
            defaults["signing"]["algorithm"] = signing["algorithm"]
        return defaults

    def public(self) -> dict[str, Any]:
        settings = self.load()
        for provider in settings["providers"].values():
            for secret in ("api_key", "auth_key"):
                if secret in provider:
                    provider[f"{secret}_configured"] = bool(provider[secret])
                    provider.pop(secret, None)
        signing = settings["signing"]
        signing["key_configured"] = bool(signing.pop("key_path", ""))
        return settings

    def update(self, supplied: object) -> dict[str, Any]:
        if not isinstance(supplied, dict):
            raise ValueError("Settings must be a JSON object.")
        current = self.load()
        if "cache_hours" in supplied:
            value = supplied["cache_hours"]
            if not isinstance(value, int) or not 1 <= value <= 168:
                raise ValueError("Cache duration must be between 1 and 168 hours.")
            current["cache_hours"] = value
        providers = supplied.get("providers")
        if providers is not None:
            if not isinstance(providers, dict) or set(providers) - set(current["providers"]):
                raise ValueError("Unknown OSINT provider.")
            for name, values in providers.items():
                if not isinstance(values, dict):
                    raise ValueError("Provider settings must be objects.")
                if "enabled" in values:
                    current["providers"][name]["enabled"] = bool(values["enabled"])
                for secret in ("api_key", "auth_key"):
                    if secret in current["providers"][name] and secret in values:
                        if not isinstance(values[secret], str) or len(values[secret]) > 512:
                            raise ValueError("Provider credentials are invalid.")
                        current["providers"][name][secret] = values[secret].strip()
        yara = supplied.get("yara")
        if yara is not None:
            if not isinstance(yara, dict):
                raise ValueError("YARA settings must be an object.")
            if "enabled" in yara:
                current["yara"]["enabled"] = bool(yara["enabled"])
            if "targets" in yara:
                if not isinstance(yara["targets"], list) or len(yara["targets"]) > 10:
                    raise ValueError("YARA targets must be a list of at most 10 paths.")
                targets = []
                for value in yara["targets"]:
                    text = str(value).strip()
                    if not text or len(text) > 1024 or "\x00" in text:
                        raise ValueError("YARA target path is invalid.")
                    targets.append(text)
                current["yara"]["targets"] = targets
        signing = supplied.get("signing")
        if signing is not None:
            if not isinstance(signing, dict):
                raise ValueError("Signing settings must be an object.")
            if "enabled" in signing:
                current["signing"]["enabled"] = bool(signing["enabled"])
            if "key_path" in signing:
                value = str(signing["key_path"]).strip()
                if len(value) > 1024 or "\x00" in value:
                    raise ValueError("Signing key path is invalid.")
                current["signing"]["key_path"] = value
            if "algorithm" in signing:
                if signing["algorithm"] not in {"", "HMAC-SHA256", "Ed25519"}:
                    raise ValueError("Signing algorithm is invalid.")
                current["signing"]["algorithm"] = signing["algorithm"]
        secure_write_text(self.path, json.dumps(current, indent=2, ensure_ascii=False) + "\n")
        return self.public()


class CaseStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or application_data_dir()).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.path = self.root / "cases.json"

    def list(self) -> list[dict[str, Any]]:
        payload = _read_object(self.path)
        cases = payload.get("cases", [])
        return sorted((item for item in cases if isinstance(item, dict)), key=lambda item: str(item.get("updated_at", "")), reverse=True)

    def save(self, supplied: object) -> dict[str, Any]:
        if not isinstance(supplied, dict):
            raise ValueError("Case must be a JSON object.")
        now = datetime.now(timezone.utc).isoformat()
        case_id = str(supplied.get("id") or uuid.uuid4()).strip()
        if not CASE_ID.fullmatch(case_id):
            raise ValueError("Case identifier is invalid.")
        reference = str(supplied.get("reference", "")).strip()
        title = str(supplied.get("title", "")).strip()
        analyst = str(supplied.get("analyst", "")).strip()
        notes = str(supplied.get("notes", "")).strip()
        if not reference or not title or any(len(value) > MAX_TEXT for value in (reference, title, analyst, notes)):
            raise ValueError("Case reference and title are required; fields must be at most 2000 characters.")
        cases = self.list()
        existing = next((item for item in cases if item.get("id") == case_id), None)
        record = {
            "id": case_id, "reference": reference, "title": title, "analyst": analyst,
            "notes": notes, "archived": bool(supplied.get("archived", False)),
            "created_at": existing.get("created_at", now) if existing else now, "updated_at": now,
        }
        cases = [item for item in cases if item.get("id") != case_id]
        cases.append(record)
        secure_write_text(self.path, json.dumps({"schema_version": 1, "cases": cases[-500:]}, indent=2, ensure_ascii=False) + "\n")
        return record
