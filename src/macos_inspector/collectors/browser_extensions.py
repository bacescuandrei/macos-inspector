"""Bounded, read-only extension permission declarations, never runtime grants."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from macos_inspector.core.io import read_bytes_limited


MAX_EXTENSIONS = 100
MAX_VERSIONS = 20
MAX_DIRECTORY_ENTRIES = 500
MAX_PERMISSION_ENTRIES = 100
MAX_MANIFEST_BYTES = 512 * 1024
MAX_ADDON_METADATA_BYTES = 4 * 1024 * 1024
MAX_PERMISSION_RECORD_BYTES = 64 * 1024
MAX_PROFILE_PERMISSION_BYTES = 1024 * 1024
BOUNDARY = "Declared or recorded permissions are not confirmed grants or observed behavior. Browser settings, host restrictions, user consent, exclusions, and disabled state can restrict access. No browser setting was changed or destination contacted."
CAPABILITIES = {
    "cookies": ("Cookie access", "Requests cookie API access for permitted sites; site access and browser restrictions still apply."),
    "history": ("Browsing history", "Requests access to read or change browser history; no such activity was observed."),
    "downloads": ("Download management", "Requests access to initiate or manage browser downloads. This is not proof a file was downloaded or executed."),
    "clipboardRead": ("Read clipboard", "Requests clipboard reading, subject to browser and interaction restrictions."),
    "clipboardWrite": ("Change clipboard", "Requests clipboard writing, subject to browser and interaction restrictions."),
    "nativeMessaging": ("Communicate with a local application", "Requests messaging with a separately installed native host. Its presence, identity, and execution were not verified."),
    "tabs": ("Tab information", "Requests sensitive tab metadata such as URLs or titles. This alone does not establish access to page contents."),
    "activeTab": ("Temporary access after user interaction", "Requests temporary access to the active tab following an allowed user action, not persistent access to every site."),
    "scripting": ("Inject scripts where allowed", "Requests script injection on pages where separate site access or user-action permission allows it."),
    "webRequest": ("Observe matching network requests", "Requests request observation within permitted scope. No request observation was collected here."),
    "webRequestBlocking": ("Modify matching network requests", "Requests blocking request handling where the browser supports and permits it."),
    "proxy": ("Browser proxy configuration", "Requests proxy-setting access. No proxy change was established by this declaration."),
    "management": ("Extension management API", "Requests extension-management API access; the exact operations depend on browser restrictions."),
    "debugger": ("Debug browser targets", "Requests debugger access to supported browser targets. No attached target or runtime use was observed."),
}


def _directories(path: Path, maximum: int) -> tuple[list[Path], list[str]]:
    notes = []
    directories = []
    try:
        if path.is_symlink():
            return [], ["A symlinked extension directory was not inspected."]
        with os.scandir(path) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_DIRECTORY_ENTRIES:
                    notes.append("Extension directory enumeration limit reached; inventory is incomplete.")
                    break
                if entry.is_symlink():
                    notes.append("Symlinked extension entries were not inspected.")
                elif entry.is_dir(follow_symlinks=False):
                    directories.append(Path(entry.path))
    except FileNotFoundError:
        return [], []
    except OSError:
        notes.append("Extension directories could not be fully read.")
    directories.sort(key=lambda item: item.name)
    if len(directories) > maximum:
        notes.append("Extension directory selection limit reached; inventory is incomplete.")
    return directories[:maximum], list(dict.fromkeys(notes))


def _strings(value, field: str, notes: list[str], missing_ok: bool = True) -> list[str]:
    if value is None and missing_ok:
        return []
    if not isinstance(value, list):
        notes.append(f"{field} is unavailable or malformed.")
        return []
    if len(value) > MAX_PERMISSION_ENTRIES:
        notes.append(f"{field} exceeded its entry limit.")
    values = []
    for item in value[:MAX_PERMISSION_ENTRIES]:
        if not isinstance(item, str) or not item or len(item) > 512 or any(0xD800 <= ord(char) <= 0xDFFF for char in item):
            notes.append(f"{field} contains unsupported entries.")
        elif item not in values:
            values.append(item)
    return values


def _partition(values: list[str]) -> tuple[list[str], list[str]]:
    return ([item for item in values if "://" not in item and item != "<all_urls>"],
            [item for item in values if "://" in item or item == "<all_urls>"])


def _label(value: str) -> str:
    """Keep malformed Unicode in declared labels from breaking report encoding."""
    return value[:200].encode("utf-8", "replace").decode("utf-8")


def _features(required: dict, optional: dict) -> list[dict]:
    features = []
    for scope, group in (("Declared requirement", required), ("Optional declaration", optional)):
        api = group["api_permissions"]
        for permission, (label, explanation) in CAPABILITIES.items():
            if permission in api:
                features.append({"key": permission, "label": label, "scope": scope, "explanation": explanation})
        hosts = group["host_patterns"] + group.get("content_script_matches", [])
        if any(item in {"<all_urls>", "*://*/*", "https://*/*", "http://*/*"} for item in hosts):
            features.append({"key": "broad_sites", "label": "Broad site patterns", "scope": scope,
                             "explanation": "Declares patterns covering all hosts for one or more schemes. Exclusions, browser restrictions, and user choices can narrow effective access."})
        if any(item.startswith("file://") or item == "<all_urls>" for item in hosts):
            features.append({"key": "file_urls", "label": "Local file URL patterns", "scope": scope,
                             "explanation": "Declares patterns that include local file URLs. Browser file-access controls may prevent access; no file access was observed."})
    return features


def _analysis(required: dict, optional: dict, source: str, notes: list[str], digest: str | None = None) -> dict:
    return {"schema_version": 1, "source": source, "source_sha256": digest, "complete": not bool(notes),
            "required": required, "optional": optional, "features": _features(required, optional),
            "limitations": list(dict.fromkeys(notes)), "boundary": BOUNDARY,
            "effective_access": "Not established; verify enabled state, site access, and granted permissions in the browser."}


def _empty_analysis(note: str) -> dict:
    return _analysis({"api_permissions": [], "host_patterns": [], "content_script_matches": [], "content_script_exclusions": []},
                     {"api_permissions": [], "host_patterns": [], "available": False}, "Unavailable", [note])


def _append_bounded(rows: list[dict], row: dict, used: int, notes: list[str]) -> int | None:
    size = len(json.dumps(row, ensure_ascii=True).encode("ascii"))
    if size > MAX_PERMISSION_RECORD_BYTES:
        row["permission_analysis"] = _empty_analysis("Permission record size limit reached; detailed declarations were omitted.")
        notes.append("Some extension permission evidence exceeded the record size limit.")
        size = len(json.dumps(row, ensure_ascii=True).encode("ascii"))
    if used + size > MAX_PROFILE_PERMISSION_BYTES:
        notes.append("Extension evidence size bound reached; some inventory records were omitted.")
        return None
    rows.append(row)
    return used + size


def _manifest_analysis(path: Path) -> tuple[dict, dict]:
    if path.is_symlink():
        raise ValueError("Symlinked manifests are not inspected.")
    raw = read_bytes_limited(path, MAX_MANIFEST_BYTES)
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or type(manifest.get("manifest_version")) is not int or manifest["manifest_version"] not in {2, 3}:
        raise ValueError("Unsupported extension manifest schema.")
    notes = []
    permissions = _strings(manifest.get("permissions", []), "permissions", notes, False)
    api, old_hosts = _partition(permissions)
    hosts = _strings(manifest.get("host_permissions", []), "host_permissions", notes, False)
    optional_api, optional_old_hosts = _partition(_strings(manifest.get("optional_permissions", []), "optional_permissions", notes, False))
    optional_hosts = _strings(manifest.get("optional_host_permissions", []), "optional_host_permissions", notes, False)
    matches, exclusions, include_globs, exclude_globs = [], [], [], []
    content = manifest.get("content_scripts", [])
    if not isinstance(content, list):
        notes.append("content_scripts is malformed.")
        content = []
    if len(content) > MAX_PERMISSION_ENTRIES:
        notes.append("Content script record limit reached.")
    for script in content[:MAX_PERMISSION_ENTRIES]:
        if not isinstance(script, dict):
            notes.append("A content script record is malformed.")
            continue
        matches.extend(_strings(script.get("matches"), "content_scripts.matches", notes, missing_ok=False))
        exclusions.extend(_strings(script.get("exclude_matches", []), "content_scripts.exclude_matches", notes, False))
        exclude_globs.extend(_strings(script.get("exclude_globs", []), "content_scripts.exclude_globs", notes, False))
        # Include-globs are additional restrictions, not independent host access.
        include_globs.extend(_strings(script.get("include_globs", []), "content_scripts.include_globs", notes, False))
    if any(len(group) > MAX_PERMISSION_ENTRIES for group in (matches, exclusions, include_globs, exclude_globs)):
        notes.append("Aggregated content script scope limit reached.")
    required_hosts = list(dict.fromkeys(old_hosts + hosts))
    optional_hosts = list(dict.fromkeys(optional_old_hosts + optional_hosts))
    if len(required_hosts) > MAX_PERMISSION_ENTRIES or len(optional_hosts) > MAX_PERMISSION_ENTRIES:
        notes.append("Aggregated host permission limit reached.")
    required = {"api_permissions": api, "host_patterns": required_hosts[:MAX_PERMISSION_ENTRIES],
                "content_script_matches": list(dict.fromkeys(matches))[:MAX_PERMISSION_ENTRIES],
                "content_script_exclusions": list(dict.fromkeys(exclusions))[:MAX_PERMISSION_ENTRIES],
                "content_script_include_globs": list(dict.fromkeys(include_globs))[:MAX_PERMISSION_ENTRIES],
                "content_script_exclude_globs": list(dict.fromkeys(exclude_globs))[:MAX_PERMISSION_ENTRIES]}
    optional = {"api_permissions": optional_api, "host_patterns": optional_hosts[:MAX_PERMISSION_ENTRIES], "available": True}
    return manifest, _analysis(required, optional, "Chromium manifest; highest observed numeric version directory, not confirmed active version", notes, hashlib.sha256(raw).hexdigest())


def chromium_extensions(path: Path | None) -> tuple[list[dict], str | None]:
    if path is None:
        return [], None
    identifiers, notes = _directories(path, MAX_EXTENSIONS)
    rows = []
    used = 0
    for identifier in identifiers:
        versions, errors = _directories(identifier, MAX_VERSIONS)
        numeric = [(tuple(int(part) for part in version.name.split("_")[0].split(".")), version)
                   for version in versions if re.fullmatch(r"\d{1,8}(?:\.\d{1,8}){0,3}(?:_\d{1,8})?", version.name)]
        row = {"id": _label(identifier.name), "version": "unknown", "name": _label(identifier.name), "active": None,
               "version_directory": None, "observed_version_directories": len(versions),
               "permission_analysis": _empty_analysis("No supported numeric extension version directory was available.")}
        if numeric:
            _, version = max(numeric, key=lambda item: (item[0], item[1].name))
            row["version_directory"] = version.name
            row["version"] = version.name.split("_")[0]
            try:
                manifest, analysis = _manifest_analysis(version / "manifest.json")
                if errors:
                    analysis["complete"] = False
                    analysis["limitations"].extend(errors)
                row["permission_analysis"] = analysis
                for key in ("name", "version"):
                    if isinstance(manifest.get(key), str):
                        row[key] = _label(manifest[key])
            except (OSError, ValueError, RecursionError):
                row["permission_analysis"] = _empty_analysis("Manifest unavailable, malformed, oversized, or unsupported; permissions were not established.")
        if not row["permission_analysis"]["complete"]:
            notes.append("Some extension permission declarations could not be fully assessed.")
        next_used = _append_bounded(rows, row, used, notes)
        if next_used is None:
            break
        used = next_used
    return rows, "; ".join(dict.fromkeys(notes)) or None


def firefox_extensions(path: Path | None) -> tuple[list[dict], str | None]:
    if path is None:
        return [], None
    try:
        if path.is_symlink():
            return [], "Symlinked Firefox addon metadata was not inspected."
        payload = json.loads(read_bytes_limited(path, MAX_ADDON_METADATA_BYTES))
    except FileNotFoundError:
        return [], None
    except (OSError, ValueError, RecursionError):
        return [], "Firefox addon metadata is unreadable, malformed, or oversized."
    if not isinstance(payload, dict) or not isinstance(payload.get("addons"), list):
        return [], "Firefox addon metadata has an unsupported structure."
    addons = payload["addons"]
    notes = ["Firefox addon inventory limit reached."] if len(addons) > MAX_EXTENSIONS else []
    rows = []
    used = 0
    for addon in addons[:MAX_EXTENSIONS]:
        if not isinstance(addon, dict):
            notes.append("A Firefox addon record was malformed.")
            continue
        row = {key: _label(addon.get(key)) if isinstance(addon.get(key), str) else None for key in ("id", "version", "type")}
        row["active"] = addon.get("active") if type(addon.get("active")) is bool else None
        locale = addon.get("defaultLocale")
        row["name"] = _label(locale.get("name")) if isinstance(locale, dict) and isinstance(locale.get("name"), str) else row["id"]
        required_meta = addon.get("userPermissions")
        permission_notes = []
        if row["type"] != "extension" or not isinstance(required_meta, dict):
            row["permission_analysis"] = _empty_analysis("WebExtension permission requirements were not available in this addon record.")
        else:
            required = {"api_permissions": _strings(required_meta.get("permissions"), "userPermissions.permissions", permission_notes, False),
                        "host_patterns": _strings(required_meta.get("origins"), "userPermissions.origins", permission_notes, False),
                        "content_script_matches": [], "content_script_exclusions": []}
            optional_meta = addon.get("optionalPermissions")
            optional = {"available": isinstance(optional_meta, dict), "api_permissions": [], "host_patterns": []}
            if isinstance(optional_meta, dict):
                optional["api_permissions"] = _strings(optional_meta.get("permissions"), "optionalPermissions.permissions", permission_notes, False)
                optional["host_patterns"] = _strings(optional_meta.get("origins"), "optionalPermissions.origins", permission_notes, False)
            else:
                permission_notes.append("Optional permission requirements were not available in the addon metadata.")
            row["permission_analysis"] = _analysis(required, optional, "Firefox addon metadata; recorded requirements, not dynamic permission grants", permission_notes)
        if not row["permission_analysis"]["complete"]:
            notes.append("Some Firefox addon permission requirements were not fully assessed.")
        next_used = _append_bounded(rows, row, used, notes)
        if next_used is None:
            break
        used = next_used
    return rows, "; ".join(dict.fromkeys(notes)) or None


def safari_legacy_extensions(path: Path | None) -> tuple[list[dict], str | None]:
    if path is None:
        return [], "Safari app/WebExtension permissions were not assessed."
    directories, notes = _directories(path, MAX_EXTENSIONS)
    rows = [{"id": _label(item.name), "name": _label(item.name), "version": "unknown", "active": None,
             "permission_analysis": _empty_analysis("Safari app/WebExtension permissions are not supported by this legacy-folder inventory.")} for item in directories]
    return rows, "; ".join([*notes, "Safari app/WebExtension permissions were not assessed; legacy folders do not establish the full extension inventory."])
