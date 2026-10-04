from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

from .io import read_bytes_limited


RULE_COLLECTORS = {"ioc", "yara-rules"}


def capture_rule_context(collector_id: str, collector: Any) -> dict[str, Any]:
    """Fingerprint local rule bytes and only the configuration used by this collector.

    No API keys, provider settings, rule text, or target paths are copied into metadata.
    Before/after capture detects ordinary edits during collection, not hostile races.
    """
    if collector_id not in RULE_COLLECTORS:
        return {}
    config = {}
    if collector_id == "ioc":
        directories, suffixes, limit, byte_limit = collector.directories, {".json"}, 1000, 2 * 1024 * 1024
    else:
        directories, suffixes, limit, byte_limit = (collector.rules_directory,), {".yar", ".yara"}, 50, 5 * 1024 * 1024
        config = {"enabled": collector.settings["yara"]["enabled"], "targets": collector.settings["yara"]["targets"]}
    files: dict[str, str] = {}
    errors: list[str] = []
    for directory in directories:
        try:
            candidates = sorted(path for path in Path(directory).iterdir() if path.suffix in suffixes)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(type(exc).__name__)
            continue
        if len(candidates) > limit:
            errors.append("Rule file count exceeds the fingerprint limit.")
        for path in candidates[:limit]:
            try:
                if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > byte_limit:
                    errors.append("A rule is not a regular file or exceeds the byte limit.")
                    continue
                # Include the resolved local identity in the hash, not in public metadata.
                files[str(path.resolve())] = hashlib.sha256(read_bytes_limited(path, byte_limit)).hexdigest()
            except (OSError, ValueError) as exc:
                errors.append(type(exc).__name__)
    encoded = json.dumps({"files": files, "config": config}, sort_keys=True, separators=(",", ":")).encode()
    return {"schema_version": 1, "fingerprint": hashlib.sha256(encoded).hexdigest(), "file_count": len(files),
            "complete": not errors, "limitations": sorted(set(errors))}


def detection_context_limits(baseline: dict, current: dict) -> list[str]:
    selected = set(baseline.get("metadata", {}).get("collectors", [])) | set(current.get("metadata", {}).get("collectors", []))
    limits = []
    for collector in sorted(selected & RULE_COLLECTORS):
        contexts = [report.get("metadata", {}).get("detection_context") for report in (baseline, current)]
        before, after = [context.get(collector) if isinstance(context, dict) else None for context in contexts]
        if not all(isinstance(value, dict) and value.get("complete") is True and value.get("stable") is True
                   and isinstance(value.get("fingerprint"), str) and re.fullmatch(r"[0-9a-f]{64}", value["fingerprint"]) for value in (before, after)):
            limits.append(f"{collector}: complete, stable rule fingerprints are unavailable in at least one report.")
        elif before["fingerprint"] != after["fingerprint"]:
            limits.append(f"{collector}: local rule content, location, or relevant configuration changed between scans.")
    return limits
