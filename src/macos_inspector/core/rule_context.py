from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .io import read_bytes_limited


RULE_COLLECTORS = {"ioc", "yara-rules"}
RULE_CONTEXT_NOTE = "Fingerprints identify the recorded local rule content, locations, and relevant configuration. They do not validate rule quality, authenticate a publisher, or prove that every check ran. No source is contacted by opening this panel."


def build_rule_context_summary(report: dict) -> dict:
    """Describe recorded rule context, independently of classification or comparison."""
    metadata = report.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    selected = metadata.get("collectors")
    selected = {item for item in selected if isinstance(item, str)} if isinstance(selected, (list, tuple)) else set()
    contexts = metadata.get("detection_context")
    contexts = contexts if isinstance(contexts, dict) else {}
    findings = report.get("findings")
    findings = [item for item in findings if isinstance(item, dict)] if isinstance(findings, (list, tuple)) else []
    rows = []
    for collector, title in (("ioc", "Local IOC packs"), ("yara-rules", "Managed YARA rules")):
        if collector not in selected:
            continue
        context = contexts.get(collector)
        context = context if isinstance(context, dict) else {}
        fingerprint = context.get("fingerprint")
        fingerprint = fingerprint if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint) else None
        count = context.get("file_count")
        count = count if type(count) is int and 0 <= count <= 1000000 else None
        usable = type(context.get("schema_version")) is int and context["schema_version"] == 1 and fingerprint is not None and count is not None
        status, label = "unavailable", "Rule snapshot unavailable"
        if usable and context.get("complete") is False:
            status, label = "incomplete", "Rule snapshot incomplete"
        elif usable and context.get("stable") is False:
            status, label = "changed", "Rules changed during collection"
        elif usable and context.get("complete") is True and context.get("stable") is True:
            status, label = "stable", "Rule snapshot stable" if count else "No rule files recorded"
        records = [item for item in findings if isinstance(item.get("finding_id"), str) and
                   (item["finding_id"].startswith("IOC-") if collector == "ioc" else item["finding_id"] == "YARA-MANAGED-SCAN")]
        statuses = {item.get("status") for item in records if isinstance(item.get("status"), str)}
        if not records:
            result = "Result records unavailable; check scope, collection gaps, and the recorded finding filter."
        elif statuses == {"Not Applicable"}:
            result = "Not run. This section was selected but its recorded result is not applicable."
        else:
            parts = []
            if "Match" in statuses:
                parts.append("Matches recorded")
            if "Unknown" in statuses:
                parts.append("Some checks could not complete")
            if "Review" in statuses:
                parts.append("Review items recorded")
            result = "; ".join(parts) + "." if parts else "Result records are available; open the technical findings for their outcomes."
        sources = []
        if collector == "ioc":
            for record in records:
                evidence = record.get("evidence")
                for item in evidence if isinstance(evidence, (list, tuple)) else []:
                    value = item.get("value") if isinstance(item, dict) and item.get("kind") == "ioc_pack_metadata" else None
                    if not isinstance(value, dict):
                        continue
                    source_host = None
                    try:
                        source = urlsplit(value.get("source", "")) if isinstance(value.get("source"), str) else None
                        if source and source.scheme in {"http", "https"} and source.hostname:
                            source_host = source.hostname[:253]
                    except ValueError:
                        pass
                    bounded = lambda key: value[key][:256] if isinstance(value.get(key), str) else "Not recorded"
                    sources.append({"name": bounded("name"), "version": bounded("version"),
                                    "updated_at": bounded("updated_at"), "source_host": source_host})
        limitations = context.get("limitations")
        limitations = [item[:500] for item in limitations if isinstance(item, str)][:10] if isinstance(limitations, (list, tuple)) else []
        rows.append({"collector": collector, "title": title, "status": status, "label": label,
                     "file_count": count if usable else None, "fingerprint": fingerprint if usable else None, "result_note": result,
                     "limitations": limitations, "sources": sources[:20], "source_count": len(sources)})
    return {"available": bool(rows), "rows": rows, "note": RULE_CONTEXT_NOTE,
            "source_note": "Source hostnames, versions, and update labels are declared by the pack, not independently verified. Missing metadata may reflect filtering or unavailable collection. Full acquisition context remains in the original evidence."}


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
