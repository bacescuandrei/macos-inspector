from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from .models import Finding, TimelineEvent


MAX_TIMELINE_EVENTS = 5000
TIMESTAMP_KEYS = {"timestamp", "last_modified"}


def _normalize_timestamp(value: Any) -> str | None:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            return None
    if isinstance(value, (int, float)) and value >= 1_000_000_000:
        try:
            divisor = 1_000_000 if value >= 1_000_000_000_000_000 else (1_000 if value >= 1_000_000_000_000 else 1)
            return datetime.fromtimestamp(value / divisor, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _embedded_timestamps(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if key in TIMESTAMP_KEYS or str(key).endswith("_at"):
                normalized = _normalize_timestamp(item)
                if normalized:
                    yield path, normalized
            if isinstance(item, (dict, list, tuple)):
                yield from _embedded_timestamps(item, path)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _embedded_timestamps(item, f"{prefix}[{index}]")


def build_timeline(findings: Iterable[Finding]) -> tuple[TimelineEvent, ...]:
    events: list[TimelineEvent] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        for evidence in finding.evidence:
            collected = _normalize_timestamp(evidence.collected_at)
            if collected:
                key = (collected, finding.finding_id, "collection", evidence.source)
                if key not in seen:
                    seen.add(key)
                    events.append(TimelineEvent(collected, finding.category, finding.finding_id, "collection", evidence.source, f"Collected {evidence.kind} evidence"))
            for path, timestamp in _embedded_timestamps(evidence.value):
                key = (timestamp, finding.finding_id, path, evidence.source)
                if key in seen:
                    continue
                seen.add(key)
                events.append(TimelineEvent(timestamp, finding.category, finding.finding_id, path, evidence.source, f"Observed timestamp in {path}"))
                if len(events) >= MAX_TIMELINE_EVENTS:
                    break
            if len(events) >= MAX_TIMELINE_EVENTS:
                break
        if len(events) >= MAX_TIMELINE_EVENTS:
            break
    return tuple(sorted(events, key=lambda event: (event.timestamp, event.finding_id, event.kind)))
