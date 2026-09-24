from __future__ import annotations

import getpass
import platform
import socket
import uuid
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from macos_inspector import __version__
from macos_inspector.collectors import COLLECTORS
from macos_inspector.core.models import ScanMetadata, ScanResult, Severity
from macos_inspector.core.runner import CommandRunner, ScanCancelled
from macos_inspector.core.scoring import calculate_coverage, calculate_scores
from macos_inspector.core.timeline import build_timeline
from macos_inspector.reporters import REPORTERS


def run_scan(
    collector_ids: list[str],
    minimum: Severity = Severity.INFORMATIONAL,
    runner: CommandRunner | None = None,
    progress: Callable[[str, int, int], None] | None = None,
    case_reference: str = "",
    analyst: str = "",
    cancel_event: threading.Event | None = None,
    item_progress: Callable[[str, str | None, int, int], None] | None = None,
    target_application: Path | None = None,
) -> ScanResult:
    """Run collectors and keep evidence gaps visible above any severity threshold."""
    started = datetime.now(timezone.utc)
    all_findings, errors = [], []
    collector_coverage: dict[str, int] = {}
    command_runner = runner or CommandRunner(cancel_event=cancel_event)
    for index, collector_id in enumerate(collector_ids, start=1):
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled("Scan cancelled by user.")
        if progress:
            progress(collector_id, index - 1, len(collector_ids))
        try:
            if collector_id == "application-trust" and target_application is not None:
                collector = COLLECTORS[collector_id](command_runner, bundles=(target_application,))
            else:
                collector = COLLECTORS[collector_id](command_runner)
            set_progress_callback = getattr(collector, "set_progress_callback", None)
            if item_progress and callable(set_progress_callback):
                set_progress_callback(
                    lambda item, completed, total, current=collector_id: item_progress(current, item, completed, total)
                )
            collected = list(collector.collect())
            all_findings.extend(collected)
            collector_coverage[collector_id] = round(
                100 * sum(finding.status.lower() != "unknown" for finding in collected) / len(collected)
            ) if collected else 0
        except ScanCancelled:
            raise
        except Exception as exc:
            errors.append(f"{collector_id}: {type(exc).__name__}: {exc}")
            collector_coverage[collector_id] = 0
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled("Scan cancelled by user.")
        if progress:
            progress(collector_id, index, len(collector_ids))

    overall, category_scores = calculate_scores(all_findings)
    category_coverage = calculate_coverage(all_findings)
    visible_findings = sorted(
        (
            finding for finding in all_findings
            if finding.severity >= minimum or finding.status.lower() in {"unknown", "not applicable"}
        ),
        key=lambda finding: (-int(finding.severity), finding.category, finding.finding_id),
    )
    completed = datetime.now(timezone.utc)
    metadata = ScanMetadata(
        tool_version=__version__, scan_id=str(uuid.uuid4()), started_at=started.isoformat(), completed_at=completed.isoformat(),
        hostname=socket.gethostname(), platform=platform.platform(), username=getpass.getuser(),
        collectors=tuple(collector_ids), collection_errors=tuple(errors),
        case_reference=case_reference.strip(), analyst=analyst.strip(),
        target_application=str(target_application) if target_application is not None else "",
    )
    return ScanResult(
        metadata, tuple(visible_findings), overall, category_scores, category_coverage,
        len(all_findings), build_timeline(visible_findings), collector_coverage,
    )


def write_reports(result: ScanResult, formats: list[str], output_directory, bundle_password: str | None = None) -> list:
    from pathlib import Path
    from macos_inspector.reporters.bundle_reporter import write_bundle
    from macos_inspector.reporters.manifest_reporter import write_manifest
    from macos_inspector.reporters.encrypted_bundle import encrypt_file
    from macos_inspector.reporters import require_report_formats

    require_report_formats(formats)
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    extension = {"markdown": "md", "bundle": "zip", "encrypted-bundle": "zip.enc"}
    paths = []
    for report_format in formats:
        if report_format in {"manifest", "bundle", "encrypted-bundle"}:
            continue
        path = output / f"macos-inspector-{result.metadata.scan_id}.{extension.get(report_format, report_format)}"
        REPORTERS[report_format](result, path)
        paths.append(path)
    if "manifest" in formats or "bundle" in formats or "encrypted-bundle" in formats:
        path = output / f"macos-inspector-{result.metadata.scan_id}.manifest"
        write_manifest(result, path, paths)
        paths.append(path)
    if "bundle" in formats:
        path = output / f"macos-inspector-{result.metadata.scan_id}.{extension['bundle']}"
        write_bundle(result, path)
        paths.append(path)
    if "encrypted-bundle" in formats:
        if not bundle_password:
            raise ValueError("A password is required for the encrypted case bundle.")
        temporary_bundle = output / f".macos-inspector-{result.metadata.scan_id}.zip"
        encrypted = output / f"macos-inspector-{result.metadata.scan_id}.zip.enc"
        try:
            write_bundle(result, temporary_bundle)
            encrypt_file(temporary_bundle, encrypted, bundle_password)
            paths.append(encrypted)
        finally:
            temporary_bundle.unlink(missing_ok=True)
    return paths
