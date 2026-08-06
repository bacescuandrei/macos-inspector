from __future__ import annotations

import argparse
import os
import platform
import sys
from pathlib import Path

from macos_inspector import __version__
from macos_inspector.collectors import COLLECTORS
from macos_inspector.core.models import Severity
from macos_inspector.core.scan import run_scan, write_reports
from macos_inspector.reporters import REPORTERS, unavailable_report_formats


def _csv(value: str) -> list[str]:
    return [part.strip().lower() for part in value.split(",") if part.strip()]


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="macos-inspector", description="Read-only macOS security and DFIR assessment")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--output", type=Path, default=Path("macos-inspector-reports"))
    p.add_argument("--collectors", default=",".join(COLLECTORS))
    p.add_argument("--formats", default="html,json,markdown,csv,sarif,manifest,bundle")
    p.add_argument("--min-severity", default="informational")
    p.add_argument("--case-reference", default="", help="Optional case or incident reference")
    p.add_argument("--analyst", default="", help="Optional analyst name")
    p.add_argument("--list-collectors", action="store_true")
    p.add_argument("--verify-manifest", type=Path, help="Verify a manifest and its report digests")
    p.add_argument("--public-key", type=Path, help="Trusted PEM public key for manifest verification")
    p.add_argument("--web", action="store_true", help="Start the local web dashboard")
    p.add_argument("--no-open-browser", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--host", default="127.0.0.1", help=argparse.SUPPRESS)
    p.add_argument("--port", type=int, default=8765, help="Web dashboard port")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.verify_manifest:
        from macos_inspector.reporters.manifest_reporter import verify_manifest
        valid, errors = verify_manifest(
            args.verify_manifest, os.environ.get("MACOS_INSPECTOR_MANIFEST_KEY"), public_key=args.public_key,
        )
        if valid:
            print(f"verified: {args.verify_manifest}")
            return 0
        for error in errors:
            print(f"verification error: {error}", file=sys.stderr)
        return 1
    if args.list_collectors:
        for collector_id, cls in COLLECTORS.items():
            print(f"{collector_id:16} {cls.title}")
        return 0
    if args.web:
        from macos_inspector.web import serve
        return serve(args.host, args.port, args.output, open_browser=not args.no_open_browser)
    if platform.system() != "Darwin":
        print("warning: collection is designed for macOS; unavailable commands will be reported as unknown", file=sys.stderr)
    selected, formats = _csv(args.collectors), _csv(args.formats)
    if not selected:
        parser().error("at least one collector is required")
    if not formats:
        parser().error("at least one report format is required")
    if len(selected) != len(set(selected)):
        parser().error("duplicate collectors are not allowed")
    if len(formats) != len(set(formats)):
        parser().error("duplicate report formats are not allowed")
    unknown = set(selected) - COLLECTORS.keys()
    bad_formats = set(formats) - REPORTERS.keys()
    try:
        minimum = Severity.parse(args.min_severity)
    except KeyError:
        parser().error(f"unknown severity: {args.min_severity}")
    if unknown:
        parser().error(f"unknown collectors: {', '.join(sorted(unknown))}")
    if bad_formats:
        parser().error(f"unknown formats: {', '.join(sorted(bad_formats))}")
    unavailable_formats = unavailable_report_formats(formats)
    if unavailable_formats:
        parser().error("; ".join(unavailable_formats.values()))
    if len(args.case_reference) > 200 or len(args.analyst) > 200:
        parser().error("case reference and analyst must be at most 200 characters")
    result = run_scan(selected, minimum, case_reference=args.case_reference, analyst=args.analyst)
    for path in write_reports(result, formats, args.output):
        print(path)
    if result.metadata.collection_errors:
        for error in result.metadata.collection_errors:
            print(f"collection error: {error}", file=sys.stderr)
        return 1
    return 0
