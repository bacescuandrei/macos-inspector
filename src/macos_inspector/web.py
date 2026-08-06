from __future__ import annotations

import json
import mimetypes
import os
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from macos_inspector import __version__
from macos_inspector.collectors import COLLECTORS
from macos_inspector.core.models import Severity
from macos_inspector.core.comparison import compare_scan_payloads
from macos_inspector.core.readiness import collect_readiness
from macos_inspector.core.scan import run_scan, write_reports
from macos_inspector.core.runner import ScanCancelled
from macos_inspector.reporters import REPORTERS, report_format_capabilities, require_report_formats
from macos_inspector.reporters.manifest_reporter import verify_manifest
from macos_inspector.reporters.comparison_reporter import write_comparison_reports
from macos_inspector.reporters.common import secure_write_text


@dataclass
class ScanJob:
    job_id: str
    collectors: list[str]
    formats: list[str]
    minimum: str
    case_reference: str = ""
    analyst: str = ""
    state: str = "queued"
    current_collector: str | None = None
    completed_collectors: int = 0
    total_collectors: int = 0
    current_item: str | None = None
    completed_items: int = 0
    total_items: int = 0
    estimated_seconds_remaining: int | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    scan_id: str | None = None
    error: str | None = None
    summary: dict | None = None
    reports: dict[str, str] = field(default_factory=dict)
    cancel_requested: bool = False

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class DashboardState:
    def __init__(self, output: Path) -> None:
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.output.chmod(0o700)
        self.jobs: dict[str, ScanJob] = {}
        self.cancel_events: dict[str, threading.Event] = {}
        self.item_progress_runtime: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.started_monotonic = time.monotonic()
        self.journal_path = self.output / ".macos-inspector-jobs.json"
        self._load_journal()

    def _load_journal(self) -> None:
        try:
            payload = json.loads(self.journal_path.read_text(encoding="utf-8"))
            if payload.get("schema_version") != 1 or not isinstance(payload.get("jobs"), list):
                return
            allowed = set(ScanJob.__dataclass_fields__)
            for raw_job in payload["jobs"][-100:]:
                if not isinstance(raw_job, dict):
                    continue
                values = {key: value for key, value in raw_job.items() if key in allowed}
                if not isinstance(values.get("job_id"), str) or not isinstance(values.get("collectors"), list) or not isinstance(values.get("formats"), list):
                    continue
                job = ScanJob(**values)
                if job.state in {"queued", "running"}:
                    job.state = "interrupted"
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    job.error = "Dashboard stopped before the scan completed. No partial reports were published."
                    job.cancel_requested = False
                self.jobs[job.job_id] = job
            self._persist_jobs_locked()
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return

    def _persist_jobs_locked(self) -> None:
        retained = sorted(
            (job.to_dict() for job in self.jobs.values() if job.state != "completed"),
            key=lambda item: item.get("created_at") or "",
        )[-100:]
        secure_write_text(self.journal_path, json.dumps({"schema_version": 1, "jobs": retained}, indent=2, ensure_ascii=False) + "\n")

    def create_job(self, collectors: list[str], formats: list[str], minimum: str, case_reference: str = "", analyst: str = "") -> ScanJob:
        requested_formats = list(dict.fromkeys(["html", "json", *formats]))
        require_report_formats(requested_formats)
        with self.lock:
            if any(job.state in {"queued", "running"} for job in self.jobs.values()):
                raise RuntimeError("A scan is already running.")
            job = ScanJob(str(uuid.uuid4()), collectors, requested_formats, minimum, case_reference, analyst, total_collectors=len(collectors))
            self.jobs[job.job_id] = job
            self.cancel_events[job.job_id] = threading.Event()
            self._persist_jobs_locked()
        threading.Thread(target=self._execute, args=(job,), daemon=True).start()
        return job

    def _execute(self, job: ScanJob) -> None:
        try:
            job.state = "running"
            with self.lock:
                self._persist_jobs_locked()
            cancel_event = self.cancel_events[job.job_id]

            def progress(collector: str, completed: int, total: int) -> None:
                with self.lock:
                    job.current_collector = collector
                    job.completed_collectors = completed
                    job.total_collectors = total
                    job.current_item = None
                    job.completed_items = 0
                    job.total_items = 0
                    job.estimated_seconds_remaining = None
                    self.item_progress_runtime.pop(job.job_id, None)
                    self._persist_jobs_locked()

            def item_progress(collector: str, item: str | None, completed: int, total: int) -> None:
                with self.lock:
                    now = time.monotonic()
                    runtime = self.item_progress_runtime.setdefault(job.job_id, {
                        "last_update": now, "completed": completed, "durations": [],
                    })
                    previous_completed = int(runtime["completed"])
                    if completed > previous_completed:
                        per_item = (now - float(runtime["last_update"])) / (completed - previous_completed)
                        runtime["durations"].append(per_item)
                        runtime["durations"] = runtime["durations"][-7:]
                        runtime["last_update"] = now
                        runtime["completed"] = completed
                    durations = sorted(float(value) for value in runtime["durations"])
                    estimate = None
                    if len(durations) >= 3 and completed < total:
                        median = durations[len(durations) // 2]
                        estimate = max(1, round(median * (total - completed)))
                    job.current_collector = collector
                    job.current_item = item
                    job.completed_items = completed
                    job.total_items = total
                    job.estimated_seconds_remaining = estimate
                    self._persist_jobs_locked()

            result = run_scan(
                job.collectors, Severity.parse(job.minimum), progress=progress,
                case_reference=job.case_reference, analyst=job.analyst, cancel_event=cancel_event,
                item_progress=item_progress,
            )
            if cancel_event.is_set():
                raise ScanCancelled("Scan cancelled by user.")
            paths = write_reports(result, job.formats, self.output)
            with self.lock:
                job.state = "completed"
                job.scan_id = result.metadata.scan_id
                job.completed_at = result.metadata.completed_at
                job.summary = result.to_dict()["summary"]
                job.reports = {path.suffix.lstrip("."): f"/reports/{path.name}" for path in paths}
                if "md" in job.reports:
                    job.reports["markdown"] = job.reports.pop("md")
                if "zip" in job.reports:
                    job.reports["bundle"] = job.reports.pop("zip")
                self._persist_jobs_locked()
        except ScanCancelled:
            with self.lock:
                job.state = "cancelled"
                job.completed_at = datetime.now(timezone.utc).isoformat()
                job.error = None
                self._persist_jobs_locked()
        except Exception as exc:
            with self.lock:
                job.state = "failed"
                job.completed_at = datetime.now(timezone.utc).isoformat()
                job.error = f"{type(exc).__name__}: {exc}"
                self._persist_jobs_locked()
        finally:
            with self.lock:
                self.cancel_events.pop(job.job_id, None)
                self.item_progress_runtime.pop(job.job_id, None)
                self._persist_jobs_locked()

    def cancel_job(self, job_id: str) -> dict:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError("Scan not found.")
            if job.state not in {"queued", "running"}:
                raise RuntimeError(f"Scan is already {job.state}.")
            job.cancel_requested = True
            event = self.cancel_events.get(job_id)
            if event:
                event.set()
            self._persist_jobs_locked()
            return job.to_dict()

    def list_jobs(self) -> list[dict]:
        with self.lock:
            live = [job.to_dict() for job in self.jobs.values()]
        known_scans = {job.get("scan_id") for job in live}
        historical = []
        for path in sorted(self.output.glob("macos-inspector-*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                metadata, summary = payload["metadata"], payload["summary"]
                scan_id = metadata["scan_id"]
                if scan_id in known_scans:
                    continue
                reports = {}
                for suffix, name in (("html", "html"), ("json", "json"), ("markdown", "md"), ("csv", "csv"), ("sarif", "sarif"), ("manifest", "manifest"), ("pdf", "pdf"), ("bundle", "zip")):
                    candidate = self.output / f"macos-inspector-{scan_id}.{name}"
                    if candidate.is_file():
                        reports[suffix] = f"/reports/{candidate.name}"
                historical.append({
                    "job_id": f"history-{scan_id}", "state": "completed", "scan_id": scan_id,
                    "collectors": metadata.get("collectors", []), "created_at": metadata.get("started_at"),
                    "case_reference": metadata.get("case_reference", ""), "analyst": metadata.get("analyst", ""),
                    "completed_at": metadata.get("completed_at"), "summary": summary, "reports": reports,
                })
            except (OSError, KeyError, json.JSONDecodeError):
                continue
        return sorted(live + historical, key=lambda job: job.get("created_at") or "", reverse=True)

    def health(self) -> dict:
        with self.lock:
            active = next((job for job in self.jobs.values() if job.state in {"queued", "running"}), None)
            active_job = None if active is None else {
                "job_id": active.job_id,
                "state": active.state,
                "current_collector": active.current_collector,
                "completed_collectors": active.completed_collectors,
                "total_collectors": active.total_collectors,
            }
        return {
            "status": "ok",
            "version": __version__,
            "started_at": self.started_at,
            "uptime_seconds": max(0, int(time.monotonic() - self.started_monotonic)),
            "active_job": active_job,
        }

    def readiness(self) -> dict:
        return collect_readiness(self.output)

    def verify_evidence(self, scan_id: str) -> dict:
        if not scan_id or Path(scan_id).name != scan_id:
            raise ValueError("Invalid scan identifier.")
        manifest = self.output / f"macos-inspector-{scan_id}.manifest"
        if not manifest.is_file():
            raise FileNotFoundError("Evidence manifest not found.")
        valid, errors = verify_manifest(manifest, os.environ.get("MACOS_INSPECTOR_MANIFEST_KEY"))
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        signature = payload.get("signature") or {}
        return {
            "valid": valid, "errors": errors, "artifact_count": len(payload.get("artifacts", [])),
            "algorithm": signature.get("algorithm"), "public_key_sha256": signature.get("public_key_sha256"),
        }

    def compare(self, baseline_id: str, current_id: str) -> dict:
        def load(scan_id: str) -> dict:
            if not scan_id or Path(scan_id).name != scan_id:
                raise ValueError("Invalid scan identifier.")
            path = self.output / f"macos-inspector-{scan_id}.json"
            if not path.is_file():
                raise FileNotFoundError(f"JSON report not found: {scan_id}")
            return json.loads(path.read_text(encoding="utf-8"))
        comparison = compare_scan_payloads(load(baseline_id), load(current_id))
        paths = write_comparison_reports(comparison, self.output)
        comparison["reports"] = {name: f"/reports/{path.name}" for name, path in paths.items()}
        return comparison


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "macOSInspector/0.1"

    @property
    def state(self) -> DashboardState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args) -> None:
        return

    def _headers(self, status: int, content_type: str, length: int, report: bool = False, download_name: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        if report:
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'self'")
        else:
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-src 'self'; object-src 'none'")
        self.end_headers()

    def _send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _send_asset(self, name: str) -> None:
        asset = files("macos_inspector.webui").joinpath(name)
        try:
            body = asset.read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            self.send_error(404)
            return
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        self._headers(200, f"{content_type}; charset=utf-8", len(body))
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._send_asset("index.html")
        elif path == "/app.js":
            self._send_asset("app.js")
        elif path == "/styles.css":
            self._send_asset("styles.css")
        elif path == "/api/config":
            self._send_json({
                "collectors": [{"id": key, "title": value.title} for key, value in COLLECTORS.items()],
                "formats": list(REPORTERS), "format_capabilities": report_format_capabilities(),
                "severities": [severity.label() for severity in Severity],
            })
        elif path == "/api/health":
            self._send_json(self.state.health())
        elif path == "/api/readiness":
            self._send_json(self.state.readiness())
        elif path == "/api/scans":
            self._send_json({"scans": self.state.list_jobs()})
        elif path == "/api/compare":
            query = parse_qs(parsed.query)
            try:
                self._send_json(self.state.compare(query.get("baseline", [""])[0], query.get("current", [""])[0]))
            except FileNotFoundError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        elif path.startswith("/api/manifests/") and path.endswith("/verify"):
            scan_id = unquote(path.removeprefix("/api/manifests/").removesuffix("/verify")).strip("/")
            try:
                self._send_json(self.state.verify_evidence(scan_id))
            except FileNotFoundError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        elif path.startswith("/api/scans/"):
            job_id = unquote(path.removeprefix("/api/scans/"))
            job = next((item for item in self.state.list_jobs() if item.get("job_id") == job_id), None)
            self._send_json(job or {"error": "Scan not found."}, 200 if job else 404)
        elif path.startswith("/reports/"):
            self._send_report(unquote(path.removeprefix("/reports/")))
        else:
            self.send_error(404)

    def _send_report(self, filename: str) -> None:
        if Path(filename).name != filename or not filename.startswith("macos-inspector-"):
            self.send_error(404)
            return
        path = (self.state.output / filename).resolve()
        if path.parent != self.state.output or not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        self._headers(200, content_type, len(body), report=path.suffix == ".html", download_name=filename if path.suffix == ".zip" else None)
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/scans/") and path.endswith("/cancel"):
            if self.headers.get("X-MacOS-Inspector") != "1":
                self._send_json({"error": "Invalid local request."}, HTTPStatus.FORBIDDEN)
                return
            job_id = unquote(path.removeprefix("/api/scans/").removesuffix("/cancel")).strip("/")
            try:
                self._send_json(self.state.cancel_job(job_id), HTTPStatus.ACCEPTED)
            except KeyError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except RuntimeError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            return
        if path != "/api/scans":
            self.send_error(404)
            return
        if self.headers.get("X-MacOS-Inspector") != "1" or self.headers.get_content_type() != "application/json":
            self._send_json({"error": "Invalid local request."}, HTTPStatus.FORBIDDEN)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                raise ValueError("Invalid request size.")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("Request body must be a JSON object.")
            collectors = list(dict.fromkeys(payload.get("collectors", [])))
            formats = list(dict.fromkeys(payload.get("formats", [])))
            minimum = str(payload.get("minimum", "informational")).lower()
            case_reference = str(payload.get("case_reference", "")).strip()
            analyst = str(payload.get("analyst", "")).strip()
            if not collectors or any(item not in COLLECTORS for item in collectors):
                raise ValueError("Select at least one valid audit section.")
            if any(item not in REPORTERS for item in formats):
                raise ValueError("Unknown report format.")
            Severity.parse(minimum)
            if len(case_reference) > 200 or len(analyst) > 200 or any(ord(char) < 32 and char != "\t" for char in case_reference + analyst):
                raise ValueError("Case reference and analyst must be plain text up to 200 characters.")
            job = self.state.create_job(collectors, formats, minimum, case_reference, analyst)
            self._send_json(job.to_dict(), HTTPStatus.ACCEPTED)
        except RuntimeError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


class DashboardServer(ThreadingHTTPServer):
    def __init__(self, address, state: DashboardState) -> None:
        self.state = state
        super().__init__(address, DashboardHandler)


def serve(host: str, port: int, output: Path, open_browser: bool = True) -> int:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The dashboard may only bind to the local computer.")
    server = DashboardServer((host, port), DashboardState(output))
    url = f"http://{host}:{server.server_port}/"
    print(f"macOS Inspector dashboard: {url}")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
