from __future__ import annotations

import ipaddress
import json
import mimetypes
import os
import re
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
from urllib.parse import unquote, urlparse

from macos_inspector import __version__
from macos_inspector.collectors import COLLECTORS, LOCAL_COLLECTORS
from macos_inspector.collectors.ioc import MAX_PACK_BYTES, load_ioc_pack
from macos_inspector.core.io import read_json_limited, read_text_limited
from macos_inspector.core.models import Severity
from macos_inspector.core.comparison import compare_scan_payloads
from macos_inspector.core.process_control import terminate_reported_process
from macos_inspector.core.readiness import collect_readiness
from macos_inspector.core.scan import run_scan, write_reports
from macos_inspector.core.runner import CommandRunner, ScanCancelled
from macos_inspector.core.storage import CaseStore, SettingsStore
from macos_inspector.core.intelligence import clear_intelligence_cache, lookup_threatfox
from macos_inspector.collectors.yara_rules import MAX_RULE_BYTES, discover_yara_rules
from macos_inspector.reporters import REPORTERS, report_format_capabilities, require_report_formats
from macos_inspector.reporters.manifest_reporter import MAX_KEY_BYTES, MAX_MANIFEST_BYTES, verify_manifest
from macos_inspector.reporters.comparison_reporter import write_comparison_reports
from macos_inspector.reporters.common import secure_write_bytes, secure_write_text
from macos_inspector.reporters.encrypted_bundle import encryption_available


MAX_JOB_JOURNAL_BYTES = 2 * 1024 * 1024
MAX_REPORT_JSON_BYTES = 64 * 1024 * 1024
MAX_CACHE_RECORD_BYTES = 32 * 1024 * 1024
MAX_HISTORY_SCANS = 500
REPORT_STREAM_CHUNK_BYTES = 64 * 1024
MAX_RESPONSE_LOG_BYTES = 4 * 1024 * 1024


SCAN_PROFILES = (
    {
        "id": "quick",
        "title": "Quick triage",
        "description": "Core accounts, live processes, persistence, hardening, management, network, extension and IOC checks.",
        "collectors": ("accounts-access", "live-triage", "persistence", "background-items", "security", "management-profiles", "network", "system-extensions", "ioc"),
        "default": True,
    },
    {
        "id": "application-trust",
        "title": "Application Trust",
        "description": "Detailed trust, signature and integrity analysis for installed apps.",
        "collectors": ("application-trust",),
        "default": False,
    },
    {
        "id": "privacy-browser",
        "title": "Privacy & browsers",
        "description": "TCC permissions plus supported browser history and download evidence.",
        "collectors": ("privacy", "browser-artifacts"),
        "default": False,
    },
    {
        "id": "online-osint",
        "title": "Vulnerability Intelligence",
        "description": "Opt-in Apple, CISA KEV, FIRST EPSS and NIST NVD correlation with a last-known-good cache.",
        "collectors": ("osint-intelligence", "vulnerability-exposure"),
        "default": False,
    },
    {
        "id": "threat-hunting",
        "title": "Threat Hunting",
        "description": "Live process/network triage plus managed IOC and optional YARA rules.",
        "collectors": ("live-triage", "ioc", "yara-rules"),
        "default": False,
    },
    {
        "id": "full",
        "title": "Full local collection",
        "description": "Every local audit section, including longer application analysis; excludes online OSINT.",
        "collectors": LOCAL_COLLECTORS,
        "default": False,
    },
)


def _is_local_authority(value: str, expected_port: int) -> bool:
    """Accept only localhost or loopback IP Host authorities for this server port."""
    text = value.strip()
    if not text or any(character in text for character in ("/", "\\", "@")):
        return False
    port = None
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            return False
        host, remainder = text[1:closing], text[closing + 1:]
        if remainder:
            if not remainder.startswith(":") or not remainder[1:].isdigit():
                return False
            port = int(remainder[1:])
    else:
        if text.count(":") > 1:
            return False
        host = text
        if ":" in text:
            host, port_text = text.rsplit(":", 1)
            if not port_text.isdigit():
                return False
            port = int(port_text)
    host = host.rstrip(".").lower()
    if not host or (port is None and expected_port != 80) or (port is not None and port != expected_port):
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_local_origin(value: str, expected_port: int) -> bool:
    """Validate an optional browser Origin against the loopback HTTP boundary."""
    try:
        parsed = urlparse(value)
        if parsed.scheme != "http" or parsed.username or parsed.password:
            return False
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            return False
        port = parsed.port
        if port is None:
            port = 80
        hostname = parsed.hostname or ""
    except ValueError:
        return False
    if ":" in hostname:
        authority = f"[{hostname}]:{port}"
    else:
        authority = f"{hostname}:{port}"
    return _is_local_authority(authority, expected_port)


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
    _bundle_password: str = field(default="", repr=False)

    def to_dict(self) -> dict:
        payload = dict(self.__dict__)
        payload.pop("_bundle_password", None)
        return payload


class DashboardState:
    def __init__(self, output: Path) -> None:
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.output.chmod(0o700)
        self.data_root = self.output / ".macos-inspector-data"
        self.data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data_root.chmod(0o700)
        os.environ["MACOS_INSPECTOR_DATA_DIR"] = str(self.data_root)
        self.settings = SettingsStore(self.data_root)
        self.cases = CaseStore(self.data_root)
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
            payload = read_json_limited(self.journal_path, MAX_JOB_JOURNAL_BYTES)
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

    def create_job(self, collectors: list[str], formats: list[str], minimum: str, case_reference: str = "", analyst: str = "", bundle_password: str = "") -> ScanJob:
        requested_formats = list(dict.fromkeys(["html", "json", *formats]))
        require_report_formats(requested_formats)
        with self.lock:
            if any(job.state in {"queued", "running"} for job in self.jobs.values()):
                raise RuntimeError("A scan is already running.")
            job = ScanJob(str(uuid.uuid4()), collectors, requested_formats, minimum, case_reference, analyst, total_collectors=len(collectors), _bundle_password=bundle_password)
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
            signing = self.settings.load()["signing"]
            previous_signing_key = os.environ.get("MACOS_INSPECTOR_SIGNING_KEY")
            previous_hmac_key = os.environ.get("MACOS_INSPECTOR_MANIFEST_KEY")
            configured_key = str(signing.get("key_path", "")) if signing.get("enabled") else ""
            if configured_key and signing.get("algorithm") == "HMAC-SHA256":
                os.environ["MACOS_INSPECTOR_MANIFEST_KEY"] = read_text_limited(Path(configured_key), MAX_KEY_BYTES, "ascii").strip()
                os.environ.pop("MACOS_INSPECTOR_SIGNING_KEY", None)
            elif configured_key:
                os.environ["MACOS_INSPECTOR_SIGNING_KEY"] = configured_key
            try:
                paths = write_reports(result, job.formats, self.output, bundle_password=job._bundle_password or None)
            finally:
                if previous_signing_key is None:
                    os.environ.pop("MACOS_INSPECTOR_SIGNING_KEY", None)
                else:
                    os.environ["MACOS_INSPECTOR_SIGNING_KEY"] = previous_signing_key
                if previous_hmac_key is None:
                    os.environ.pop("MACOS_INSPECTOR_MANIFEST_KEY", None)
                else:
                    os.environ["MACOS_INSPECTOR_MANIFEST_KEY"] = previous_hmac_key
            job._bundle_password = ""
            with self.lock:
                job.state = "completed"
                job.scan_id = result.metadata.scan_id
                job.completed_at = result.metadata.completed_at
                job.summary = result.to_dict()["summary"]
                job.reports = {
                    ("encrypted-bundle" if path.name.endswith(".zip.enc") else path.suffix.lstrip(".")): f"/reports/{path.name}"
                    for path in paths
                }
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
            job._bundle_password = ""
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
        candidates = []
        for path in self.output.glob("macos-inspector-*.json"):
            try:
                candidates.append((path.stat().st_mtime, path))
            except OSError:
                continue
        for _, path in sorted(candidates, reverse=True)[:MAX_HISTORY_SCANS]:
            try:
                payload = read_json_limited(path, MAX_REPORT_JSON_BYTES)
                metadata, summary = payload["metadata"], payload["summary"]
                scan_id = metadata["scan_id"]
                if scan_id in known_scans:
                    continue
                reports = {}
                for suffix, name in (("html", "html"), ("json", "json"), ("markdown", "md"), ("csv", "csv"), ("sarif", "sarif"), ("manifest", "manifest"), ("pdf", "pdf"), ("bundle", "zip"), ("encrypted-bundle", "zip.enc")):
                    candidate = self.output / f"macos-inspector-{scan_id}.{name}"
                    if candidate.is_file():
                        reports[suffix] = f"/reports/{candidate.name}"
                historical.append({
                    "job_id": f"history-{scan_id}", "state": "completed", "scan_id": scan_id,
                    "collectors": metadata.get("collectors", []), "created_at": metadata.get("started_at"),
                    "case_reference": metadata.get("case_reference", ""), "analyst": metadata.get("analyst", ""),
                    "completed_at": metadata.get("completed_at"), "summary": summary, "reports": reports,
                })
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
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
        verification_key = os.environ.get("MACOS_INSPECTOR_MANIFEST_KEY")
        signing = self.settings.load().get("signing", {})
        if not verification_key and signing.get("algorithm") == "HMAC-SHA256":
            key_path = Path(str(signing.get("key_path", ""))).expanduser()
            if signing.get("enabled") and key_path.is_file():
                try:
                    verification_key = read_text_limited(key_path, MAX_KEY_BYTES).strip()
                except (OSError, UnicodeError, ValueError):
                    verification_key = None
        valid, errors = verify_manifest(manifest, verification_key)
        payload = read_json_limited(manifest, MAX_MANIFEST_BYTES)
        signature = payload.get("signature") or {}
        return {
            "valid": valid, "errors": errors, "artifact_count": len(payload.get("artifacts", [])),
            "algorithm": signature.get("algorithm"), "public_key_sha256": signature.get("public_key_sha256"),
        }

    def _load_scan_report(self, scan_id: str) -> dict:
        if not scan_id or Path(scan_id).name != scan_id:
            raise ValueError("Invalid scan identifier.")
        path = self.output / f"macos-inspector-{scan_id}.json"
        if not path.is_file():
            raise FileNotFoundError(f"JSON report not found: {scan_id}")
        report = read_json_limited(path, MAX_REPORT_JSON_BYTES)
        metadata = report.get("metadata") if isinstance(report, dict) else None
        if not isinstance(metadata, dict) or metadata.get("scan_id") != scan_id:
            raise ValueError("JSON report identity does not match the requested scan.")
        return report

    def compare(self, baseline_id: str, current_id: str) -> dict:
        comparison = compare_scan_payloads(self._load_scan_report(baseline_id), self._load_scan_report(current_id))
        paths = write_comparison_reports(comparison, self.output)
        comparison["reports"] = {name: f"/reports/{path.name}" for name, path in paths.items()}
        return comparison

    def terminate_process(self, scan_id: str, pid: int, mode: str, **controls) -> dict:
        report = self._load_scan_report(scan_id)
        result = terminate_reported_process(report, pid, mode, **controls)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_id,
            **result,
        }
        log_path = self.data_root / "response-actions.jsonl"
        try:
            with self.lock:
                if log_path.is_file() and log_path.stat().st_size >= MAX_RESPONSE_LOG_BYTES:
                    rotated = self.data_root / "response-actions.previous.jsonl"
                    rotated.unlink(missing_ok=True)
                    os.replace(log_path, rotated)
                descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.fchmod(descriptor, 0o600)
                    payload = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
                    written = 0
                    while written < len(payload):
                        written += os.write(descriptor, payload[written:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except OSError as exc:
            record["audit_logged"] = False
            record["audit_error"] = f"The signal was sent, but the local audit record could not be written: {exc}"
        else:
            record["audit_logged"] = True
        return record

    def list_ioc_packs(self) -> list[dict]:
        directory = self.data_root / "ioc-packs"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        records = []
        for path in sorted(directory.glob("*.json")):
            pack, error = load_ioc_pack(path)
            records.append({
                "filename": path.name, "valid": error is None, "error": error,
                "name": pack.name if pack else path.stem, "version": pack.version if pack else "",
                "source": pack.source if pack else "", "indicator_count": len(pack.indicators) if pack else 0,
                "size": path.stat().st_size,
            })
        return records

    def store_ioc_pack(self, filename: str, content: object) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.json", filename):
            raise ValueError("IOC pack filename is invalid.")
        text = json.dumps(content, indent=2, ensure_ascii=False) + "\n"
        if len(text.encode()) > MAX_PACK_BYTES:
            raise ValueError("IOC pack exceeds 2 MiB.")
        directory = self.data_root / "ioc-packs"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / filename
        secure_write_text(path, text)
        pack, error = load_ioc_pack(path)
        if error or not pack:
            path.unlink(missing_ok=True)
            raise ValueError(error or "IOC pack is disabled or empty.")
        return next(item for item in self.list_ioc_packs() if item["filename"] == filename)

    def list_yara_rules(self) -> list[dict]:
        directory = self.data_root / "yara-rules"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        valid, errors = discover_yara_rules(directory)
        valid_names = {path.name for path in valid}
        error_map = {entry.split(":", 1)[0]: entry for entry in errors}
        return [{
            "filename": path.name, "valid": path.name in valid_names, "error": error_map.get(path.name),
            "size": path.stat().st_size,
        } for path in sorted((*directory.glob("*.yar"), *directory.glob("*.yara")))]

    def store_yara_rule(self, filename: str, content: object) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.ya(?:r|ra)", filename):
            raise ValueError("YARA filename is invalid.")
        if not isinstance(content, str) or not content.strip() or len(content.encode()) > MAX_RULE_BYTES:
            raise ValueError("YARA content is empty or too large.")
        if not re.search(r"\brule\s+[A-Za-z_][A-Za-z0-9_]*", content):
            raise ValueError("No YARA rule declaration was found.")
        directory = self.data_root / "yara-rules"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        secure_write_text(directory / filename, content.rstrip() + "\n")
        return next(item for item in self.list_yara_rules() if item["filename"] == filename)

    def delete_managed_file(self, kind: str, filename: str) -> None:
        directory_name, suffixes = ("ioc-packs", {".json"}) if kind == "ioc-packs" else ("yara-rules", {".yar", ".yara"})
        if Path(filename).name != filename or Path(filename).suffix.lower() not in suffixes:
            raise ValueError("Managed filename is invalid.")
        path = (self.data_root / directory_name / filename).resolve()
        if path.parent != (self.data_root / directory_name).resolve() or not path.is_file():
            raise FileNotFoundError("Managed file not found.")
        path.unlink()

    def cache_status(self) -> list[dict]:
        directory = self.data_root / "osint-cache"
        records = []
        if directory.is_dir():
            for path in sorted(directory.glob("*.json")):
                try:
                    raw = read_json_limited(path, MAX_CACHE_RECORD_BYTES)
                    records.append({
                        "name": path.stem, "provider": raw.get("provider", ""), "url": raw.get("url", ""),
                        "fetched_at": raw.get("fetched_at", ""), "sha256": raw.get("sha256", ""), "size": path.stat().st_size,
                    })
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
        return records

    def generate_signing_key(self, replace: bool = False) -> dict:
        signing = self.settings.load().get("signing", {})
        current_path = Path(str(signing.get("key_path", ""))).expanduser()
        if current_path.is_file() and not replace:
            raise RuntimeError("A signing identity is already configured. Confirm replacement explicitly.")
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError:
            import secrets
            directory = self.data_root / "keys"
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = directory / "manifest-hmac.key"
            secure_write_text(path, secrets.token_hex(32))
            self.settings.update({"signing": {"enabled": True, "key_path": str(path), "algorithm": "HMAC-SHA256"}})
            return {"configured": True, "algorithm": "HMAC-SHA256", "public_key_sha256": None}
        directory = self.data_root / "keys"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        path = directory / "manifest-ed25519.pem"
        private_key = ed25519.Ed25519PrivateKey.generate()
        payload = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        secure_write_bytes(path, payload)
        self.settings.update({"signing": {"enabled": True, "key_path": str(path), "algorithm": "Ed25519"}})
        public_der = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        import hashlib
        return {"configured": True, "algorithm": "Ed25519", "public_key_sha256": hashlib.sha256(public_der).hexdigest()}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = f"macOSInspector/{__version__}"

    @property
    def state(self) -> DashboardState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args) -> None:
        return

    def _require_local_request(self) -> bool:
        expected_port = self.server.server_port  # type: ignore[attr-defined]
        hosts = self.headers.get_all("Host", [])
        origins = self.headers.get_all("Origin", [])
        if (
            len(hosts) != 1
            or len(origins) > 1
            or not _is_local_authority(hosts[0], expected_port)
            or (origins and not _is_local_origin(origins[0], expected_port))
        ):
            self._send_json({"error": "Invalid local request."}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def _headers(self, status: int, content_type: str, length: int, report: bool = False, download_name: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
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

    def _read_json_body(self, max_bytes: int = 65536) -> dict:
        if self.headers.get("X-MacOS-Inspector") != "1" or self.headers.get_content_type() != "application/json":
            raise PermissionError("Invalid local request.")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > max_bytes:
            raise ValueError("Invalid request size.")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        return payload

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
        if not self._require_local_request():
            return
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
                "collectors": [{
                    "id": key, "title": value.title, "description": value.description,
                    "external_network": value.external_network, "privacy_note": value.privacy_note,
                } for key, value in COLLECTORS.items()],
                "profiles": SCAN_PROFILES,
                "formats": list(REPORTERS), "format_capabilities": report_format_capabilities(),
                "feature_capabilities": {
                    "signing": {"available": True, "reason": "HMAC-SHA256 is built in; Ed25519 is used when the optional signing dependency is available."},
                    "yara": {"available": Path(CommandRunner.ALLOWED["yara"]).is_file(), "reason": "" if Path(CommandRunner.ALLOWED["yara"]).is_file() else "Install YARA with Homebrew to enable local rule execution."},
                    "process_response": {"available": os.geteuid() != 0, "reason": "" if os.geteuid() != 0 else "Process response is disabled when the dashboard runs as root."},
                },
                "severities": [severity.label() for severity in Severity],
            })
        elif path == "/api/health":
            self._send_json(self.state.health())
        elif path == "/api/readiness":
            self._send_json(self.state.readiness())
        elif path == "/api/settings":
            self._send_json(self.state.settings.public())
        elif path == "/api/cases":
            self._send_json({"cases": self.state.cases.list()})
        elif path == "/api/ioc-packs":
            self._send_json({"packs": self.state.list_ioc_packs()})
        elif path == "/api/yara-rules":
            self._send_json({"rules": self.state.list_yara_rules()})
        elif path == "/api/osint-cache":
            self._send_json({"entries": self.state.cache_status()})
        elif path == "/api/scans":
            self._send_json({"scans": self.state.list_jobs()})
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
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        try:
            handle = path.open("rb")
        except OSError:
            self._send_json({"error": "Report could not be read."}, HTTPStatus.NOT_FOUND)
            return
        with handle:
            try:
                length = os.fstat(handle.fileno()).st_size
            except OSError:
                self._send_json({"error": "Report could not be read."}, HTTPStatus.NOT_FOUND)
                return
            self._headers(200, content_type, length, report=path.suffix == ".html", download_name=filename if filename.endswith((".zip", ".zip.enc")) else None)
            try:
                remaining = length
                while remaining:
                    chunk = handle.read(min(REPORT_STREAM_CHUNK_BYTES, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
            except OSError:
                return

    def do_POST(self) -> None:
        if not self._require_local_request():
            return
        path = urlparse(self.path).path
        if path == "/api/processes/terminate":
            try:
                payload = self._read_json_body(4096)
                self._send_json(self.state.terminate_process(
                    str(payload.get("scan_id", "")), payload.get("pid"), str(payload.get("mode", "terminate")),
                ))
            except PermissionError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
            except FileNotFoundError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except ProcessLookupError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except RuntimeError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if path == "/api/compare":
            try:
                payload = self._read_json_body(4096)
                self._send_json(self.state.compare(str(payload.get("baseline", "")), str(payload.get("current", ""))))
            except PermissionError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
            except FileNotFoundError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
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
        if path in {"/api/settings", "/api/cases", "/api/ioc-packs", "/api/yara-rules", "/api/osint-cache/clear", "/api/signing/generate", "/api/threatfox/lookup"}:
            try:
                payload = self._read_json_body(6 * 1024 * 1024)
                if path == "/api/settings":
                    result = self.state.settings.update(payload)
                elif path == "/api/cases":
                    result = self.state.cases.save(payload)
                elif path == "/api/ioc-packs":
                    result = self.state.store_ioc_pack(str(payload.get("filename", "")), payload.get("content"))
                elif path == "/api/yara-rules":
                    result = self.state.store_yara_rule(str(payload.get("filename", "")), payload.get("content"))
                elif path == "/api/signing/generate":
                    result = self.state.generate_signing_key(bool(payload.get("replace", False)))
                elif path == "/api/threatfox/lookup":
                    result = lookup_threatfox(str(payload.get("indicator", "")))
                else:
                    result = {"cleared": clear_intelligence_cache()}
                self._send_json(result, HTTPStatus.CREATED if path in {"/api/cases", "/api/ioc-packs", "/api/yara-rules"} else HTTPStatus.OK)
            except PermissionError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
            except RuntimeError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
            except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        if path != "/api/scans":
            self.send_error(404)
            return
        try:
            payload = self._read_json_body()
            collectors = list(dict.fromkeys(payload.get("collectors", [])))
            formats = list(dict.fromkeys(payload.get("formats", [])))
            minimum = str(payload.get("minimum", "informational")).lower()
            case_reference = str(payload.get("case_reference", "")).strip()
            analyst = str(payload.get("analyst", "")).strip()
            bundle_password = str(payload.get("bundle_password", ""))
            if not collectors or any(item not in COLLECTORS for item in collectors):
                raise ValueError("Select at least one valid audit section.")
            if any(item not in REPORTERS for item in formats):
                raise ValueError("Unknown report format.")
            Severity.parse(minimum)
            if len(case_reference) > 200 or len(analyst) > 200 or any(ord(char) < 32 and char != "\t" for char in case_reference + analyst):
                raise ValueError("Case reference and analyst must be plain text up to 200 characters.")
            if "encrypted-bundle" in formats and not 12 <= len(bundle_password) <= 256:
                raise ValueError("Encrypted case bundle password must contain 12 to 256 characters.")
            if "encrypted-bundle" not in formats:
                bundle_password = ""
            job = self.state.create_job(collectors, formats, minimum, case_reference, analyst, bundle_password)
            self._send_json(job.to_dict(), HTTPStatus.ACCEPTED)
        except RuntimeError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_DELETE(self) -> None:
        if not self._require_local_request():
            return
        path = urlparse(self.path).path
        if self.headers.get("X-MacOS-Inspector") != "1":
            self._send_json({"error": "Invalid local request."}, HTTPStatus.FORBIDDEN)
            return
        match = re.fullmatch(r"/api/(ioc-packs|yara-rules)/([^/]+)", path)
        if not match:
            self.send_error(404)
            return
        try:
            self.state.delete_managed_file(match.group(1), unquote(match.group(2)))
            self._send_json({"deleted": True})
        except FileNotFoundError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
        except (OSError, ValueError) as exc:
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
