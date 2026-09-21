import tempfile
import unittest
import csv
import hashlib
import http.client
import io
import sqlite3
import json
import importlib.util
import plistlib
import re
import signal
import threading
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from unittest.mock import patch
from pathlib import Path

from macos_inspector.collectors.application_trust import (
    ApplicationTrustCollector,
    BundlePathDetails,
    FileIntegrityDetails,
    SignatureDetails,
    assess_bundle_paths,
    assess_file_integrity,
    assess_metadata_integrity,
    classify_trust,
    discover_applications,
    inspect_file_integrity,
    inspect_bundle_paths,
    merge_trust_assessments,
    assess_entitlements,
    parse_codesign_details,
    parse_entitlements,
    parse_gatekeeper_details,
    parse_quarantine,
    parse_where_froms_hex,
)
from macos_inspector.collectors.background_items import BackgroundItemsCollector, parse_disabled_services
from macos_inspector.collectors.browser_artifacts import BrowserArtifactsCollector
from macos_inspector.collectors.persistence import _program_from_plist
from macos_inspector.collectors.privacy import PrivacyCollector
from macos_inspector.collectors.network import NetworkCollector, enabled_proxy_types, parse_certificate_hashes, parse_proxy_configuration
from macos_inspector.collectors.system_extensions import parse_system_extensions
from macos_inspector.collectors.ioc import IOCCollector
from macos_inspector.collectors import COLLECTORS, LOCAL_COLLECTORS
from macos_inspector.collectors.security import SecurityControlsCollector
from macos_inspector.collectors.management_profiles import ManagementProfilesCollector, parse_configuration_profile_status, parse_enrollment_status
from macos_inspector.collectors.accounts_access import AccountsAccessCollector, account_anomalies, parse_group_members, parse_user_records, regular_accounts
from macos_inspector.collectors.osint_intelligence import CISA_KEV_FEED, OSINTIntelligenceCollector, apple_kev_entries, validate_cisa_kev
from macos_inspector.collectors.vulnerability_exposure import VulnerabilityExposureCollector, macos_kev_entries, nvd_macos_range, parse_sw_vers
from macos_inspector.collectors.live_triage import (
    LiveTriageCollector,
    deduplicate_connections,
    network_risk_candidates,
    parse_cwd_fields,
    parse_lsof_fields,
    parse_process_context,
    parse_processes,
    merge_process_context,
    socket_exposure,
    sanitize_command_line,
    suspicious_processes,
)
from macos_inspector.collectors.yara_rules import discover_yara_rules, parse_yara_matches
from macos_inspector.core.intelligence import (
    IntelligenceResource,
    fetch_cached_json,
    lookup_hash_reputation,
    lookup_malwarebazaar_hash,
    lookup_virustotal_hash,
    parse_apple_security_releases,
    validate_epss,
    validate_nvd,
)
from macos_inspector.core.io import read_json_limited
from macos_inspector.core.storage import CaseStore, InvestigationStore, SettingsStore
from macos_inspector.core.guidance import build_guidance, finding_fingerprint
from macos_inspector.core.decision_support import build_decision_support, confidence_for_finding, write_investigation_summary
from macos_inspector.core.models import Evidence, Finding, ScanMetadata, ScanResult, Severity
from macos_inspector.core.comparison import compare_scan_payloads
from macos_inspector.core.process_control import review_process_candidates, terminate_reported_process
from macos_inspector.core.runner import CommandResult, CommandRunner, ScanCancelled
from macos_inspector.core.readiness import _probe_sqlite_readable, collect_readiness
from macos_inspector.core.scan import run_scan, write_reports
from macos_inspector.core.scoring import calculate_scores
from macos_inspector.core.timeline import build_timeline
from macos_inspector.reporters import REPORTERS, report_format_capabilities, require_report_formats
from macos_inspector.reporters.manifest_reporter import verify_manifest, write_manifest
from macos_inspector.reporters.comparison_reporter import write_comparison_reports
from macos_inspector.reporters.encrypted_bundle import decrypt_file, encryption_available
from macos_inspector.web import DashboardServer, DashboardState, SCAN_PROFILES, ScanJob, _is_local_authority, _is_local_origin
from scripts.build_release import LAUNCHER, build_release
from macos_inspector.cli import parser as cli_parser


def finding(severity=Severity.HIGH, status="Fail"):
    return Finding("TEST-1", "Persistence", "Test", severity, status, "Description", "Why", "Checked", "Expected", "Observed", "Recommendation", (Evidence("test", "unit", "value"),))


def dashboard_request(server, method, path, host, *, origin=None, payload=None, extra_host=None, extra_origin=None, write_header=True):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    body = json.dumps(payload).encode() if payload is not None else None
    connection.putrequest(method, path, skip_host=True)
    connection.putheader("Host", host)
    if extra_host is not None:
        connection.putheader("Host", extra_host)
    if origin is not None:
        connection.putheader("Origin", origin)
    if extra_origin is not None:
        connection.putheader("Origin", extra_origin)
    if body is not None:
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(body)))
        if write_header:
            connection.putheader("X-MacOS-Inspector", "1")
    connection.endheaders(body)
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


class CoreTests(unittest.TestCase):
    def test_dashboard_rejects_dns_rebinding_hosts_and_cross_origin_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            server = DashboardServer(("127.0.0.1", 0), state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_port
            try:
                status, headers, _ = dashboard_request(server, "GET", "/api/health", f"127.0.0.1:{port}")
                self.assertEqual(status, 200)
                self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
                self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN")

                for host in (f"attacker.example:{port}", f"localhost.attacker.example:{port}", f"127.0.0.1.example:{port}"):
                    status, _, body = dashboard_request(server, "GET", "/api/health", host)
                    self.assertEqual(status, 403)
                    self.assertIn(b"Invalid local request", body)

                status, _, _ = dashboard_request(
                    server, "GET", "/api/health", f"127.0.0.1:{port}", extra_host=f"localhost:{port}",
                )
                self.assertEqual(status, 403)

                status, _, _ = dashboard_request(
                    server, "POST", "/api/settings", f"127.0.0.1:{port}",
                    origin=f"http://attacker.example:{port}", payload={"cache_hours": 7},
                )
                self.assertEqual(status, 403)
                self.assertEqual(state.settings.load()["cache_hours"], 24)

                status, _, _ = dashboard_request(
                    server, "POST", "/api/settings", f"127.0.0.1:{port}",
                    origin=f"http://127.0.0.1:{port}", extra_origin=f"http://localhost:{port}", payload={"cache_hours": 7},
                )
                self.assertEqual(status, 403)
                self.assertEqual(state.settings.load()["cache_hours"], 24)

                status, _, _ = dashboard_request(
                    server, "POST", "/api/settings", f"127.0.0.1:{port}",
                    origin=f"http://127.0.0.1:{port}", payload={"cache_hours": 7},
                )
                self.assertEqual(status, 200)
                self.assertEqual(state.settings.load()["cache_hours"], 7)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_dashboard_comparison_reports_require_protected_post(self):
        def scan_payload(scan_id, score):
            return {
                "metadata": {"scan_id": scan_id, "collectors": ["security"]},
                "summary": {"overall_score": score, "category_scores": {"Security": score}},
                "findings": [],
            }

        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            for scan_id, score in (("baseline", 80), ("current", 90)):
                (state.output / f"macos-inspector-{scan_id}.json").write_text(json.dumps(scan_payload(scan_id, score)))
            server = DashboardServer(("127.0.0.1", 0), state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_port
            try:
                status, _, _ = dashboard_request(
                    server, "GET", "/api/compare?baseline=baseline&current=current", f"127.0.0.1:{port}",
                )
                self.assertEqual(status, 404)
                self.assertFalse(list(state.output.glob("macos-inspector-comparison-*")))

                status, _, _ = dashboard_request(
                    server, "POST", "/api/compare", f"127.0.0.1:{port}",
                    payload={"baseline": "baseline", "current": "current"}, write_header=False,
                )
                self.assertEqual(status, 403)
                self.assertFalse(list(state.output.glob("macos-inspector-comparison-*")))

                status, _, body = dashboard_request(
                    server, "POST", "/api/compare", f"127.0.0.1:{port}",
                    payload={"baseline": "baseline", "current": "current"},
                )
                self.assertEqual(status, 200)
                comparison = json.loads(body)
                self.assertEqual(comparison["score_delta"], 10)
                self.assertEqual(len(list(state.output.glob("macos-inspector-comparison-*"))), 2)

                status, _, body = dashboard_request(
                    server, "GET", comparison["reports"]["comparison_json"], f"127.0.0.1:{port}",
                )
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["score_delta"], 10)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_local_json_inputs_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.json"
            path.write_text('{"value": 7}', encoding="utf-8")
            self.assertEqual(read_json_limited(path, path.stat().st_size), {"value": 7})
            with self.assertRaisesRegex(ValueError, "size limit"):
                read_json_limited(path, path.stat().st_size - 1)

            report = Path(directory) / "macos-inspector-oversized.json"
            report.write_text('{"metadata": {"scan_id": "oversized"}, "summary": {}, "findings": []}', encoding="utf-8")
            state = DashboardState(Path(directory))
            with patch("macos_inspector.web.MAX_REPORT_JSON_BYTES", 32):
                self.assertFalse(state.list_jobs())
                with self.assertRaisesRegex(ValueError, "size limit"):
                    state.compare("oversized", "oversized")

            manifest = Path(directory) / "oversized.manifest"
            manifest.write_text('{"artifacts": []}', encoding="utf-8")
            with patch("macos_inspector.reporters.manifest_reporter.MAX_MANIFEST_BYTES", 8):
                valid, errors = verify_manifest(manifest)
            self.assertFalse(valid)
            self.assertIn("size limit", errors[0])

    def test_dashboard_local_authority_and_origin_validation(self):
        port = 8765
        for authority in ("localhost:8765", "LOCALHOST.:8765", "127.0.0.1:8765", "[::1]:8765"):
            self.assertTrue(_is_local_authority(authority, port), authority)
        for authority in ("", "localhost", "localhost:9000", "localhost.example:8765", "127.0.0.1.example:8765", "127.1:8765", "[::1]:9000", "user@localhost:8765"):
            self.assertFalse(_is_local_authority(authority, port), authority)
        self.assertTrue(_is_local_origin("http://localhost:8765", port))
        self.assertTrue(_is_local_origin("http://[::1]:8765", port))
        for origin in ("null", "https://localhost:8765", "http://localhost:9000", "http://attacker.example:8765", "http://localhost:8765/path"):
            self.assertFalse(_is_local_origin(origin, port), origin)

    def test_settings_cases_and_secrets_remain_local(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = SettingsStore(root)
            public = settings.update({
                "cache_hours": 12,
                "providers": {
                    "nvd": {"enabled": True, "api_key": "nvd-secret"},
                    "threatfox": {"enabled": True, "auth_key": "fox-secret"},
                    "virustotal": {"enabled": True, "api_key": "vt-secret"},
                    "malwarebazaar": {"enabled": True, "auth_key": "bazaar-secret"},
                },
                "yara": {"enabled": True, "targets": ["~/Downloads"]},
            })
            self.assertNotIn("language", public)
            self.assertTrue(public["providers"]["nvd"]["api_key_configured"])
            self.assertTrue(public["providers"]["virustotal"]["api_key_configured"])
            self.assertTrue(public["providers"]["malwarebazaar"]["auth_key_configured"])
            for secret in ("nvd-secret", "fox-secret", "vt-secret", "bazaar-secret"):
                self.assertNotIn(secret, json.dumps(public))
            self.assertEqual(settings.path.stat().st_mode & 0o777, 0o600)

            cases = CaseStore(root)
            saved = cases.save({"reference": "IR-12", "title": "Suspicious launch item", "analyst": "DFIR", "notes": "Preserve first.", "archived": False})
            self.assertEqual(cases.list()[0]["id"], saved["id"])
            self.assertEqual(cases.path.stat().st_mode & 0o777, 0o600)

    def test_guided_investigation_is_plain_language_and_kept_separate_from_evidence(self):
        finding_payload = {
            "finding_id": "APP-TRUST-TEST",
            "category": "Application Trust",
            "title": "Application trust: Example",
            "severity": "High",
            "status": "Review",
            "description": "Checks application trust.",
            "observed_result": "The signature is valid, but the executable is writable by other users.",
            "evidence": [
                {"kind": "application_bundle", "source": "/Applications/Example.app", "value": {"name": "Example", "version": "1.0", "bundle_identifier": "test.example", "executable": "/Applications/Example.app/Contents/MacOS/Example"}, "collected_at": "first"},
                {"kind": "code_signature", "source": "/Applications/Example.app", "value": {"valid": True, "team_identifier": "TEAM123"}, "collected_at": "first"},
                {"kind": "executable_integrity", "source": "/Applications/Example.app/Contents/MacOS/Example", "value": {"sha256": "a" * 64}, "collected_at": "first"},
                {"kind": "gatekeeper_assessment", "source": "/Applications/Example.app", "value": {"accepted": True}, "collected_at": "first"},
            ],
        }
        report = {"metadata": {"scan_id": "guided-scan"}, "summary": {}, "findings": [finding_payload]}
        fingerprint = finding_fingerprint(finding_payload)
        changed_timestamp = json.loads(json.dumps(finding_payload))
        changed_timestamp["evidence"][0]["collected_at"] = "second"
        self.assertEqual(finding_fingerprint(changed_timestamp), fingerprint)

        guidance = build_guidance(report)
        self.assertEqual(guidance["counts"]["attention"], 1)
        item = guidance["findings"]["APP-TRUST-TEST"]
        self.assertEqual(item["label"], "Needs review")
        self.assertNotIn("executable_sha256", item["simple_explanation"])
        self.assertEqual(item["context"]["publisher_team_id"], "TEAM123")
        self.assertIn("not proof of malware", guidance["plain_language_note"])

        with tempfile.TemporaryDirectory() as directory:
            store = InvestigationStore(Path(directory))
            saved = store.save(report, {"finding_id": "APP-TRUST-TEST", "status": "Expected", "note": "Installed by the owner."})
            self.assertEqual(saved["status"], "Expected")
            self.assertEqual(store.path.stat().st_mode & 0o777, 0o600)
            current = store.for_report(report)["APP-TRUST-TEST"]
            self.assertEqual(current["status"], "Expected")
            self.assertTrue(current["current"])
            expected_guidance = build_guidance(report, store.for_report(report))
            self.assertEqual(expected_guidance["counts"]["attention"], 0)

            changed_binary = json.loads(json.dumps(report))
            changed_binary["findings"][0]["evidence"][2]["value"]["sha256"] = "b" * 64
            stale = store.for_report(changed_binary)["APP-TRUST-TEST"]
            self.assertEqual(stale["status"], "New")
            self.assertFalse(stale["current"])
            self.assertEqual(stale["previous_status"], "Expected")

    def test_guidance_and_investigation_endpoints_require_local_protected_requests(self):
        report = {
            "metadata": {"scan_id": "guided-endpoint"},
            "summary": {"overall_score": 80},
            "findings": [{
                "finding_id": "TEST-GUIDED", "category": "Security", "title": "Test guided item",
                "severity": "Medium", "status": "Review", "description": "Description",
                "observed_result": "An item needs review.", "evidence": [],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            (state.output / "macos-inspector-guided-endpoint.json").write_text(json.dumps(report), encoding="utf-8")
            server = DashboardServer(("127.0.0.1", 0), state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host = f"127.0.0.1:{server.server_port}"
                status, _, body = dashboard_request(server, "GET", "/api/guidance/guided-endpoint", host)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["counts"]["attention"], 1)

                status, _, _ = dashboard_request(server, "POST", "/api/investigations", host, payload={
                    "scan_id": "guided-endpoint", "finding_id": "TEST-GUIDED", "status": "Investigating", "note": "Checking ownership.",
                }, write_header=False)
                self.assertEqual(status, 403)

                status, _, body = dashboard_request(server, "POST", "/api/investigations", host, payload={
                    "scan_id": "guided-endpoint", "finding_id": "TEST-GUIDED", "status": "Investigating", "note": "Checking ownership.",
                })
                self.assertEqual(status, 200)
                saved = json.loads(body)
                self.assertEqual(saved["record"]["status"], "Investigating")
                self.assertEqual(saved["guidance"]["findings"]["TEST-GUIDED"]["investigation"]["note"], "Checking ownership.")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_decision_support_separates_confidence_changes_and_correlations(self):
        def application(sha256):
            return {
                "finding_id": "APP-TRUST-EXAMPLE", "category": "Application Trust",
                "title": "Application trust: Example", "severity": "High", "status": "Review",
                "description": "Checks application trust.", "observed_result": "The application needs review.",
                "evidence": [
                    {"kind": "application_bundle", "source": "/Applications/Example.app", "value": {"name": "Example", "version": "1.0", "bundle_identifier": "test.example", "executable": "/Applications/Example.app/Contents/MacOS/Example"}},
                    {"kind": "code_signature", "source": "/Applications/Example.app", "value": {"valid": True, "team_identifier": "TEAM123", "signature_type": "Developer ID", "authority": ["Developer ID Application: Example Company (TEAM123)"]}},
                    {"kind": "executable_integrity", "source": "/Applications/Example.app/Contents/MacOS/Example", "value": {"sha256": sha256}},
                    {"kind": "gatekeeper_assessment", "source": "/Applications/Example.app", "value": {"accepted": True, "source": "Notarized Developer ID", "origin": "Developer ID Application: Example Company (TEAM123)"}},
                    {"kind": "quarantine_attribute", "source": "/Applications/Example.app", "value": {"present": True, "agent": "Safari", "timestamp_iso": "2026-01-01T10:00:00+00:00"}},
                    {"kind": "download_sources", "source": "/Applications/Example.app", "value": {"sources": ["https://downloads.example.test/app.dmg?campaign=release-test"]}},
                ],
            }
        baseline = {
            "metadata": {"scan_id": "baseline", "tool_version": "1.3.2", "collectors": ["application-trust", "live-triage"], "target_application": "/Applications/Example.app", "completed_at": "2026-01-01T00:00:00+00:00"},
            "summary": {}, "findings": [application("a" * 64)],
        }
        current_app = application("b" * 64)
        process = {
            "finding_id": "LIVE-PROCESS-TREE", "category": "Live Triage", "title": "Running process tree snapshot",
            "severity": "Low", "status": "Review", "description": "Live process review.", "observed_result": "One candidate.",
            "evidence": [{"kind": "process_snapshot", "source": "local", "value": {
                "running_processes": [
                    {"pid": 42, "stat": "S", "elapsed": "01:20", "executable": "/Applications/Example.app/Contents/MacOS/Example"},
                    {"pid": 43, "stat": "S", "executable": "/Applications/Example.app.helper/Contents/MacOS/Helper"},
                ],
                "review_candidates": [{
                    "pid": 42, "uid": 501, "user": "owner", "executable": "/Applications/Example.app/Contents/MacOS/Example", "reason": "test", "priority": "low",
                }],
            }}],
        }
        network = {
            "finding_id": "LIVE-NETWORK-PROCESSES", "category": "Live Triage", "title": "Process and network connection correlation",
            "severity": "Informational", "status": "Observed", "description": "Network context.", "observed_result": "One connection.",
            "evidence": [{"kind": "network_process_snapshot", "source": "local", "value": {
                "listeners": [],
                "established": [
                    {"pid": 42, "state": "ESTABLISHED", "endpoint": "127.0.0.1:5000->127.0.0.1:443", "executable": "/Applications/Example.app/Contents/MacOS/Example"},
                    {"pid": 43, "state": "ESTABLISHED", "endpoint": "127.0.0.1:5001->127.0.0.1:443", "executable": "/Applications/Example.app.helper/Contents/MacOS/Helper"},
                ],
            }}],
        }
        persistence = {
            "finding_id": "PERSIST-LAUNCHD-EXAMPLE", "category": "Persistence", "title": "launchd item: Example",
            "severity": "Informational", "status": "Observed", "description": "Startup context.", "observed_result": "Configured.",
            "evidence": [{"kind": "plist", "source": "/Library/LaunchAgents/test.example.plist", "value": {
                "label": "test.example", "program": "/Applications/Example.app/Contents/MacOS/Example",
            }}],
        }
        current = {
            "metadata": {"scan_id": "current", "tool_version": "1.3.3", "hostname": "fixture", "collectors": ["application-trust", "live-triage"], "target_application": "/Applications/Example.app", "completed_at": "2026-01-02T00:00:00+00:00"},
            "summary": {}, "findings": [current_app, process, network, persistence],
        }
        result = build_decision_support(current, baseline)
        app_guidance = result["guidance"]["findings"]["APP-TRUST-EXAMPLE"]
        self.assertEqual(app_guidance["confidence"]["level"], "high")
        self.assertEqual(result["changes"]["counts"]["changed_applications"], 1)
        self.assertEqual(len(result["changes"]["application_changes"]), 1)
        self.assertTrue(result["changes"]["comparison_context"]["different_tool_versions"])
        self.assertEqual(result["changes"]["comparison_context"]["baseline_tool_version"], "1.3.2")
        self.assertEqual(result["changes"]["comparison_context"]["current_tool_version"], "1.3.3")
        self.assertIn("newly observed evidence does not always mean", result["changes"]["comparison_context"]["message"])
        self.assertEqual(result["changes"]["highlights"][0]["label"], "Changed app still needs review")
        self.assertEqual(result["changes"]["highlights"][0]["priority"], "high")
        self.assertEqual(result["changes"]["highlights"][0]["changed_fields"][0]["label"], "Executable SHA-256")
        self.assertEqual(result["changes"]["highlights"][0]["changed_fields"][0]["before"], "aaaaaaaaaaaaaaaa...")
        self.assertEqual(len(result["stories"]), 1)
        self.assertIn("application", result["stories"][0]["title"])
        self.assertEqual(result["application_review"]["counts"]["review_first"], 1)
        self.assertEqual(result["application_review"]["applications"][0]["name"], "Example")
        self.assertEqual(result["application_review"]["applications"][0]["change"]["label"], "Changed app still needs review")
        provenance = result["application_review"]["applications"][0]["provenance"]
        self.assertEqual(provenance["publisher"], "Developer ID Application: Example Company (TEAM123)")
        self.assertEqual(provenance["source_hosts"], ["downloads.example.test"])
        self.assertEqual(provenance["download_agent"], "Safari")
        self.assertEqual(provenance["install_scope"], "Installed for all users")
        self.assertNotIn("campaign", json.dumps(provenance))
        activity = result["application_review"]["applications"][0]["activity"]
        self.assertEqual(len(activity["running_processes"]), 1)
        self.assertEqual(len(activity["network_connections"]), 1)
        self.assertEqual(len(activity["startup_items"]), 1)
        self.assertEqual(activity["counts"], {"running": 1, "network": 1, "startup": 1})
        self.assertFalse(activity["details_truncated"])
        self.assertEqual(activity["coverage"], {
            "running": True, "network": True, "startup": True, "available": True,
        })
        self.assertEqual(result["application_review"]["activity_counts"], {
            "running": 1, "network": 1, "starts_automatically": 1,
        })
        self.assertEqual(confidence_for_finding({"status": "Unknown", "evidence": []})["level"], "low")
        with tempfile.TemporaryDirectory() as directory:
            path = write_investigation_summary(current, result, Path(directory))
            html = path.read_text(encoding="utf-8")
            self.assertIn("Changes since the previous comparable scan", html)
            self.assertIn("Comparison note:", html)
            self.assertIn("macOS Inspector 1.3.2 and 1.3.3", html)
            self.assertIn("Changed app still needs review", html)
            self.assertIn("Next: Open the current result and resolve its signature", html)
            self.assertIn("Application review queue", html)
            self.assertIn("Example", html)
            self.assertIn("Publisher context: Developer ID Application: Example Company (TEAM123)", html)
            self.assertIn("Source context: downloads.example.test", html)
            self.assertNotIn("campaign=release-test", html)
            self.assertIn("Observed activity: running processes: 1, network endpoints: 1, startup items: 1", html)
            self.assertIn("Target application: /Applications/Example.app", html)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

        updated_app = application("c" * 64)
        updated_app["severity"] = "Informational"
        updated_app["status"] = "Pass"
        updated_app["evidence"][0]["value"]["version"] = "2.0"
        updated = {**current, "findings": [updated_app]}
        update_change = build_decision_support(updated, baseline)["changes"]["highlights"][0]
        self.assertEqual(update_change["label"], "Possible application update")
        self.assertEqual(update_change["priority"], "context")
        self.assertIn("Team ID TEAM123 remained the same", update_change["detail"])

        coverage_before = application("a" * 64)
        coverage_before["severity"] = "Informational"
        coverage_before["status"] = "Pass"
        coverage_after = application("a" * 64)
        coverage_after["severity"] = "High"
        coverage_after["status"] = "Review"
        coverage_after["evidence"].append({
            "kind": "info_plist_integrity", "source": "/Applications/Example.app/Contents/Info.plist",
            "value": {"permissions": "0644", "changed_during_read": False},
        })
        coverage_baseline = {**baseline, "findings": [coverage_before]}
        coverage_report = {**current, "findings": [coverage_after]}
        coverage_changes = build_decision_support(coverage_report, coverage_baseline)["changes"]
        coverage_change = coverage_changes["application_changes"][0]
        self.assertEqual(coverage_changes["counts"]["changed_applications"], 0)
        self.assertEqual(coverage_changes["counts"]["application_coverage_changes"], 1)
        self.assertEqual(coverage_change["kind"], "application-coverage-change")
        self.assertEqual(coverage_change["label"], "New concern from expanded checks")
        self.assertEqual(coverage_change["priority"], "high")
        self.assertIn("do not assume the application itself changed", coverage_change["next_action"])

        unresolved_update = application("c" * 64)
        unresolved_update["evidence"][0]["value"]["version"] = "2.0"
        unresolved_report = {**current, "findings": [unresolved_update]}
        unresolved_change = build_decision_support(unresolved_report, baseline)["changes"]["highlights"][0]
        self.assertEqual(unresolved_change["label"], "Changed app still needs review")
        self.assertEqual(unresolved_change["priority"], "high")
        self.assertIn("current trust result is review", unresolved_change["detail"])

        trusted_permissions = application("a" * 64)
        trusted_permissions["severity"] = "Informational"
        trusted_permissions["status"] = "Pass"
        trusted_permissions["evidence"][2]["value"]["permissions"] = "0755"
        permissions_baseline = {**baseline, "findings": [trusted_permissions]}
        weakened_permissions = application("a" * 64)
        weakened_permissions["evidence"][2]["value"]["permissions"] = "0777"
        permissions_report = {**current, "findings": [weakened_permissions]}
        permission_change = build_decision_support(permissions_report, permissions_baseline)["changes"]["highlights"][0]
        self.assertEqual(permission_change["label"], "Executable permissions weakened")
        self.assertEqual(permission_change["priority"], "high")
        self.assertIn("0755", permission_change["detail"])
        self.assertIn("0777", permission_change["detail"])

        trusted_metadata = application("a" * 64)
        trusted_metadata["severity"] = "Informational"
        trusted_metadata["status"] = "Pass"
        trusted_metadata["evidence"].append({
            "kind": "info_plist_integrity", "source": "/Applications/Example.app/Contents/Info.plist",
            "value": {"permissions": "0644"},
        })
        weakened_metadata = application("a" * 64)
        weakened_metadata["evidence"].append({
            "kind": "info_plist_integrity", "source": "/Applications/Example.app/Contents/Info.plist",
            "value": {"permissions": "0666"},
        })
        metadata_baseline = {**baseline, "findings": [trusted_metadata]}
        metadata_report = {**current, "findings": [weakened_metadata]}
        metadata_change = build_decision_support(metadata_report, metadata_baseline)["changes"]["highlights"][0]
        self.assertEqual(metadata_change["label"], "Application metadata permissions weakened")
        self.assertEqual(metadata_change["priority"], "high")

        trusted_path = application("a" * 64)
        trusted_path["severity"] = "Informational"
        trusted_path["status"] = "Pass"
        trusted_path["evidence"].append({
            "kind": "bundle_path_integrity", "source": "/Applications/Example.app",
            "value": {"executable_resolves_within_bundle": True},
        })
        escaped_path = application("a" * 64)
        escaped_path["evidence"].append({
            "kind": "bundle_path_integrity", "source": "/Applications/Example.app",
            "value": {"executable_resolves_within_bundle": False},
        })
        path_baseline = {**baseline, "findings": [trusted_path]}
        path_report = {**current, "findings": [escaped_path]}
        path_change = build_decision_support(path_report, path_baseline)["changes"]["highlights"][0]
        self.assertEqual(path_change["label"], "Bundle path integrity regressed")
        self.assertEqual(path_change["priority"], "high")

        previously_unclassified = application("a" * 64)
        previously_unclassified["severity"] = "Informational"
        previously_unclassified["status"] = "Pass"
        previously_unclassified["evidence"][2]["value"]["permissions"] = "0777"
        newly_classified = application("a" * 64)
        newly_classified["evidence"][2]["value"]["permissions"] = "0777"
        classification_baseline = {**baseline, "findings": [previously_unclassified]}
        classification_report = {
            **current,
            "metadata": {**current["metadata"], "tool_version": "1.3.2"},
            "findings": [newly_classified],
        }
        classification_change = build_decision_support(classification_report, classification_baseline)["changes"]["highlights"][0]
        self.assertEqual(classification_change["label"], "New trust concern detected")
        self.assertEqual(classification_change["priority"], "high")
        self.assertIn("writable by every local user", classification_change["detail"])

        replaced_signer = application("a" * 64)
        replaced_signer["evidence"][1]["value"]["team_identifier"] = "NEWTEAM456"
        signer_report = {**current, "findings": [replaced_signer]}
        signer_change = build_decision_support(signer_report, baseline)["changes"]["highlights"][0]
        self.assertEqual(signer_change["label"], "Signing identity changed")
        self.assertEqual(signer_change["priority"], "high")

        replaced_bundle = application("a" * 64)
        replaced_bundle["evidence"][0]["value"]["bundle_identifier"] = "test.example.replaced"
        bundle_report = {**current, "findings": [replaced_bundle]}
        bundle_change = build_decision_support(bundle_report, baseline)["changes"]["highlights"][0]
        self.assertEqual(bundle_change["label"], "Bundle identity changed")
        self.assertEqual(bundle_change["priority"], "high")

        regressed = application("a" * 64)
        regressed["evidence"][1]["value"]["valid"] = False
        regressed["evidence"][3]["value"]["accepted"] = False
        regression_report = {**current, "findings": [regressed]}
        regression = build_decision_support(regression_report, baseline)["changes"]["highlights"][0]
        self.assertEqual(regression["label"], "Trust check regressed")
        self.assertEqual(regression["priority"], "high")

        removed_report = {**current, "findings": [process, network, persistence]}
        removed_changes = build_decision_support(removed_report, baseline)["changes"]
        removed_change = next(item for item in removed_changes["highlights"] if item["kind"] == "removed-application")
        self.assertEqual(removed_changes["counts"]["removed_applications"], 1)
        self.assertEqual(removed_change["label"], "Application no longer present")
        self.assertEqual(removed_change["title"], "Example")
        self.assertEqual(removed_change["priority"], "review")
        self.assertIn("not found in the current application inventory", removed_change["detail"])
        self.assertIn("intentionally removed", removed_change["next_action"])
        self.assertEqual(removed_change["finding_id"], "")

        new_unverified = application("a" * 64)
        new_unverified["finding_id"] = "APP-TRUST-NEW"
        new_unverified["severity"] = "Informational"
        new_unverified["status"] = "Unknown"
        new_report = {**current, "findings": [*current["findings"], new_unverified]}
        new_change = next(
            item for item in build_decision_support(new_report, current)["changes"]["application_changes"]
            if item["finding_id"] == "APP-TRUST-NEW"
        )
        self.assertEqual(new_change["label"], "New application")
        self.assertEqual(new_change["priority"], "review")
        self.assertIn("resolve its current trust result", new_change["next_action"])

    def test_application_change_context_is_complete_prioritized_and_os_aware(self):
        def application(index, sha256, *, valid=True, gatekeeper=True, system=False):
            name = f"App {index:02d}"
            path = f"/Applications/{name}.app"
            return {
                "finding_id": f"APP-TRUST-{index:02d}", "category": "Application Trust",
                "title": f"Application trust: {name}", "severity": "Informational", "status": "Pass",
                "description": "Checks application trust.", "observed_result": "Checks completed.",
                "evidence": [
                    {"kind": "application_bundle", "source": path, "value": {
                        "name": name, "version": "1.0",
                        "bundle_identifier": f"com.apple.app{index}" if system else f"test.app{index}",
                        "executable": f"{path}/Contents/MacOS/{name}",
                    }},
                    {"kind": "code_signature", "source": path, "value": {
                        "valid": valid, "team_identifier": None if system else "TEAM123",
                        "signature_type": "Apple System" if system else "Developer ID",
                    }},
                    {"kind": "executable_integrity", "source": f"{path}/Contents/MacOS/{name}", "value": {
                        "sha256": sha256,
                    }},
                    {"kind": "gatekeeper_assessment", "source": path, "value": {
                        "accepted": gatekeeper, "notarized": gatekeeper,
                    }},
                ],
            }

        baseline_apps = [application(index, "a" * 64, system=index == 0) for index in range(60)]
        current_apps = [application(index, "b" * 64, system=index == 0) for index in range(60)]
        current_apps[-1]["evidence"][1]["value"]["valid"] = False
        current_apps[-1]["evidence"][3]["value"]["accepted"] = False
        baseline = {
            "metadata": {
                "scan_id": "before-update", "collectors": ["application-trust"],
                "completed_at": "2026-01-01T00:00:00+00:00", "platform": "macOS-26.5.2-arm64-arm-64bit",
            },
            "summary": {}, "findings": baseline_apps,
        }
        current = {
            "metadata": {
                "scan_id": "after-update", "collectors": ["application-trust"],
                "completed_at": "2026-01-02T00:00:00+00:00", "platform": "macOS-26.6.2-arm64-arm-64bit",
            },
            "summary": {}, "findings": current_apps,
        }

        result = build_decision_support(current, baseline)
        changes = result["changes"]
        self.assertEqual(changes["counts"]["changed_applications"], 60)
        self.assertEqual(len(changes["application_changes"]), 60)
        self.assertEqual(changes["highlights"][0]["finding_id"], "APP-TRUST-59")
        self.assertEqual(changes["highlights"][0]["label"], "Trust check regressed")
        system_change = next(item for item in changes["application_changes"] if item["finding_id"] == "APP-TRUST-00")
        self.assertEqual(system_change["label"], "Possible macOS update change")
        self.assertEqual(system_change["priority"], "context")
        self.assertIn("macOS changed from 26.5.2 to 26.6.2", system_change["detail"])
        self.assertIn("macOS version", {item["label"] for item in system_change["changed_fields"]})
        self.assertNotIn("Info.plist permissions", {item["label"] for item in system_change["changed_fields"]})
        review_changes = {
            item["finding_id"]: item["change"] for item in result["application_review"]["applications"]
        }
        self.assertEqual(len(review_changes), 60)
        self.assertEqual(review_changes["APP-TRUST-59"]["label"], "Trust check regressed")

    def test_application_review_queue_prioritizes_without_malware_verdicts(self):
        def application(name, severity, status, signature, gatekeeper, sha256, permissions="0755"):
            path = f"/Applications/{name}.app"
            return {
                "finding_id": f"APP-TRUST-{name.upper()}", "category": "Application Trust",
                "title": f"Application trust: {name}", "severity": severity, "status": status,
                "description": "Checks application trust.", "observed_result": f"{name} trust result.",
                "evidence": [
                    {"kind": "application_bundle", "source": path, "value": {"name": name, "version": "1.0", "executable": f"{path}/Contents/MacOS/{name}"}},
                    {"kind": "code_signature", "source": path, "value": {"valid": signature, "team_identifier": "TEAM123" if signature else None, "signature_type": "Developer ID" if signature else None, "hardened_runtime": signature}},
                    {"kind": "executable_integrity", "source": f"{path}/Contents/MacOS/{name}", "value": {"sha256": sha256, "permissions": permissions}},
                    {"kind": "gatekeeper_assessment", "source": path, "value": {"accepted": gatekeeper, "notarized": gatekeeper}},
                    {"kind": "bundle_path_integrity", "source": path, "value": {"executable_resolves_within_bundle": True}},
                    {"kind": "code_entitlements", "source": path, "value": {"sensitive": []}},
                ],
            }

        report = {
            "metadata": {"scan_id": "application-queue", "collectors": ["application-trust"]},
            "summary": {},
            "findings": [
                application("Normal", "Informational", "Pass", True, True, "a" * 64),
                application("Broken", "Medium", "Fail", False, False, "b" * 64, "0777"),
                application("Context", "Low", "Review", True, True, "c" * 64),
                application("Unknown", "Informational", "Unknown", None, None, None),
            ],
        }
        queue = build_decision_support(report)["application_review"]
        self.assertEqual(queue["total"], 4)
        self.assertEqual(queue["counts"]["review_first"], 1)
        self.assertEqual(queue["counts"]["needs_context"], 1)
        self.assertEqual(queue["counts"]["unable_to_verify"], 1)
        self.assertEqual(queue["counts"]["checks_passed"], 1)
        self.assertEqual(queue["applications"][0]["name"], "Broken")
        self.assertFalse(queue["applications"][0]["activity"]["coverage"]["available"])
        self.assertIn("code signature did not validate", " ".join(queue["applications"][0]["signals"]).lower())
        self.assertIn("writable by every local user", " ".join(queue["applications"][0]["signals"]).lower())
        self.assertIn("does not label an application as malware or safe", queue["conclusion"])
        normal_item = next(item for item in queue["applications"] if item["name"] == "Normal")
        self.assertIn("absence is not a risk signal", normal_item["provenance"]["summary"])
        broken = report["findings"][1]
        reviewed = build_decision_support(report, investigations={
            broken["finding_id"]: {
                "status": "Expected", "current": True, "note": "Approved local application.",
                "fingerprint": finding_fingerprint(broken),
            },
        })["application_review"]
        reviewed_item = next(item for item in reviewed["applications"] if item["name"] == "Broken")
        self.assertEqual(reviewed_item["group"], "reviewed")
        self.assertEqual(reviewed["counts"]["review_first"], 0)
        self.assertEqual(reviewed["counts"]["reviewed"], 1)

    def test_decision_support_and_summary_export_use_comparable_baseline(self):
        baseline = {
            "metadata": {"scan_id": "decision-old", "collectors": ["security"], "completed_at": "2026-01-01T00:00:00+00:00"},
            "summary": {"overall_score": 100}, "findings": [],
        }
        current = {
            "metadata": {"scan_id": "decision-new", "hostname": "fixture", "collectors": ["security"], "completed_at": "2026-01-02T00:00:00+00:00"},
            "summary": {"overall_score": 80}, "findings": [{
                "finding_id": "SECURITY-TEST", "category": "System Hardening", "title": "Security control",
                "severity": "High", "status": "Fail", "description": "Control check", "observed_result": "Disabled", "evidence": [],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            for report in (baseline, current):
                scan_id = report["metadata"]["scan_id"]
                (state.output / f"macos-inspector-{scan_id}.json").write_text(json.dumps(report), encoding="utf-8")
            server = DashboardServer(("127.0.0.1", 0), state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host = f"127.0.0.1:{server.server_port}"
                status, _, body = dashboard_request(server, "GET", "/api/decision-support/decision-new", host)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["changes"]["baseline_scan_id"], "decision-old")
                status, _, _ = dashboard_request(server, "POST", "/api/investigation-summary", host, payload={"scan_id": "decision-new"}, write_header=False)
                self.assertEqual(status, 403)
                status, _, body = dashboard_request(server, "POST", "/api/investigation-summary", host, payload={"scan_id": "decision-new"})
                self.assertEqual(status, 201)
                exported = json.loads(body)
                self.assertTrue((state.output / exported["filename"]).is_file())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_hash_reputation_is_explicit_hash_only_and_provider_controlled(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"MACOS_INSPECTOR_DATA_DIR": directory}, clear=False):
            SettingsStore().update({"providers": {"virustotal": {"enabled": True, "api_key": "test-key"}}})
            with patch("macos_inspector.core.intelligence.lookup_virustotal_hash", return_value={"status": "not_found", "provider": "VirusTotal"}) as lookup:
                result = lookup_hash_reputation("a" * 64)
            lookup.assert_called_once_with("a" * 64)
            self.assertEqual(result["sha256_transmitted"], "a" * 64)
            self.assertFalse(result["automatic_submission"])
            self.assertFalse(result["file_uploaded"])
            with self.assertRaises(ValueError):
                lookup_hash_reputation("not-a-hash")

    def test_hash_reputation_provider_requests_send_only_the_digest(self):
        class Response:
            def __init__(self, url, payload):
                self.url = url
                self.payload = json.dumps(payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def geturl(self):
                return self.url

            def read(self, _limit):
                return self.payload

        vt_digest, bazaar_digest = "1" * 64, "2" * 64
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"MACOS_INSPECTOR_DATA_DIR": directory}, clear=False):
            SettingsStore().update({"providers": {
                "virustotal": {"enabled": True, "api_key": "vt-key"},
                "malwarebazaar": {"enabled": True, "auth_key": "bazaar-key"},
            }})
            vt_payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}, "type_description": "Mach-O"}}}
            with patch("macos_inspector.core.intelligence.urlopen", return_value=Response(
                f"https://www.virustotal.com/api/v3/files/{vt_digest}", vt_payload,
            )) as request_call:
                result = lookup_virustotal_hash(vt_digest)
            request = request_call.call_args.args[0]
            self.assertEqual(request.full_url, f"https://www.virustotal.com/api/v3/files/{vt_digest}")
            self.assertIsNone(request.data)
            self.assertEqual(result["analysis_stats"]["malicious"], 1)
            self.assertTrue(result["provenance"]["host_data_transmitted"])
            self.assertEqual(result["provenance"]["transmitted_fields"], ["sha256"])
            with patch("macos_inspector.core.intelligence.urlopen", side_effect=AssertionError("cache miss")):
                cached = lookup_virustotal_hash(vt_digest)
            self.assertEqual(cached["provenance"]["cache_status"], "cache")

            bazaar_payload = {"query_status": "ok", "data": [{"signature": "Fixture", "file_type": "mach-o"}]}
            with patch("macos_inspector.core.intelligence.urlopen", return_value=Response(
                "https://mb-api.abuse.ch/api/v1/", bazaar_payload,
            )) as request_call:
                result = lookup_malwarebazaar_hash(bazaar_digest)
            request = request_call.call_args.args[0]
            self.assertEqual(request.full_url, "https://mb-api.abuse.ch/api/v1/")
            self.assertEqual(request.data.decode(), f"query=get_info&hash={bazaar_digest}")
            self.assertNotIn("path", request.data.decode())
            self.assertEqual(result["signature"], "Fixture")

    def test_change_analysis_detects_aggregate_startup_item_changes(self):
        def report(scan_id, entries):
            return {
                "metadata": {"scan_id": scan_id, "collectors": ["background-items"], "completed_at": f"2026-01-0{1 if scan_id == 'old' else 2}T00:00:00+00:00"},
                "summary": {},
                "findings": [{
                    "finding_id": "BACKGROUND-SYSTEM", "category": "Background Items",
                    "title": "ServiceManagement disabled map: system", "severity": "Medium", "status": "Review",
                    "description": "Service state", "observed_result": "Service state collected.",
                    "evidence": [{"kind": "launchctl_services", "source": "launchctl", "value": {"scope": "system", "entries": entries}}],
                }],
            }

        baseline = report("old", [{"label": "com.example.old", "state": "disabled"}])
        current = report("new", [
            {"label": "com.example.old", "state": "enabled"},
            {"label": "com.example.new", "state": "enabled"},
        ])
        changes = build_decision_support(current, baseline)["changes"]
        self.assertEqual(changes["counts"]["new_startup_items"], 1)
        self.assertEqual(changes["counts"]["changed_startup_items"], 1)
        self.assertIn("New startup item", {item["label"] for item in changes["highlights"]})
        self.assertIn("Startup item changed", {item["label"] for item in changes["highlights"]})

    def test_goal_profiles_are_local_and_problem_oriented(self):
        goals = {profile["id"]: profile for profile in SCAN_PROFILES if profile.get("goal")}
        self.assertEqual(set(goals), {"unexpected-app", "remote-access", "browser-problem", "performance"})
        self.assertTrue(all(set(profile["collectors"]) <= set(LOCAL_COLLECTORS) for profile in goals.values()))

    def test_intelligence_cache_uses_validated_last_known_good_data(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"MACOS_INSPECTOR_DATA_DIR": directory}, clear=False):
            validator = lambda payload: payload if isinstance(payload, dict) and payload.get("ok") is True else (_ for _ in ()).throw(ValueError("invalid"))
            with patch("macos_inspector.core.intelligence._request_bytes", return_value=b'{"ok":true,"value":7}'):
                fresh = fetch_cached_json("fixture", "Fixture", "https://example.test/feed", {"example.test"}, validator, force=True, cache_hours=1)
            self.assertEqual(fresh.cache_status, "refreshed")
            with patch("macos_inspector.core.intelligence._request_bytes", side_effect=OSError("offline")):
                fallback = fetch_cached_json("fixture", "Fixture", "https://example.test/feed", {"example.test"}, validator, force=True, cache_hours=1)
            self.assertEqual(fallback.payload["value"], 7)
            self.assertEqual(fallback.cache_status, "stale-fallback")
            self.assertEqual((Path(directory) / "osint-cache" / "fixture.json").stat().st_mode & 0o777, 0o600)

    def test_dashboard_generates_local_signing_identity_without_exposing_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            result = state.generate_signing_key()
            self.assertIn(result["algorithm"], {"HMAC-SHA256", "Ed25519"})
            public = state.settings.public()
            self.assertTrue(public["signing"]["key_configured"])
            self.assertNotIn("key_path", public["signing"])
            key_path = Path(state.settings.load()["signing"]["key_path"])
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(RuntimeError, "already configured"):
                state.generate_signing_key()
            self.assertTrue(state.generate_signing_key(replace=True)["configured"])

    def test_dashboard_source_opened_as_file_has_a_styled_launcher(self):
        webui = Path(__file__).parents[1] / "src" / "macos_inspector" / "webui"
        index = (webui / "index.html").read_text(encoding="utf-8")
        script = (webui / "app.js").read_text(encoding="utf-8")
        self.assertIn('href="styles.css"', index)
        self.assertIn('src="app.js"', index)
        self.assertNotIn('href="/styles.css"', index)
        self.assertNotIn('src="/app.js"', index)
        self.assertIn('id="local-launcher-help"', index)
        self.assertIn('id="inspect-application-activity"', index)
        self.assertIn("['application-trust', 'live-triage', 'persistence']", script)
        self.assertIn("window.location.protocol === 'file:'", script)
        self.assertNotIn('id="language-select"', index)
        self.assertNotIn('value="ro"', index)
        self.assertNotRegex(index + script, r"[\u0103\u00e2\u00ee\u0219\u021b\u0102\u00c2\u00ce\u0218\u021a]")
        self.assertNotRegex(index + script, r"[\u2013\u2014\u2018\u2019\u201c\u201d]")

    def test_vulnerability_exposure_correlates_without_claiming_compromise(self):
        payload = json.loads((Path(__file__).parent / "fixtures" / "osint" / "cisa_kev.json").read_text())
        self.assertEqual(len(macos_kev_entries(payload)), 2)
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*", "versionEndExcluding": "26.6"
        }]}]}]}
        self.assertEqual(nvd_macos_range(cve, "26.5.2")[0], True)
        self.assertEqual(nvd_macos_range(cve, "26.6")[0], False)
        self.assertEqual(parse_sw_vers("ProductName:\tmacOS\nProductVersion:\t26.5.2\nBuildVersion:\t25F84")["build_version"], "25F84")

        def resource(value, provider):
            return IntelligenceResource(value, provider, "https://example.test", "2026-08-09T00:00:00+00:00", "a" * 64, "fixture", False)

        epss = {"data": [{"cve": "CVE-2025-54321", "epss": "0.91", "percentile": "0.99"}]}
        nvd = {"vulnerabilities": [{"cve": {"id": "CVE-2025-54321", **cve, "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]}
        apple = {"releases": [{"name": "macOS Tahoe 26.6", "version": "26.6"}]}

        class FakeRunner:
            def run(self, argv):
                return CommandResult(tuple(argv), 0, "ProductName:\tmacOS\nProductVersion:\t26.5.2\nBuildVersion:\t25F84", "")

        findings = {item.finding_id: item for item in VulnerabilityExposureCollector(
            FakeRunner(), lambda: resource(payload, "CISA"), lambda ids: resource(epss, "FIRST EPSS"),
            lambda ids: resource(nvd, "NIST NVD"), lambda: resource(apple, "Apple"), settings=SettingsStore.DEFAULTS,
        ).collect()}
        self.assertEqual(findings["EXPOSURE-MACOS-VERSION"].status, "Review")
        correlation = findings["EXPOSURE-APPLE-KEV-CORRELATION"]
        self.assertEqual(correlation.status, "Review")
        self.assertIn("not proof", correlation.observed_result)
        self.assertFalse(correlation.evidence[0].value["host_vulnerability_inferred"])

    def test_intelligence_validators_and_apple_release_parser(self):
        epss = validate_epss({"data": [{"cve": "CVE-2026-12345", "epss": "0.5", "percentile": "0.8"}]})
        self.assertEqual(epss["data"][0]["cve"], "CVE-2026-12345")
        nvd = validate_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2026-12345"}}]})
        self.assertEqual(nvd["vulnerabilities"][0]["cve"]["id"], "CVE-2026-12345")
        releases = parse_apple_security_releases("<html><body><h2>macOS Tahoe 26.6</h2><p>macOS Sequoia 15.7.8</p></body></html>")
        self.assertEqual([item["version"] for item in releases["releases"]], ["26.6", "15.7.8"])

    def test_live_triage_parsers_and_correlation(self):
        processes = parse_processes(
            "1 0 0 root Ss /sbin/launchd\n"
            "42 1 501 alice S /private/tmp/agent\n"
            "77 1 501 alice Z /Applications/Old.app/Contents/MacOS/Old\n"
            "99 42 501 alice S /Applications/Safe.app/Contents/MacOS/Safe"
        )
        self.assertEqual(len(processes), 4)
        self.assertEqual(processes[1]["uid"], 501)
        suspicious = suspicious_processes(processes)
        self.assertEqual(suspicious[0]["pid"], 42)
        zombie = next(item for item in suspicious if item["pid"] == 77)
        self.assertTrue(zombie["zombie"])
        self.assertEqual(zombie["priority"], "medium")
        self.assertIn("zombie", zombie["reasons"][0])
        sockets = parse_lsof_fields("p42\ncagent\nn*:8080\nTST=LISTEN\nn1.2.3.4:443\nTST=ESTABLISHED\n")
        self.assertEqual([item["state"] for item in sockets], ["LISTEN", "ESTABLISHED"])

        class FakeRunner:
            def run(self, argv):
                if argv[0] == "ps":
                    if "etime" in argv[2]:
                        return CommandResult(tuple(argv), 0, "1 01:00 /sbin/launchd\n42 00:30 /private/tmp/agent", "")
                    return CommandResult(tuple(argv), 0, "1 0 0 root Ss /sbin/launchd\n42 1 501 alice S /private/tmp/agent", "")
                return CommandResult(tuple(argv), 0, "p42\ncagent\nn*:8080\nTST=LISTEN", "")

        findings = {item.finding_id: item for item in LiveTriageCollector(FakeRunner()).collect()}
        self.assertEqual(findings["LIVE-PROCESS-TREE"].status, "Review")
        self.assertEqual(findings["LIVE-PROCESS-TREE"].severity, Severity.MEDIUM)
        process_snapshot = findings["LIVE-PROCESS-TREE"].evidence[0].value
        self.assertEqual(len(process_snapshot["running_processes"]), 2)
        self.assertNotIn("command_line", process_snapshot["running_processes"][0])
        self.assertEqual(findings["LIVE-NETWORK-PROCESSES"].severity, Severity.HIGH)

    def test_process_response_requires_reported_current_user_identity_and_logs_action(self):
        candidate = {
            "pid": 4242, "ppid": 12, "uid": 501, "user": "alice", "stat": "S", "zombie": False,
            "executable": "/private/tmp/agent", "priority": "medium", "reasons": ["fixture"],
        }
        report = {
            "metadata": {"scan_id": "response-scan", "collectors": ["live-triage"]},
            "summary": {"overall_score": 80},
            "findings": [{
                "finding_id": "LIVE-PROCESS-TREE", "status": "Review",
                "evidence": [{"kind": "process_snapshot", "value": {"review_candidates": [candidate]}}],
            }],
        }

        class ProcessRunner:
            def __init__(self, executable="/private/tmp/agent", stat="S"):
                self.executable = executable
                self.stat = stat

            def run(self, argv):
                return CommandResult(tuple(argv), 0, f"4242 12 501 alice {self.stat} {self.executable}", "")

        signals = []
        result = terminate_reported_process(
            report, 4242, "terminate", runner=ProcessRunner(), kill_process=lambda pid, value: signals.append((pid, value)),
            effective_uid=501, protected_pids={1, 100, 101},
        )
        self.assertEqual(signals, [(4242, signal.SIGTERM)])
        self.assertEqual(result["status"], "signal_sent")
        self.assertEqual(review_process_candidates(report), [candidate])

        with self.assertRaises(PermissionError):
            terminate_reported_process(report, 9999, "terminate", runner=ProcessRunner(), effective_uid=501, protected_pids={1})
        with self.assertRaisesRegex(PermissionError, "protected"):
            terminate_reported_process(report, 4242, "terminate", runner=ProcessRunner(), effective_uid=501, protected_pids={1, 4242})
        cross_user_report = json.loads(json.dumps(report))
        cross_user_report["findings"][0]["evidence"][0]["value"]["review_candidates"][0]["uid"] = 502
        with self.assertRaisesRegex(PermissionError, "dashboard user"):
            terminate_reported_process(cross_user_report, 4242, "terminate", runner=ProcessRunner(), effective_uid=501, protected_pids={1})
        with self.assertRaisesRegex(RuntimeError, "different process"):
            terminate_reported_process(report, 4242, "kill", runner=ProcessRunner("/tmp/reused"), effective_uid=501, protected_pids={1})
        with self.assertRaisesRegex(PermissionError, "runs as root"):
            terminate_reported_process(report, 4242, "terminate", runner=ProcessRunner(), effective_uid=0, protected_pids={1})
        zombie_report = json.loads(json.dumps(report))
        zombie_report["findings"][0]["evidence"][0]["value"]["review_candidates"][0].update({"stat": "Z", "zombie": True})
        with self.assertRaisesRegex(RuntimeError, "zombie"):
            terminate_reported_process(zombie_report, 4242, "kill", runner=ProcessRunner("/private/tmp/agent", "Z"), effective_uid=501, protected_pids={1})

        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            report_path = state.output / "macos-inspector-response-scan.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            state_result = state.terminate_process(
                "response-scan", 4242, "kill", runner=ProcessRunner(), kill_process=lambda pid, value: signals.append((pid, value)),
                effective_uid=501, protected_pids={1},
            )
            self.assertEqual(state_result["signal"], "SIGKILL")
            self.assertTrue(state_result["audit_logged"])
            action_log = state.data_root / "response-actions.jsonl"
            self.assertEqual(action_log.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(action_log.read_text())["scan_id"], "response-scan")

    def test_process_response_endpoint_requires_protected_post(self):
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            server = DashboardServer(("127.0.0.1", 0), state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_port
            response = {"pid": 4242, "signal": "SIGTERM", "status": "signal_sent", "timestamp": "2026-01-01T00:00:00+00:00"}
            try:
                with patch.object(state, "terminate_process", return_value=response) as terminate:
                    status, _, _ = dashboard_request(
                        server, "POST", "/api/processes/terminate", f"127.0.0.1:{port}",
                        payload={"scan_id": "scan", "pid": 4242, "mode": "terminate"}, write_header=False,
                    )
                    self.assertEqual(status, 403)
                    terminate.assert_not_called()

                    status, _, body = dashboard_request(
                        server, "POST", "/api/processes/terminate", f"127.0.0.1:{port}",
                        payload={"scan_id": "scan", "pid": 4242, "mode": "terminate"},
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body)["signal"], "SIGTERM")
                    terminate.assert_called_once_with("scan", 4242, "terminate")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_live_triage_prioritizes_exposure_and_suppresses_loopback_false_positive(self):
        processes = merge_process_context(
            parse_processes(
                "55709 1 alice /Users/alice/.cache/runtime/python\n"
                "38335 1 alice /opt/homebrew/bin/python3\n"
            ),
            parse_process_context(
                "55709 00:25:20 /Users/alice/.cache/runtime/python -m inspector --web\n"
                "38335 10-21:08:27 /opt/homebrew/bin/python3 -m http.server 4477\n"
            ),
        )
        suspicious = suspicious_processes(processes)
        sockets = deduplicate_connections(parse_lsof_fields(
            "p55709\ncpython\nn127.0.0.1:8765\nTST=LISTEN\n"
            "p38335\ncPython\nn*:4477\nTST=LISTEN\nn*:4477\nTST=LISTEN\n"
        ))
        self.assertEqual(len(sockets), 2)
        self.assertEqual(sockets[1]["socket_count"], 2)
        high, medium, local_only = network_risk_candidates(
            sockets,
            processes,
            suspicious,
            {38335: "/private/tmp/site-preview", 55709: "/Users/alice/project"},
        )
        self.assertEqual([item["pid"] for item in high], [38335])
        self.assertFalse(medium)
        self.assertEqual([item["pid"] for item in local_only], [55709])
        self.assertEqual(next(item for item in suspicious if item["pid"] == 55709)["priority"], "low")
        self.assertTrue(any("restricted to the local host" in reason for reason in local_only[0]["reasons"]))
        self.assertEqual(socket_exposure("127.0.0.1:8765", "LISTEN"), "loopback")
        self.assertEqual(socket_exposure("[::1]:8765", "LISTEN"), "loopback")
        self.assertEqual(socket_exposure("*:4477", "LISTEN"), "wildcard")
        self.assertEqual(parse_cwd_fields("p38335\nfcwd\nn/private/tmp/site-preview\n"), {38335: "/private/tmp/site-preview"})
        command, redacted = sanitize_command_line(
            "python service.py --token top-secret --api-key=second OPENAI_API_KEY=third --client-secret fourth"
        )
        self.assertTrue(redacted)
        self.assertNotIn("top-secret", command)
        self.assertNotIn("second", command)
        self.assertNotIn("third", command)
        self.assertNotIn("fourth", command)

    def test_managed_yara_rules_are_bounded_and_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "valid.yar").write_text('rule Example { strings: $a = "fixture" condition: $a }')
            (root / "invalid.yara").write_text("not a rule")
            rules, errors = discover_yara_rules(root)
            self.assertEqual([path.name for path in rules], ["valid.yar"])
            self.assertTrue(errors)
            self.assertEqual(parse_yara_matches("Example /tmp/file\n"), [{"rule": "Example", "path": "/tmp/file"}])

    def test_free_osint_feed_is_validated_and_does_not_infer_host_exposure(self):
        payload = json.loads((Path(__file__).parent / "fixtures" / "osint" / "cisa_kev.json").read_text())
        validated = validate_cisa_kev(payload)
        entries = apple_kev_entries(validated)
        self.assertEqual([entry["cve_id"] for entry in entries], ["CVE-2026-12345", "CVE-2025-54321"])
        self.assertNotIn("?", CISA_KEV_FEED)

        findings = {finding.finding_id: finding for finding in OSINTIntelligenceCollector(None, lambda: payload).collect()}
        self.assertEqual(findings["OSINT-CISA-KEV-CATALOG"].status, "Observed")
        self.assertEqual(findings["OSINT-CISA-KEV-APPLE"].status, "Observed")
        self.assertIn("does not establish host exposure", findings["OSINT-CISA-KEV-APPLE"].observed_result)
        evidence = findings["OSINT-CISA-KEV-APPLE"].evidence[0].value
        self.assertFalse(evidence["host_vulnerability_inferred"])
        self.assertFalse(evidence["host_data_transmitted"])

        malformed = dict(payload, count=999)
        with self.assertRaisesRegex(ValueError, "count"):
            validate_cisa_kev(malformed)

    def test_account_inventory_is_sanitized_and_anomalies_are_classified(self):
        fixtures = Path(__file__).parent / "fixtures" / "accounts"
        standard_users = (fixtures / "users_standard.txt").read_text()
        standard_admins = (fixtures / "admin_standard.txt").read_text()
        records = parse_user_records(standard_users)
        self.assertEqual([record.name for record in regular_accounts(records)], ["alice", "analyst"])
        self.assertEqual(parse_group_members(standard_admins), ("alice", "root"))
        self.assertNotIn("password", repr(records).lower())
        self.assertFalse(any(account_anomalies(records, ("alice", "root")).values()))

        anomalous_records = parse_user_records((fixtures / "users_anomalous.txt").read_text())
        anomalous_admins = parse_group_members((fixtures / "admin_anomalous.txt").read_text())
        anomalies = account_anomalies(anomalous_records, anomalous_admins)
        self.assertEqual(anomalies["duplicate_uids"], {"501": ("alice", "alice-copy")})
        self.assertEqual(anomalies["low_uid_interactive"][0]["name"], "hidden-support")
        self.assertEqual(anomalies["low_uid_interactive"][1]["name"], "_concealed")
        self.assertEqual(anomalies["unlisted_administrators"], ("external-admin", "hidden-support"))

        class FakeRunner:
            def run(self, argv):
                command = tuple(argv)
                output = standard_admins if "group" in command else standard_users
                return CommandResult(command, 0, output, "")

        findings = {finding.finding_id: finding for finding in AccountsAccessCollector(FakeRunner()).collect()}
        self.assertEqual(findings["ACCOUNTS-ANOMALIES"].status, "Pass")
        inventory = findings["ACCOUNTS-INVENTORY"].evidence[0].value
        self.assertFalse(inventory["sensitive_fields_retained"])
        self.assertNotIn("password", repr(inventory).lower())

    def test_management_profile_status_fixtures(self):
        fixtures = Path(__file__).parent / "fixtures" / "management_profiles"
        no_profiles = (fixtures / "configuration_none.txt").read_text()
        installed_profiles = (fixtures / "configuration_installed.txt").read_text()
        enrollment_output = (fixtures / "enrollment_managed.txt").read_text()
        self.assertFalse(parse_configuration_profile_status(no_profiles))
        self.assertTrue(parse_configuration_profile_status(installed_profiles))
        enrollment = parse_enrollment_status(enrollment_output)
        self.assertTrue(enrollment.dep_enrolled)
        self.assertTrue(enrollment.mdm_enrolled)

        class FakeRunner:
            def run(self, argv):
                command = tuple(argv)
                output = installed_profiles if command[-1] == "configuration" else enrollment_output
                return CommandResult(command, 0, output, "")

        findings = {finding.finding_id: finding for finding in ManagementProfilesCollector(FakeRunner()).collect()}
        self.assertEqual((findings["MANAGEMENT-CONFIGURATION-PROFILES"].severity, findings["MANAGEMENT-CONFIGURATION-PROFILES"].status), (Severity.LOW, "Review"))
        self.assertEqual((findings["MANAGEMENT-ENROLLMENT"].severity, findings["MANAGEMENT-ENROLLMENT"].status), (Severity.INFORMATIONAL, "Observed"))
        self.assertIn("MDM enrollment=yes", findings["MANAGEMENT-ENROLLMENT"].observed_result)

    def test_proxy_fixtures_are_interpreted_and_sensitive_url_components_are_redacted(self):
        fixtures = Path(__file__).parent / "fixtures" / "network"
        active = parse_proxy_configuration((fixtures / "proxy_active.txt").read_text())
        self.assertEqual(enabled_proxy_types(active), ("HTTP", "HTTPS", "SOCKS", "PAC"))
        self.assertEqual(active["HTTPProxy"], "proxy.example.test")
        self.assertEqual(active["HTTPPort"], 8080)
        self.assertEqual(active["ProxyAutoConfigURLString"], "https://redacted@pac.example.test/config.pac?redacted")
        self.assertEqual(enabled_proxy_types(parse_proxy_configuration((fixtures / "proxy_empty.txt").read_text())), ())

        class FakeRunner:
            def __init__(self, proxy_output):
                self.proxy_output = proxy_output

            def run(self, argv):
                command = tuple(argv)
                if command == ("scutil", "--proxy"):
                    return CommandResult(command, 0, self.proxy_output, "")
                if command[0] == "security":
                    return CommandResult(command, 0, "SHA-1 hash: 0123456789012345678901234567890123456789", "")
                return CommandResult(command, 0, "fixture output", "")

        active_finding = next(finding for finding in NetworkCollector(FakeRunner((fixtures / "proxy_active.txt").read_text())).collect() if finding.finding_id == "NETWORK-PROXY")
        self.assertEqual((active_finding.severity, active_finding.status), (Severity.LOW, "Review"))
        self.assertNotIn("secret", json.dumps(active_finding.to_dict()))
        empty_finding = next(finding for finding in NetworkCollector(FakeRunner((fixtures / "proxy_empty.txt").read_text())).collect() if finding.finding_id == "NETWORK-PROXY")
        self.assertEqual((empty_finding.severity, empty_finding.status), (Severity.INFORMATIONAL, "Pass"))

    def test_security_control_fixtures_distinguish_failure_from_review(self):
        fixtures = Path(__file__).parent / "fixtures" / "security_controls"
        outputs = {
            ("csrutil", "status"): (0, (fixtures / "csrutil_enabled.txt").read_text()),
            ("fdesetup", "status"): (0, (fixtures / "filevault_on.txt").read_text()),
            ("spctl", "--status"): (0, (fixtures / "gatekeeper_enabled.txt").read_text()),
            ("socketfilterfw", "--getglobalstate"): (0, (fixtures / "firewall_enabled.txt").read_text()),
            ("softwareupdate", "--schedule"): (0, (fixtures / "automatic_updates_on.txt").read_text()),
            ("socketfilterfw", "--getstealthmode"): (0, (fixtures / "firewall_stealth_off.txt").read_text()),
            ("system_profiler", "SPSharingDataType", "-json", "-detailLevel", "mini"): (0, '{"SPSharingDataType": []}'),
        }

        class FakeRunner:
            def run(self, argv):
                command = tuple(argv)
                returncode, stdout = outputs[command]
                return CommandResult(command, returncode, stdout, "")

        findings = {finding.finding_id: finding for finding in SecurityControlsCollector(FakeRunner()).collect()}
        self.assertEqual((findings["CONTROL-AUTOMATIC-UPDATES"].severity, findings["CONTROL-AUTOMATIC-UPDATES"].status), (Severity.INFORMATIONAL, "Pass"))
        self.assertEqual((findings["CONTROL-FIREWALL-STEALTH"].severity, findings["CONTROL-FIREWALL-STEALTH"].status), (Severity.LOW, "Review"))
        self.assertEqual(findings["CONTROL-REMOTELOGIN"].status, "Pass")

        outputs[("softwareupdate", "--schedule")] = (0, "Automatic checking for updates is turned off")
        disabled = {finding.finding_id: finding for finding in SecurityControlsCollector(FakeRunner()).collect()}
        self.assertEqual((disabled["CONTROL-AUTOMATIC-UPDATES"].severity, disabled["CONTROL-AUTOMATIC-UPDATES"].status), (Severity.MEDIUM, "Fail"))

    def test_dashboard_scan_profiles_keep_online_osint_explicit(self):
        profile_ids = [profile["id"] for profile in SCAN_PROFILES]
        self.assertEqual(len(profile_ids), len(set(profile_ids)))
        self.assertEqual(sum(bool(profile["default"]) for profile in SCAN_PROFILES), 1)
        for profile in SCAN_PROFILES:
            self.assertTrue(profile["collectors"])
            self.assertEqual(len(profile["collectors"]), len(set(profile["collectors"])))
            self.assertFalse(set(profile["collectors"]) - set(COLLECTORS))
        full = next(profile for profile in SCAN_PROFILES if profile["id"] == "full")
        local_collectors = {identifier for identifier, collector in COLLECTORS.items() if not collector.external_network}
        self.assertEqual(set(full["collectors"]), local_collectors)
        self.assertNotIn("osint-intelligence", full["collectors"])
        self.assertNotIn("vulnerability-exposure", full["collectors"])
        osint = next(profile for profile in SCAN_PROFILES if profile["id"] == "online-osint")
        self.assertEqual(osint["collectors"], ("osint-intelligence", "vulnerability-exposure"))
        self.assertEqual(tuple(cli_parser().parse_args([]).collectors.split(",")), LOCAL_COLLECTORS)
        self.assertNotIn("osint-intelligence", cli_parser().parse_args([]).collectors)
        quick = next(profile for profile in SCAN_PROFILES if profile["id"] == "quick")
        self.assertNotIn("application-trust", quick["collectors"])

    def test_application_trust_macOS_command_fixtures(self):
        fixtures = Path(__file__).parent / "fixtures" / "application_trust"
        signature = parse_codesign_details((fixtures / "codesign_developer_id.txt").read_text())
        gatekeeper = parse_gatekeeper_details((fixtures / "spctl_notarized.txt").read_text())
        entitlements, error = parse_entitlements((fixtures / "entitlements_abstract.txt").read_text())

        self.assertEqual(signature.identifier, "com.example.Acme")
        self.assertEqual(signature.team_identifier, "ABC1234567")
        self.assertEqual(signature.signature_type, "Developer ID")
        self.assertTrue(signature.hardened_runtime)
        self.assertTrue(gatekeeper.notarized)
        self.assertEqual(gatekeeper.source, "Notarized Developer ID")
        self.assertIsNone(error)
        self.assertTrue(entitlements["com.apple.security.app-sandbox"])
        self.assertEqual(entitlements["com.apple.security.application-groups"], ["ABC1234567.com.example.shared"])

    def test_application_integrity_gaps_and_risky_permissions_change_trust(self):
        unavailable = assess_file_integrity(FileIntegrityDetails(error="PermissionError: denied"))
        self.assertEqual(unavailable[0][:2], (Severity.INFORMATIONAL, "Unknown"))
        self.assertEqual(
            merge_trust_assessments((Severity.INFORMATIONAL, "Pass", "Signature accepted."), unavailable)[:2],
            (Severity.INFORMATIONAL, "Unknown"),
        )

        group_writable = assess_file_integrity(FileIntegrityDetails(sha256="a" * 64, permissions="0775"))
        self.assertEqual(group_writable[0][:2], (Severity.MEDIUM, "Review"))
        self.assertIn("group-writable", group_writable[0][2])

        world_writable = assess_file_integrity(FileIntegrityDetails(
            sha256="b" * 64, permissions="0777", is_symlink=True, changed_during_read=True,
        ))
        merged = merge_trust_assessments(
            (Severity.LOW, "Review", "Ad-hoc signature."),
            world_writable,
        )
        self.assertEqual(merged[:2], (Severity.HIGH, "Review"))
        self.assertIn("changed while", merged[2])
        self.assertIn("world-writable", merged[2])
        self.assertIn("symbolic link", merged[2])

    def test_application_bundle_path_escape_and_metadata_permissions_are_reviewed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "Escaped.app"
            macos = bundle / "Contents" / "MacOS"
            macos.mkdir(parents=True)
            external = root / "outside-executable"
            external.write_bytes(b"outside bundle")
            external.chmod(0o755)
            executable = macos / "Escaped"
            executable.symlink_to(external)

            paths = inspect_bundle_paths(bundle, executable)
            self.assertFalse(paths.executable_resolves_within_bundle)
            path_assessments = assess_bundle_paths(paths)
            self.assertEqual(path_assessments[0][:2], (Severity.HIGH, "Review"))
            self.assertIn("outside", path_assessments[0][2])

        self.assertFalse(assess_bundle_paths(BundlePathDetails(
            bundle_is_symlink=True,
            resolved_bundle="/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app",
            bundle_symlink_is_system_managed=True,
        )))

        metadata_assessments = assess_metadata_integrity(FileIntegrityDetails(
            sha256="c" * 64, permissions="0666",
        ))
        self.assertEqual(metadata_assessments[0][:2], (Severity.HIGH, "Review"))
        self.assertIn("world-writable", metadata_assessments[0][2])

    def test_pdf_report_is_available_without_optional_dependencies(self):
        capabilities = report_format_capabilities()
        self.assertTrue(capabilities["pdf"]["available"])
        self.assertTrue(capabilities["html"]["available"])
        require_report_formats(["html", "pdf"])
        metadata = ScanMetadata("0.1", "portable-pdf", "start", "end", "host", "platform", "user", ("test",))
        result = ScanResult(metadata, (finding(),), 82, {"Persistence": 82})
        with tempfile.TemporaryDirectory() as directory, patch(
            "macos_inspector.reporters.pdf_reporter.importlib.util.find_spec", return_value=None,
        ):
            path = Path(directory) / "report.pdf"
            REPORTERS["pdf"](result, path)
            self.assertTrue(path.read_bytes().startswith(b"%PDF-1.4"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_readiness_is_bounded_and_reports_access_without_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "reports"
            output.mkdir()
            tcc = root / "TCC.db"
            browser_history = root / "History"
            with closing(sqlite3.connect(tcc)) as connection:
                connection.execute("CREATE TABLE access (service TEXT)")
            with closing(sqlite3.connect(browser_history)) as connection:
                connection.execute("CREATE TABLE urls (url TEXT)")
            self.assertTrue(_probe_sqlite_readable(tcc))
            self.assertFalse(_probe_sqlite_readable(root / "missing.db"))

            profile = type("Profile", (), {"history_path": browser_history})()
            with patch("macos_inspector.core.readiness.platform.system", return_value="Darwin"), patch(
                "macos_inspector.core.readiness.platform.release", return_value="25.0"
            ), patch(
                "macos_inspector.core.readiness._available_commands",
                return_value=(list(CommandRunner.ALLOWED), []),
            ), patch(
                "macos_inspector.core.readiness._tcc_database_paths", return_value=(tcc,)
            ), patch(
                "macos_inspector.core.readiness.discover_applications", return_value=[Path("Test.app")]
            ), patch(
                "macos_inspector.core.readiness.discover_browser_profiles", return_value=[profile]
            ), patch(
                "macos_inspector.core.readiness._dependency_available", side_effect=lambda name: name == "reportlab"
            ):
                readiness = collect_readiness(output, root)

            checks = {check["id"]: check for check in readiness["checks"]}
            self.assertEqual(readiness["overall"], "ready")
            self.assertEqual(checks["tcc"]["status"], "ready")
            self.assertEqual(checks["browser"]["status"], "ready")
            self.assertEqual(checks["pdf"]["status"], "ready")
            self.assertEqual(checks["signing"]["status"], "optional")
            self.assertNotIn(str(root), json.dumps(readiness))

    def test_case_bundle_contains_only_current_scan_reports_and_manifest(self):
        metadata = ScanMetadata(
            "0.1", "bundle-scan", "start", "end", "host", "platform", "user", ("test",),
            case_reference="CASE-7", analyst="DFIR", target_application="/Applications/Example.app",
        )
        result = ScanResult(metadata, (finding(),), 82, {"Persistence": 82})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "macos-inspector-other.json").write_text("other case")
            (root / "private-key.pem").write_text("private")

            paths = write_reports(result, ["html", "json", "bundle"], root)
            bundle = next(path for path in paths if path.suffix == ".zip")
            manifest = root / "macos-inspector-bundle-scan.manifest"

            self.assertIn(manifest, paths)
            self.assertEqual(bundle.stat().st_mode & 0o777, 0o600)
            with zipfile.ZipFile(bundle) as archive:
                names = set(archive.namelist())
                index = json.loads(archive.read("bundle-index.json"))
                report_permissions = archive.getinfo("macos-inspector-bundle-scan.json").external_attr >> 16 & 0o777

            self.assertEqual(report_permissions, 0o600)
            self.assertEqual(index["scan_id"], "bundle-scan")
            self.assertEqual(index["case_reference"], "CASE-7")
            self.assertEqual(index["target_application"], "/Applications/Example.app")
            self.assertIn("macos-inspector-bundle-scan.manifest", names)
            self.assertIn("VERIFY.txt", names)
            self.assertNotIn("macos-inspector-other.json", names)
            self.assertNotIn("private-key.pem", names)

    def test_release_archive_contains_executable_launcher_without_case_data(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = build_release(Path(directory) / "release.zip")
            checksum_line = (Path(directory) / "SHA256SUMS").read_text(encoding="ascii").strip()
            self.assertEqual(checksum_line, f"{hashlib.sha256(archive_path.read_bytes()).hexdigest()}  release.zip")
            with zipfile.ZipFile(archive_path) as archive:
                names = archive.namelist()
                launcher = next(name for name in names if name.endswith(f"/{LAUNCHER}"))
                permissions = archive.getinfo(launcher).external_attr >> 16 & 0o777
            self.assertEqual(permissions, 0o755)
            self.assertTrue(any(name.endswith("/LICENSE") for name in names))
            self.assertTrue(any(name.endswith("/CHANGELOG.md") for name in names))
            self.assertTrue(any(name.endswith("/SECURITY.md") for name in names))
            self.assertTrue(any(name.endswith("/docs/ARCHITECTURE.md") for name in names))
            self.assertTrue(any(name.endswith("/docs/THREAT_MODEL.md") for name in names))
            self.assertTrue(any(name.endswith("/docs/INSTALLATION.md") for name in names))
            self.assertTrue(any(name.endswith("/docs/USAGE.md") for name in names))
            self.assertTrue(any(name.endswith("/src/macos_inspector/webui/index.html") for name in names))
            self.assertFalse(any("macos-inspector-reports" in name or "/tmp/" in name or "/output/" in name for name in names))
            self.assertFalse(any(".DS_Store" in name or ".egg-info/" in name or "/._" in name for name in names))

    def test_public_documentation_relative_links_resolve(self):
        root = Path(__file__).resolve().parents[1]
        documents = (
            list(root.glob("*.md"))
            + list((root / "docs").rglob("*.md"))
            + list((root / ".github" / "release-notes").rglob("*.md"))
        )
        missing = []
        for document in documents:
            content = document.read_text(encoding="utf-8")
            for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", content):
                target = match.group(1).strip().split()[0].split("#", 1)[0]
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                candidate = (document.parent / target).resolve()
                if not candidate.exists():
                    missing.append(f"{document.relative_to(root)} -> {target}")
        self.assertEqual(missing, [])

    def test_gitea_workflow_tests_and_verifies_release_without_secrets(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".gitea" / "workflows" / "ci.yml").read_text()
        expected_steps = (
            "python -m unittest discover -s tests -v",
            "python -m compileall -q src scripts tests",
            "node --check src/macos_inspector/webui/app.js",
            "python -m scripts.build_release",
            "christopherhx/gitea-upload-artifact@v4",
            "contents: read",
        )
        for step in expected_steps:
            self.assertIn(step, workflow)
        self.assertNotIn("MACOS_INSPECTOR_MANIFEST_KEY", workflow)
        self.assertNotIn("MACOS_INSPECTOR_SIGNING_KEY", workflow)

    def test_github_workflow_tests_macos_and_builds_release(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "ci.yml").read_text()
        expected_steps = (
            "ubuntu-latest",
            "macos-latest",
            'python-version: ["3.10", "3.13"]',
            "python -m unittest discover -s tests -v",
            "node --check src/macos_inspector/webui/app.js",
            "python -m scripts.build_release",
            "actions/upload-artifact@",
            "contents: read",
        )
        for step in expected_steps:
            self.assertIn(step, workflow)
        action_references = re.findall(r"uses:\s+[^@\s]+@([^\s#]+)", workflow)
        self.assertTrue(action_references)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_references))

    def test_dashboard_health_reports_only_operational_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            idle = state.health()
            self.assertEqual(idle["status"], "ok")
            self.assertIsNone(idle["active_job"])
            self.assertGreaterEqual(idle["uptime_seconds"], 0)
            self.assertNotIn("output", idle)

            job = ScanJob(
                "job-1", ["security"], ["json"], "informational", state="running",
                current_collector="security", total_collectors=1, current_item="Example.app",
                completed_items=3, total_items=10,
            )
            state.jobs[job.job_id] = job
            active = state.health()["active_job"]
            self.assertEqual(active["job_id"], "job-1")
            self.assertEqual(active["current_collector"], "security")
            self.assertNotIn("current_item", active)
            self.assertEqual(job.to_dict()["current_item"], "Example.app")

    def test_dashboard_recovers_running_job_as_interrupted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = DashboardState(root)
            job = ScanJob("job-1", ["security"], ["json"], "informational", state="running", current_collector="security")
            state.jobs[job.job_id] = job
            state._persist_jobs_locked()
            recovered = DashboardState(root)
            restored = recovered.jobs["job-1"]
            self.assertEqual(restored.state, "interrupted")
            self.assertIn("No partial reports", restored.error)
            self.assertIsNotNone(restored.completed_at)
            self.assertEqual(recovered.journal_path.stat().st_mode & 0o777, 0o600)

    def test_dashboard_estimates_item_progress_from_recent_median(self):
        metadata = ScanMetadata("0.1", "progress-scan", "start", "end", "host", "platform", "user", ("application-trust",))
        result = ScanResult(metadata, (), 100, {})
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            job = ScanJob("job-progress", ["application-trust"], ["json"], "informational", total_collectors=1)
            state.jobs[job.job_id] = job
            state.cancel_events[job.job_id] = threading.Event()
            estimates = []

            def fake_run_scan(*args, **kwargs):
                callback = kwargs["item_progress"]
                for item, completed in (("One.app", 0), ("Two.app", 1), ("Three.app", 2), ("Four.app", 3)):
                    callback("application-trust", item, completed, 5)
                    estimates.append(job.estimated_seconds_remaining)
                callback("application-trust", None, 5, 5)
                return result

            with patch("macos_inspector.web.run_scan", side_effect=fake_run_scan), patch(
                "macos_inspector.web.write_reports", return_value=[]
            ), patch("macos_inspector.web.time.monotonic", side_effect=[100, 110, 112, 114, 116]):
                state._execute(job)

            self.assertEqual(estimates, [None, None, None, 4])
            self.assertEqual(job.state, "completed")
            self.assertIsNone(job.estimated_seconds_remaining)
            self.assertNotIn(job.job_id, state.item_progress_runtime)

    def test_case_metadata_is_serialized(self):
        metadata = ScanMetadata("0.1", "scan", "start", "end", "host", "platform", "user", ("test",), case_reference="CASE-42", analyst="DFIR Team")
        result = ScanResult(metadata, (finding(),), 82, {"Persistence": 82})
        payload = result.to_dict()
        self.assertEqual(payload["metadata"]["case_reference"], "CASE-42")
        self.assertEqual(payload["metadata"]["analyst"], "DFIR Team")

    def test_scan_comparison_classifies_changes(self):
        def item(finding_id, status="Pass", observed="same"):
            return {"finding_id": finding_id, "title": finding_id, "status": status, "severity": "Informational", "observed_result": observed}
        baseline = {
            "metadata": {"scan_id": "base", "collectors": ["security"]}, "summary": {"overall_score": 80, "category_scores": {"Security": 80}},
            "findings": [item("UNCHANGED"), item("CHANGED", "Pass"), item("RESOLVED", "Fail")],
        }
        current = {
            "metadata": {"scan_id": "current", "collectors": ["security", "persistence"]}, "summary": {"overall_score": 90, "category_scores": {"Security": 90}},
            "findings": [item("UNCHANGED"), item("CHANGED", "Fail"), item("NEW", "Fail")],
        }
        comparison = compare_scan_payloads(baseline, current)
        self.assertEqual(comparison["score_delta"], 10)
        self.assertEqual(comparison["scope"], {"changed": True, "added_collectors": ["persistence"], "removed_collectors": []})
        self.assertEqual(comparison["counts"], {"new": 1, "resolved": 1, "changed": 1, "unchanged": 1})
        self.assertEqual(comparison["new"][0]["finding_id"], "NEW")
        self.assertEqual(comparison["resolved"][0]["finding_id"], "RESOLVED")
        self.assertEqual(comparison["changed"][0]["changes"]["status"], {"before": "Pass", "after": "Fail"})

    def test_comparison_reports_are_secure_and_escape_html(self):
        comparison = {
            "baseline_scan_id": "base", "current_scan_id": "current", "baseline_score": 80,
            "current_score": 70, "score_delta": -10,
            "counts": {"new": 1, "resolved": 0, "changed": 0, "unchanged": 0},
            "scope": {"changed": False, "added_collectors": [], "removed_collectors": []},
            "category_deltas": {"Security": -10},
            "new": [{"finding_id": "NEW-1", "title": "<script>alert(1)</script>", "severity": "High", "status": "Fail"}],
            "resolved": [], "changed": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            reports = write_comparison_reports(comparison, Path(directory))
            html_report = reports["comparison_html"].read_text()
            json_report = json.loads(reports["comparison_json"].read_text())
            self.assertNotIn("<script>alert(1)</script>", html_report)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_report)
            self.assertEqual(json_report["score_delta"], -10)
            self.assertEqual(reports["comparison_html"].stat().st_mode & 0o777, 0o600)

    def test_codesign_details_parser(self):
        details = parse_codesign_details("""Identifier=com.example.App
Signature=adhoc
Authority=Developer ID Application: Example (TEAM123)
TeamIdentifier=TEAM123
Runtime Version=14.0.0
designated => identifier \"com.example.App\" and anchor apple generic""")
        self.assertEqual(details.identifier, "com.example.App")
        self.assertEqual(details.team_identifier, "TEAM123")
        self.assertEqual(details.authority, ("Developer ID Application: Example (TEAM123)",))
        self.assertEqual(details.signature_type, "Ad hoc")
        self.assertTrue(details.hardened_runtime)

    def test_gatekeeper_details_parser(self):
        details = parse_gatekeeper_details("""/Applications/Example.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: Example (TEAM123)""")
        self.assertEqual(details.source, "Notarized Developer ID")
        self.assertEqual(details.origin, "Developer ID Application: Example (TEAM123)")
        self.assertTrue(details.notarized)

    def test_application_entitlements_and_acquisition_metadata_parsers(self):
        entitlement_plist = plistlib.dumps({
            "com.apple.security.get-task-allow": True,
            "com.apple.security.app-sandbox": True,
            "binary": b"\x01\x02",
        }).decode()
        entitlements, error = parse_entitlements(f"Executable=/Applications/Test.app/Contents/MacOS/Test\n{entitlement_plist}\nwarning")
        self.assertIsNone(error)
        self.assertTrue(entitlements["com.apple.security.app-sandbox"])
        self.assertEqual(entitlements["binary"], {"encoding": "hex", "value": "0102"})
        sensitive, severity = assess_entitlements(entitlements)
        self.assertEqual(sensitive, ("com.apple.security.get-task-allow",))
        self.assertEqual(severity, Severity.MEDIUM)
        runtime_sensitive, runtime_severity = assess_entitlements({"com.apple.security.cs.allow-unsigned-executable-memory": True})
        self.assertEqual(runtime_sensitive, ("com.apple.security.cs.allow-unsigned-executable-memory",))
        self.assertIsNone(runtime_severity)

        abstract = """Executable=/Applications/Test.app/Contents/MacOS/Test
[Dict]
\t[Key] com.apple.security.get-task-allow
\t[Value]
\t\t[Bool] true
\t[Key] com.apple.security.application-groups
\t[Value]
\t\t[Array]
\t\t\t[String] group.example.one
\t\t\t[String] group.example.two
"""
        abstract_entitlements, abstract_error = parse_entitlements(abstract)
        self.assertIsNone(abstract_error)
        self.assertTrue(abstract_entitlements["com.apple.security.get-task-allow"])
        self.assertEqual(abstract_entitlements["com.apple.security.application-groups"], ["group.example.one", "group.example.two"])

        sources_plist = plistlib.dumps(["https://example.test/download", "https://example.test/"])
        sources, source_error = parse_where_froms_hex(sources_plist.hex())
        self.assertIsNone(source_error)
        self.assertEqual(sources[0], "https://example.test/download")

        quarantine = parse_quarantine("0083;00000000;Safari;ABC-123")
        self.assertEqual(quarantine.flags, "0083")
        self.assertEqual(quarantine.timestamp_iso, "1970-01-01T00:00:00+00:00")
        self.assertEqual(quarantine.agent, "Safari")

    def test_unavailable_authority_is_not_a_signature_type(self):
        details = parse_codesign_details("Identifier=com.example.App\nAuthority=(unavailable)\nTeamIdentifier=TEAM123")
        self.assertIsNone(details.signature_type)
        self.assertEqual(details.authority, ("(unavailable)",))

    def test_launchctl_service_parser(self):
        entries = parse_disabled_services('"com.example.agent" => enabled\n"com.apple.demo" => disabled')
        self.assertEqual(entries, [("com.example.agent", "enabled"), ("com.apple.demo", "disabled")])

    def test_background_items_prioritize_enabled_third_party_services(self):
        class FakeRunner:
            def run(self, argv):
                command = tuple(argv)
                if argv[0] == "sfltool":
                    return CommandResult(command, 0, "collected", "")
                output = (
                    '"com.vendor.active" => enabled'
                    if argv[-1].startswith("user/")
                    else '"com.vendor.inactive" => disabled'
                )
                return CommandResult(command, 0, output, "")

        findings = {item.title: item for item in BackgroundItemsCollector(FakeRunner()).collect()}
        user = findings["ServiceManagement disabled map: user"]
        system = findings["ServiceManagement disabled map: system"]
        self.assertEqual((user.severity, user.status), (Severity.MEDIUM, "Review"))
        self.assertEqual((system.severity, system.status), (Severity.INFORMATIONAL, "Observed"))
        self.assertEqual(system.evidence[0].value["review_candidates"], [])
        self.assertEqual(system.evidence[0].value["disabled_third_party_context"][0]["label"], "com.vendor.inactive")

    def test_certificate_hash_parser(self):
        output = "SHA-256 hash: aa11\nSHA-1 hash: 0123456789012345678901234567890123456789\nSHA-256 hash: AA11"
        self.assertEqual(parse_certificate_hashes(output), ["0123456789012345678901234567890123456789"])

    def test_system_extension_parser(self):
        output = """enabled active ABC1234567 com.example.filter (1.2.3)\nterminated XYZ7654321 com.apple.demo (2.0)"""
        extensions = parse_system_extensions(output)
        self.assertEqual(len(extensions), 2)
        self.assertEqual(extensions[0].bundle_id, "com.example.filter")
        self.assertEqual(extensions[0].state, "enabled active")
        current_output = """2 extension(s)
--- com.apple.system_extension.network_extension
enabled active teamID bundleID (version) name [state]
* * J6S6Q257EK ch.protonvpn.mac.OpenVPN-Extension (4.3.0/2404171112) ProtonVPN OpenVPN [activated enabled]
* * J6S6Q257EK ch.protonvpn.mac.WireGuard-Extension (6.5.1/3106797) Proton VPN WireGuard [activated enabled]"""
        current = parse_system_extensions(current_output)
        self.assertEqual([item.bundle_id for item in current], [
            "ch.protonvpn.mac.OpenVPN-Extension",
            "ch.protonvpn.mac.WireGuard-Extension",
        ])
        self.assertTrue(all(item.team_id == "J6S6Q257EK" for item in current))
        self.assertTrue(all(item.state == "activated enabled" for item in current))

    def test_ioc_pack_matches_explicit_path(self):
        class FakeRunner:
            pass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "marker.bin"
            marker.write_bytes(b"evidence")
            pack = root / "pack.json"
            pack.write_text(json.dumps({
                "schema_version": 1, "enabled": True, "name": "Unit Pack", "version": "1",
                "source": "unit-test", "updated_at": datetime.now(timezone.utc).isoformat(),
                "indicators": [
                    {"id": "present", "type": "path", "value": str(marker), "severity": "high"},
                    {"id": "absent", "type": "path", "value": str(root / "absent"), "severity": "high"},
                ],
            }))
            findings = IOCCollector(FakeRunner(), (root,)).collect()
            statuses = {finding.title: finding.status for finding in findings}
            self.assertEqual(statuses["IOC path: present"], "Match")
            self.assertEqual(statuses["IOC path: absent"], "Pass")
            self.assertEqual(marker.read_bytes(), b"evidence")

    def test_application_trust_classification(self):
        valid = CommandResult(("codesign",), 0, "", "")
        accepted = CommandResult(("spctl",), 0, "", "accepted")
        self.assertEqual(classify_trust(True, valid, accepted)[:2], (Severity.INFORMATIONAL, "Pass"))
        rejected = CommandResult(("spctl",), 3, "", "rejected")
        self.assertEqual(classify_trust(True, valid, rejected)[:2], (Severity.MEDIUM, "Fail"))
        unsigned = CommandResult(("codesign",), 1, "", "code object is not signed at all")
        self.assertEqual(classify_trust(True, unsigned, rejected)[:2], (Severity.HIGH, "Fail"))
        unavailable = CommandResult(("codesign",), 126, "", "not in a trusted system directory")
        self.assertEqual(classify_trust(True, unavailable, rejected)[:2], (Severity.INFORMATIONAL, "Unknown"))
        ad_hoc = SignatureDetails(identifier="local.app", signature_type="Ad hoc")
        self.assertEqual(classify_trust(True, valid, accepted, ad_hoc)[:2], (Severity.LOW, "Review"))
        metadata_only = CommandResult(("codesign",), 1, "", "resource fork, Finder information, or similar detritus not allowed")
        self.assertEqual(classify_trust(True, metadata_only, accepted)[:2], (Severity.MEDIUM, "Review"))
        missing_resource = CommandResult(("codesign",), 1, "", "a sealed resource is missing or invalid\nfile missing: payload.dylib")
        self.assertEqual(classify_trust(True, missing_resource, rejected)[:2], (Severity.HIGH, "Fail"))
        self.assertIn("incomplete", classify_trust(True, missing_resource, rejected)[2])
        apple = SignatureDetails(identifier="com.apple.Passwords", signature_type="Apple")
        not_assessable = CommandResult(("spctl",), 3, "", "rejected (the code is valid but does not seem to be an app)")
        self.assertEqual(classify_trust(True, valid, not_assessable, apple)[:2], (Severity.INFORMATIONAL, "Pass"))

    def test_application_discovery_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Direct.app").mkdir()
            (root / "Vendor" / "Nested.app").mkdir(parents=True)
            (root / "Vendor" / "Deeper" / "Ignored.app").mkdir(parents=True)
            self.assertEqual(
                [path.name for path in discover_applications((root,))],
                ["Direct.app", "Nested.app"],
            )

    def test_targeted_application_trust_inspects_only_explicit_bundles(self):
        class NoCommands:
            pass

        first = Path("/Applications/One.app")
        second = Path("/Applications/Two.app")
        collector = ApplicationTrustCollector(NoCommands(), bundles=(second, first, second))
        with patch.object(collector, "_inspect", side_effect=lambda path: path):
            self.assertEqual(collector.collect(), [first, second])

    def test_run_scan_records_and_routes_target_application(self):
        captured = {}

        class TargetCollector:
            def __init__(self, runner, bundles=None):
                captured["bundles"] = bundles

            def collect(self):
                return []

        target = Path("/Applications/Example.app")
        with patch.dict("macos_inspector.core.scan.COLLECTORS", {"application-trust": TargetCollector}, clear=True):
            result = run_scan(["application-trust"], runner=object(), target_application=target)
        self.assertEqual(captured["bundles"], (target,))
        self.assertEqual(result.metadata.target_application, str(target))
        self.assertEqual(result.to_dict()["metadata"]["target_application"], str(target))

    def test_dashboard_application_inventory_rejects_arbitrary_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Allowed.app"
            bundle.mkdir()
            state = DashboardState(Path(directory) / "reports")
            with patch("macos_inspector.web.discover_applications", return_value=[bundle]):
                self.assertEqual(state.applications(), [{"name": "Allowed", "path": str(bundle)}])
                self.assertEqual(state.validate_target_application(str(bundle)), str(bundle))
                with self.assertRaisesRegex(ValueError, "local application list"):
                    state.validate_target_application("/tmp/Unlisted.app")
                with self.assertRaisesRegex(ValueError, "Application Trust"):
                    state.create_job(["security"], ["json"], "informational", target_application=str(bundle))

                server = DashboardServer(("127.0.0.1", 0), state)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    host = f"127.0.0.1:{server.server_port}"
                    status, _, body = dashboard_request(server, "GET", "/api/applications", host)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body)["applications"][0]["path"], str(bundle))

                    status, _, body = dashboard_request(server, "POST", "/api/scans", host, payload={
                        "collectors": ["application-trust"], "formats": ["json"],
                        "target_application": "/tmp/Unlisted.app",
                    })
                    self.assertEqual(status, 400)
                    self.assertIn("local application list", json.loads(body)["error"])

                    accepted = ScanJob(
                        "target-job", ["application-trust"], ["html", "json"],
                        "informational", target_application=str(bundle),
                    )
                    with patch.object(state, "create_job", return_value=accepted) as create:
                        status, _, body = dashboard_request(server, "POST", "/api/scans", host, payload={
                            "collectors": ["application-trust"], "formats": ["json"],
                            "target_application": str(bundle),
                        })
                    self.assertEqual(status, 202)
                    self.assertEqual(json.loads(body)["target_application"], str(bundle))
                    self.assertEqual(create.call_args.args[-1], str(bundle))
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

    def test_previous_comparable_report_requires_same_application_target(self):
        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            reports = (
                {"metadata": {"scan_id": "full", "collectors": ["application-trust"], "completed_at": "2026-01-01T00:00:00+00:00"}},
                {"metadata": {"scan_id": "other", "collectors": ["application-trust"], "target_application": "/Applications/Other.app", "completed_at": "2026-01-02T00:00:00+00:00"}},
                {"metadata": {"scan_id": "same", "collectors": ["application-trust"], "target_application": "/Applications/Example.app", "completed_at": "2026-01-03T00:00:00+00:00"}},
            )
            for report in reports:
                scan_id = report["metadata"]["scan_id"]
                (state.output / f"macos-inspector-{scan_id}.json").write_text(json.dumps(report))
            current = {"metadata": {
                "scan_id": "current", "collectors": ["application-trust"],
                "target_application": "/Applications/Example.app",
                "completed_at": "2026-01-04T00:00:00+00:00",
            }}
            self.assertEqual(state._previous_comparable_report(current)["metadata"]["scan_id"], "same")

    def test_application_trust_records_stable_executable_hash(self):
        class FakeRunner:
            def run(self, argv):
                command = tuple(argv)
                if argv[0] == "codesign" and "--entitlements" in argv:
                    return CommandResult(command, 0, "", "")
                if argv[0] == "codesign" and "--verify" in argv:
                    return CommandResult(command, 0, "", "")
                if argv[0] == "codesign":
                    return CommandResult(command, 0, "", "Identifier=com.example.Test\nTeamIdentifier=TEAM123\nAuthority=Developer ID Application: Test (TEAM123)\nRuntime Version=14.0")
                if argv[0] == "spctl":
                    return CommandResult(command, 0, "", "accepted\nsource=Notarized Developer ID")
                return CommandResult(command, 1, "", "attribute not found")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "Test.app"
            executable = bundle / "Contents" / "MacOS" / "Test"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"trusted executable fixture")
            executable.chmod(0o751)
            with (bundle / "Contents" / "Info.plist").open("wb") as stream:
                plistlib.dump({
                    "CFBundleExecutable": "Test",
                    "CFBundleIdentifier": "com.example.Test",
                    "CFBundleName": "Test",
                }, stream)

            details = inspect_file_integrity(executable)
            self.assertEqual(details.sha256, hashlib.sha256(executable.read_bytes()).hexdigest())
            self.assertEqual(details.size_bytes, len(executable.read_bytes()))
            self.assertEqual(details.permissions, "0751")
            self.assertFalse(details.changed_during_read)

            progress = []
            collector = ApplicationTrustCollector(FakeRunner(), (root,))
            collector.set_progress_callback(lambda item, completed, total: progress.append((item, completed, total)))
            finding = collector.collect()[0]
            integrity = next(item for item in finding.evidence if item.kind == "executable_integrity")
            plist_integrity = next(item for item in finding.evidence if item.kind == "info_plist_integrity")
            path_integrity = next(item for item in finding.evidence if item.kind == "bundle_path_integrity")
            self.assertEqual(finding.status, "Pass")
            self.assertEqual(integrity.value["sha256"], details.sha256)
            self.assertEqual(integrity.value["owner_uid"], executable.stat().st_uid)
            self.assertEqual(integrity.value["owner_gid"], executable.stat().st_gid)
            self.assertIn(details.sha256, finding.observed_result)
            self.assertIn("executable_mode=0751", finding.observed_result)
            self.assertIn(f"info_plist_sha256={plist_integrity.value['sha256']}", finding.observed_result)
            self.assertIn("executable_inside_bundle=yes", finding.observed_result)
            self.assertEqual(len(plist_integrity.value["sha256"]), 64)
            self.assertTrue(path_integrity.value["executable_resolves_within_bundle"])
            self.assertEqual(progress, [("Test.app", 0, 1), (None, 1, 1)])

            executable.chmod(0o775)
            risky_finding = collector._inspect(bundle)
            self.assertEqual((risky_finding.severity, risky_finding.status), (Severity.MEDIUM, "Review"))
            self.assertIn("group-writable", risky_finding.observed_result)

    def test_scan_forwards_collector_item_progress(self):
        class ProgressCollector:
            def __init__(self, runner):
                self.callback = None

            def set_progress_callback(self, callback):
                self.callback = callback

            def collect(self):
                self.callback("One.app", 0, 2)
                self.callback("Two.app", 1, 2)
                self.callback(None, 2, 2)
                return []

        events = []
        with patch.dict("macos_inspector.core.scan.COLLECTORS", {"progress": ProgressCollector}, clear=True):
            run_scan(["progress"], item_progress=lambda collector, item, completed, total: events.append((collector, item, completed, total)))
        self.assertEqual(events, [
            ("progress", "One.app", 0, 2),
            ("progress", "Two.app", 1, 2),
            ("progress", None, 2, 2),
        ])

    def test_browser_artifacts_read_chromium_profile(self):
        class FakeRunner:
            pass

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = home / "Library/Application Support/Google/Chrome/Default"
            profile.mkdir(parents=True)
            with closing(sqlite3.connect(profile / "History")) as connection:
                connection.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
                connection.execute("CREATE TABLE downloads (target_path TEXT, tab_url TEXT, start_time INTEGER, state INTEGER, danger_type INTEGER)")
                connection.execute("INSERT INTO urls VALUES (?, ?, ?, ?)", ("https://example.test/", "Example", 2, 1))
                connection.commit()
            (profile / "Extensions/exampleextension/1.0").mkdir(parents=True)
            findings = BrowserArtifactsCollector(FakeRunner(), home).collect()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "Review")
            self.assertEqual(findings[0].severity, Severity.LOW)
            self.assertIn("1 recent history", findings[0].observed_result)

    def test_privacy_collector_reads_tcc_database_read_only(self):
        class FakeRunner:
            pass

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "TCC.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE access (service TEXT, client TEXT, auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER)")
                connection.execute("INSERT INTO access VALUES (?, ?, ?, ?, ?)", ("kTCCServiceCamera", "com.example.camera", 2, 4, 123))
                connection.execute("INSERT INTO access VALUES (?, ?, ?, ?, ?)", ("kTCCServiceCamera", "com.example.denied", 0, 4, 124))
                connection.commit()
            findings = PrivacyCollector(FakeRunner(), (database,)).collect()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].status, "Review")
            self.assertEqual(findings[0].severity, Severity.MEDIUM)
            self.assertIn("allow access", findings[0].observed_result)
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM access").fetchone()[0], 2)

    def test_program_resolution(self):
        self.assertEqual(_program_from_plist({"Program": "/bin/test"}), "/bin/test")
        self.assertEqual(_program_from_plist({"ProgramArguments": ["/bin/other", "x"]}), "/bin/other")
        self.assertIsNone(_program_from_plist({}))

    def test_scoring_penalizes_open_findings_only(self):
        overall, categories = calculate_scores([finding(), finding(Severity.MEDIUM, "Pass")])
        self.assertEqual(overall, 82)
        self.assertEqual(categories["Persistence"], 82)

    def test_timeline_extracts_collection_and_embedded_timestamps(self):
        item = finding()
        item = Finding(
            item.finding_id, item.category, item.title, item.severity, item.status, item.description,
            item.why_it_matters, item.what_was_checked, item.expected_result, item.observed_result,
            item.recommendation,
            (Evidence("browser", "unit", {"visited_at": "2026-01-02T03:04:05+00:00"}, "2026-01-03T00:00:00+00:00"),),
        )
        timeline = build_timeline([item])
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline[0].kind, "visited_at")
        self.assertEqual(timeline[1].kind, "collection")

    def test_runner_rejects_non_allowlisted_command(self):
        with self.assertRaises(ValueError):
            CommandRunner().run(("rm", "-rf", "/"))
        with self.assertRaises(ValueError):
            CommandRunner().run(("/tmp/codesign",))

    def test_scan_cancellation_stops_before_collection_and_commands(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(ScanCancelled):
            CommandRunner(cancel_event=event).run(("uname",))

        class NeverCollector:
            def __init__(self, runner):
                raise AssertionError("Cancelled scan must not construct a collector")

        with patch.dict("macos_inspector.core.scan.COLLECTORS", {"never": NeverCollector}, clear=True):
            with self.assertRaises(ScanCancelled):
                run_scan(["never"], cancel_event=event)

    def test_scan_score_is_not_inflated_by_minimum_severity(self):
        class FakeCollector:
            def __init__(self, runner):
                pass
            def collect(self):
                return [finding(Severity.HIGH), finding(Severity.LOW)]

        with patch.dict("macos_inspector.core.scan.COLLECTORS", {"fake": FakeCollector}, clear=True):
            result = run_scan(["fake"], Severity.HIGH)
        self.assertEqual(result.overall_score, 79)
        self.assertEqual(result.total_finding_count, 2)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.to_dict()["summary"]["total_finding_count"], 2)

    def test_all_reporters_write(self):
        metadata = ScanMetadata("0.1", "scan", "start", "end", "host", "platform", "user", ("test",))
        result = ScanResult(metadata, (finding(),), 82, {"Persistence": 82})
        with tempfile.TemporaryDirectory() as directory:
            for name, reporter in REPORTERS.items():
                if name == "encrypted-bundle" and not encryption_available():
                    continue
                path = Path(directory) / f"report.{name}"
                with patch.dict("os.environ", {"MACOS_INSPECTOR_BUNDLE_PASSWORD": "correct horse battery staple"}, clear=False):
                    reporter(result, path)
                self.assertGreater(path.stat().st_size, 10)

    def test_encrypted_case_bundle_detects_wrong_password_and_tampering(self):
        if not encryption_available():
            self.skipTest("cryptography is not installed")
        metadata = ScanMetadata("1.2", "encrypted", "start", "end", "host", "platform", "user", ("test",), case_reference="IR-ENC")
        result = ScanResult(metadata, (finding(),), 82, {"Persistence": 82})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = write_reports(result, ["json", "encrypted-bundle"], root, bundle_password="correct horse battery staple")
            encrypted = next(path for path in paths if path.name.endswith(".zip.enc"))
            decrypted = root / "decrypted.zip"
            decrypt_file(encrypted, decrypted, "correct horse battery staple")
            with zipfile.ZipFile(decrypted) as archive:
                self.assertIn("bundle-index.json", archive.namelist())
            with self.assertRaisesRegex(ValueError, "incorrect|modified"):
                decrypt_file(encrypted, root / "wrong.zip", "incorrect password value")

    def test_sarif_contains_only_actionable_findings(self):
        metadata = ScanMetadata("0.1", "scan", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:01+00:00", "host", "platform", "user", ("test",))
        result = ScanResult(metadata, (finding(Severity.HIGH, "Fail"), finding(Severity.INFORMATIONAL, "Pass")), 82, {"Persistence": 82})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.sarif"
            REPORTERS["sarif"](result, path)
            payload = json.loads(path.read_text())
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(payload["runs"][0]["results"]), 1)
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "error")

    def test_target_application_scope_is_visible_in_export_formats(self):
        target = "/Applications/Example.app"
        metadata = ScanMetadata(
            "1.3.0", "target-exports", "start", "end", "host", "platform", "user",
            ("application-trust",), target_application=target,
        )
        result = ScanResult(metadata, (finding(),), 82, {"Application Trust": 82})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html_path, markdown_path = root / "report.html", root / "report.md"
            csv_path, sarif_path = root / "report.csv", root / "report.sarif"
            REPORTERS["html"](result, html_path)
            REPORTERS["markdown"](result, markdown_path)
            REPORTERS["csv"](result, csv_path)
            REPORTERS["sarif"](result, sarif_path)
            self.assertIn(f"Target application: {target}", html_path.read_text())
            self.assertIn(f"**Target application:** {target}", markdown_path.read_text())
            csv_rows = list(csv.DictReader(io.StringIO(csv_path.read_text())))
            self.assertEqual(csv_rows[0]["target_application"], target)
            sarif = json.loads(sarif_path.read_text())
            self.assertEqual(sarif["runs"][0]["invocations"][0]["properties"]["targetApplication"], target)

    def test_evidence_manifest_hashes_and_signature(self):
        metadata = ScanMetadata("0.1", "scan", "start", "end", "host", "platform", "user", ("test",))
        result = ScanResult(metadata, (finding(),), 82, {"Persistence": 82})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "report.json"
            artifact.write_text("evidence")
            manifest = root / "report.manifest"
            with patch.dict("os.environ", {"MACOS_INSPECTOR_MANIFEST_KEY": "unit-secret"}, clear=True):
                write_manifest(result, manifest, (artifact,))
            valid, errors = verify_manifest(manifest, "unit-secret")
            self.assertTrue(valid, errors)
            artifact.write_text("changed")
            valid, errors = verify_manifest(manifest, "unit-secret")
            self.assertFalse(valid)
            self.assertIn("Digest mismatch", errors[0])

    def test_asymmetric_manifest_signature(self):
        if importlib.util.find_spec("cryptography") is None:
            self.skipTest("cryptography is not installed")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        metadata = ScanMetadata("0.1", "scan", "start", "end", "host", "platform", "user", ("test",))
        result = ScanResult(metadata, (finding(),), 82, {"Persistence": 82})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / "identity.pem"
            private_path.write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
            ))
            artifact = root / "report.json"
            artifact.write_text("evidence")
            manifest = root / "report.manifest"
            with patch.dict("os.environ", {"MACOS_INSPECTOR_SIGNING_KEY": str(private_path)}, clear=True):
                write_manifest(result, manifest, (artifact,))
            payload = json.loads(manifest.read_text())
            self.assertEqual(payload["signature"]["algorithm"], "Ed25519")
            self.assertEqual(len(payload["signature"]["public_key_sha256"]), 64)
            valid, errors = verify_manifest(manifest)
            self.assertTrue(valid, errors)
            payload["scan_id"] = "tampered"
            manifest.write_text(json.dumps(payload))
            valid, errors = verify_manifest(manifest)
            self.assertFalse(valid)
            self.assertIn("Manifest signature mismatch.", errors)


if __name__ == "__main__":
    unittest.main()
