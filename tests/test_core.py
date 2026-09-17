import tempfile
import unittest
import hashlib
import http.client
import io
import sqlite3
import json
import importlib.util
import plistlib
import re
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
from macos_inspector.core.intelligence import IntelligenceResource, fetch_cached_json, parse_apple_security_releases, validate_epss, validate_nvd
from macos_inspector.core.storage import CaseStore, SettingsStore
from macos_inspector.core.models import Evidence, Finding, ScanMetadata, ScanResult, Severity
from macos_inspector.core.comparison import compare_scan_payloads
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


class CoreTests(unittest.TestCase):
    def test_dashboard_rejects_dns_rebinding_hosts_and_cross_origin_writes(self):
        def request(server, method, path, host, *, origin=None, payload=None, extra_host=None, extra_origin=None):
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
                connection.putheader("X-MacOS-Inspector", "1")
            connection.endheaders(body)
            response = connection.getresponse()
            result = response.status, dict(response.getheaders()), response.read()
            connection.close()
            return result

        with tempfile.TemporaryDirectory() as directory:
            state = DashboardState(Path(directory))
            server = DashboardServer(("127.0.0.1", 0), state)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_port
            try:
                status, headers, _ = request(server, "GET", "/api/health", f"127.0.0.1:{port}")
                self.assertEqual(status, 200)
                self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
                self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN")

                for host in (f"attacker.example:{port}", f"localhost.attacker.example:{port}", f"127.0.0.1.example:{port}"):
                    status, _, body = request(server, "GET", "/api/health", host)
                    self.assertEqual(status, 403)
                    self.assertIn(b"Invalid local request", body)

                status, _, _ = request(
                    server, "GET", "/api/health", f"127.0.0.1:{port}", extra_host=f"localhost:{port}",
                )
                self.assertEqual(status, 403)

                status, _, _ = request(
                    server, "POST", "/api/settings", f"127.0.0.1:{port}",
                    origin=f"http://attacker.example:{port}", payload={"cache_hours": 7},
                )
                self.assertEqual(status, 403)
                self.assertEqual(state.settings.load()["cache_hours"], 24)

                status, _, _ = request(
                    server, "POST", "/api/settings", f"127.0.0.1:{port}",
                    origin=f"http://127.0.0.1:{port}", extra_origin=f"http://localhost:{port}", payload={"cache_hours": 7},
                )
                self.assertEqual(status, 403)
                self.assertEqual(state.settings.load()["cache_hours"], 24)

                status, _, _ = request(
                    server, "POST", "/api/settings", f"127.0.0.1:{port}",
                    origin=f"http://127.0.0.1:{port}", payload={"cache_hours": 7},
                )
                self.assertEqual(status, 200)
                self.assertEqual(state.settings.load()["cache_hours"], 7)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

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
                "providers": {"nvd": {"enabled": True, "api_key": "nvd-secret"}, "threatfox": {"enabled": True, "auth_key": "fox-secret"}},
                "yara": {"enabled": True, "targets": ["~/Downloads"]},
            })
            self.assertNotIn("language", public)
            self.assertTrue(public["providers"]["nvd"]["api_key_configured"])
            self.assertNotIn("nvd-secret", json.dumps(public))
            self.assertEqual(settings.path.stat().st_mode & 0o777, 0o600)

            cases = CaseStore(root)
            saved = cases.save({"reference": "IR-12", "title": "Suspicious launch item", "analyst": "DFIR", "notes": "Preserve first.", "archived": False})
            self.assertEqual(cases.list()[0]["id"], saved["id"])
            self.assertEqual(cases.path.stat().st_mode & 0o777, 0o600)

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
        processes = parse_processes("1 0 root /sbin/launchd\n42 1 alice /private/tmp/agent\n99 42 alice /Applications/Safe.app/Contents/MacOS/Safe")
        self.assertEqual(len(processes), 3)
        suspicious = suspicious_processes(processes)
        self.assertEqual(suspicious[0]["pid"], 42)
        sockets = parse_lsof_fields("p42\ncagent\nn*:8080\nTST=LISTEN\nn1.2.3.4:443\nTST=ESTABLISHED\n")
        self.assertEqual([item["state"] for item in sockets], ["LISTEN", "ESTABLISHED"])

        class FakeRunner:
            def run(self, argv):
                if argv[0] == "ps":
                    if "etime" in argv[2]:
                        return CommandResult(tuple(argv), 0, "1 01:00 /sbin/launchd\n42 00:30 /private/tmp/agent", "")
                    return CommandResult(tuple(argv), 0, "1 0 root /sbin/launchd\n42 1 alice /private/tmp/agent", "")
                return CommandResult(tuple(argv), 0, "p42\ncagent\nn*:8080\nTST=LISTEN", "")

        findings = {item.finding_id: item for item in LiveTriageCollector(FakeRunner()).collect()}
        self.assertEqual(findings["LIVE-PROCESS-TREE"].status, "Review")
        self.assertEqual(findings["LIVE-PROCESS-TREE"].severity, Severity.MEDIUM)
        self.assertEqual(findings["LIVE-NETWORK-PROCESSES"].severity, Severity.HIGH)

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
            case_reference="CASE-7", analyst="DFIR",
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
            self.assertIn("macos-inspector-bundle-scan.manifest", names)
            self.assertIn("VERIFY.txt", names)
            self.assertNotIn("macos-inspector-other.json", names)
            self.assertNotIn("private-key.pem", names)

    def test_release_archive_contains_executable_launcher_without_case_data(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = build_release(Path(directory) / "release.zip")
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
            "actions/upload-artifact@v4",
            "contents: read",
        )
        for step in expected_steps:
            self.assertIn(step, workflow)

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
