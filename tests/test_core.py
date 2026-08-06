import tempfile
import unittest
import hashlib
import sqlite3
import json
import importlib.util
import plistlib
import threading
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from unittest.mock import patch
from pathlib import Path

from macos_inspector.collectors.application_trust import (
    ApplicationTrustCollector,
    SignatureDetails,
    classify_trust,
    discover_applications,
    inspect_file_integrity,
    assess_entitlements,
    parse_codesign_details,
    parse_entitlements,
    parse_gatekeeper_details,
    parse_quarantine,
    parse_where_froms_hex,
)
from macos_inspector.collectors.background_items import parse_disabled_services
from macos_inspector.collectors.browser_artifacts import BrowserArtifactsCollector
from macos_inspector.collectors.persistence import _program_from_plist
from macos_inspector.collectors.privacy import PrivacyCollector
from macos_inspector.collectors.network import parse_certificate_hashes
from macos_inspector.collectors.system_extensions import parse_system_extensions
from macos_inspector.collectors.ioc import IOCCollector
from macos_inspector.core.models import Evidence, Finding, ScanMetadata, ScanResult, Severity
from macos_inspector.core.comparison import compare_scan_payloads
from macos_inspector.core.runner import CommandResult, CommandRunner, ScanCancelled
from macos_inspector.core.scan import run_scan, write_reports
from macos_inspector.core.scoring import calculate_scores
from macos_inspector.core.timeline import build_timeline
from macos_inspector.reporters import REPORTERS
from macos_inspector.reporters.manifest_reporter import verify_manifest, write_manifest
from macos_inspector.reporters.comparison_reporter import write_comparison_reports
from macos_inspector.web import DashboardState, ScanJob
from scripts.build_release import LAUNCHER, build_release


def finding(severity=Severity.HIGH, status="Fail"):
    return Finding("TEST-1", "Persistence", "Test", severity, status, "Description", "Why", "Checked", "Expected", "Observed", "Recommendation", (Evidence("test", "unit", "value"),))


class CoreTests(unittest.TestCase):
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
            self.assertTrue(any(name.endswith("/src/macos_inspector/webui/index.html") for name in names))
            self.assertFalse(any("macos-inspector-reports" in name or "/tmp/" in name or "/output/" in name for name in names))
            self.assertFalse(any(".DS_Store" in name or ".egg-info/" in name or "/._" in name for name in names))

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

    def test_certificate_hash_parser(self):
        output = "SHA-256 hash: aa11\nSHA-1 hash: 0123456789012345678901234567890123456789\nSHA-256 hash: AA11"
        self.assertEqual(parse_certificate_hashes(output), ["0123456789012345678901234567890123456789"])

    def test_system_extension_parser(self):
        output = """enabled active ABC1234567 com.example.filter (1.2.3)\nterminated XYZ7654321 com.apple.demo (2.0)"""
        extensions = parse_system_extensions(output)
        self.assertEqual(len(extensions), 2)
        self.assertEqual(extensions[0].bundle_id, "com.example.filter")
        self.assertEqual(extensions[0].state, "enabled active")

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
            self.assertEqual(integrity.value["sha256"], details.sha256)
            self.assertIn(details.sha256, finding.observed_result)
            self.assertEqual(progress, [("Test.app", 0, 1), (None, 1, 1)])

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
                if name == "pdf" and importlib.util.find_spec("reportlab") is None:
                    continue
                path = Path(directory) / f"report.{name}"
                reporter(result, path)
                self.assertGreater(path.stat().st_size, 10)

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
