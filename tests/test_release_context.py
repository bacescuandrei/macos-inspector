import json
import copy
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from macos_inspector.collectors.application_trust import ApplicationTrustCollector, discover_applications
from macos_inspector.collectors.ioc import IOCCollector
from macos_inspector.collectors.live_triage import LiveTriageCollector
from macos_inspector.collectors.yara_rules import YARARulesCollector
from macos_inspector.core.comparison import compare_scan_payloads
from macos_inspector.core.decision_support import analyze_changes
from macos_inspector.core.models import Finding, Severity
from macos_inspector.core.rule_context import capture_rule_context, detection_context_limits
from macos_inspector.core.response_history import append_response_event, read_response_history, evaluate_response_recheck
from macos_inspector.core.scan import run_scan
from macos_inspector.web import DashboardState, ScanJob


def response_fixture():
    action = {"pid": 4242, "uid": 501, "process_start": "fixture-start", "executable": "/synthetic/tool",
              "hostname": "fixture", "timestamp": "2026-01-01T00:00:00Z"}
    snapshot = {"process_count": 1, "running_processes": [dict(action)], "inventory_complete": True, "snapshot_truncated": False}
    report = {"metadata": {"hostname": "fixture", "started_at": "2026-01-01T00:01:00Z",
                           "completed_at": "2026-01-01T00:02:00Z", "collection_errors": []},
              "findings": [{"finding_id": "LIVE-PROCESS-TREE", "status": "Pass", "evidence": [
                  {"kind": "process_snapshot", "collected_at": "2026-01-01T00:01:30Z", "value": snapshot}]}]}
    return action, report, snapshot


class ReleaseContextTests(unittest.TestCase):
    def test_declared_detection_validation_scenarios_are_reproducible(self):
        from scripts.validate_detections import validate_detections
        result = validate_detections()
        self.assertEqual(result["scenario_count"], 26)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["false_alerts_in_expected_pass_cases"], 0)
        self.assertEqual(result["missed_review_in_declared_review_cases"], 0)
        self.assertIn("not real-world", result["limitation"])

    def test_discovery_keeps_partial_inventory_and_records_access_gaps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Example.app").mkdir()
            blocked = root / "Vendor"
            blocked.mkdir()
            original = Path.iterdir

            def listing(path):
                if path == blocked:
                    raise PermissionError("Synthetic access failure")
                return original(path)

            errors = []
            with patch.object(Path, "iterdir", listing):
                self.assertEqual(discover_applications((root,), errors=errors), [root / "Example.app"])
                collector = ApplicationTrustCollector(object(), roots=(root,))
                with patch.object(collector, "_inspect", return_value=None):
                    findings = collector.collect()
            self.assertIn("PermissionError", errors[0])
            self.assertEqual(findings[-1].finding_id, "APP-INVENTORY-COVERAGE")
            self.assertEqual(findings[-1].status, "Unknown")

    def test_optional_missing_application_roots_are_not_access_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = []
            self.assertEqual(discover_applications((Path(directory) / "absent",), errors=errors), [])
            self.assertEqual(errors, [])

    def test_one_unknown_result_cannot_round_completion_up_to_one_hundred(self):
        class Collector:
            def __init__(self, runner):
                self.collection_errors = ["Synthetic inventory gap"]

            def collect(self):
                template = Finding("TEST", "Test", "Test", Severity.INFORMATIONAL, "Pass", "", "", "", "", "", "")
                from dataclasses import replace
                return [replace(template, finding_id=f"TEST-{index}") for index in range(499)] + [replace(template, status="Unknown")]

        with patch.dict("macos_inspector.core.scan.COLLECTORS", {"test": Collector}, clear=True):
            result = run_scan(["test"], runner=object())
        self.assertEqual(result.collector_coverage["test"], 99)
        self.assertEqual(result.metadata.collection_errors, ("test: Synthetic inventory gap",))

    def test_rule_fingerprint_uses_content_not_pack_version_and_excludes_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "pack.json"
            rule.write_text('{"version":"1","indicators":[]}', encoding="utf-8")
            collector = IOCCollector(object(), directories=(root,))
            before = capture_rule_context("ioc", collector)
            self.assertEqual(before, capture_rule_context("ioc", collector))
            rule.write_text('{"version":"1","indicators":[{"value":"changed"}]}', encoding="utf-8")
            after = capture_rule_context("ioc", collector)
            self.assertNotEqual(before["fingerprint"], after["fingerprint"])
            settings = {"yara": {"enabled": True, "targets": ["/synthetic/one"]}, "api_key": "DO-NOT-RECORD"}
            yara = YARARulesCollector(object(), settings=settings, rules_directory=root)
            first = capture_rule_context("yara-rules", yara)
            settings["api_key"] = "different-secret"
            self.assertEqual(first, capture_rule_context("yara-rules", yara))
            settings["yara"]["targets"] = ["/synthetic/two"]
            self.assertNotEqual(first["fingerprint"], capture_rule_context("yara-rules", yara)["fingerprint"])
            self.assertNotIn("synthetic", json.dumps(first))
            self.assertNotIn("DO-NOT-RECORD", json.dumps(first))

    def test_rule_changes_disable_inventory_and_index_inferences_not_raw_records(self):
        context = {"schema_version": 1, "complete": True, "stable": True, "fingerprint": "a" * 64}
        baseline = {"metadata": {"collectors": ["ioc"], "hostname": "fixture", "tool_version": "1", "detection_context": {"ioc": context}},
                    "summary": {"total_finding_count": 1, "collector_coverage": {"ioc": 100}},
                    "findings": [{"finding_id": "IOC-FIXTURE", "severity": "High", "status": "Match"}]}
        current = json.loads(json.dumps(baseline))
        current["metadata"]["detection_context"]["ioc"]["fingerprint"] = "b" * 64
        current["findings"] = []
        current["summary"]["total_finding_count"] = 0
        self.assertTrue(detection_context_limits(baseline, current))
        result = compare_scan_payloads(baseline, current)
        self.assertIsNone(result["score_delta"])
        self.assertEqual(len(result["resolved"]), 1)
        changes = analyze_changes(baseline, current)
        self.assertIsNone(changes["counts"]["resolved_findings"])
        self.assertTrue(changes["comparison_context"]["limited"])
        current["metadata"].pop("detection_context")
        self.assertIn("unavailable", detection_context_limits(baseline, current)[0])

    def test_rule_context_changes_during_collection_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "pack.json"
            rule.write_text("{}", encoding="utf-8")

            class Collector:
                def __init__(self, runner):
                    self.directories = (root,)

                def collect(self):
                    rule.write_text('{"changed":true}', encoding="utf-8")
                    return []

            with patch.dict("macos_inspector.core.scan.COLLECTORS", {"ioc": Collector}, clear=True):
                result = run_scan(["ioc"], runner=object())
            self.assertFalse(result.metadata.detection_context["ioc"]["stable"])
            self.assertIn("Rule context", result.metadata.collection_errors[0])

    def test_response_history_preserves_identity_and_links_later_observations(self):
        action = {"action_id": "fixture-action", "scan_id": "fixture-source", "timestamp": "2026-01-01T00:00:00Z", "pid": 4242,
                  "uid": 501, "process_start": "Thu Jan 1 00:00:00 2026", "executable": "/synthetic/tool", "signal": "SIGTERM", "status": "signal_sent"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            append_response_event(root, action)
            append_response_event(root, {"event": "recheck", "action_id": action["action_id"], "scan_id": "later", "timestamp": "2026-01-01T00:02:00Z", "outcome": "not_observed", "explanation": "Synthetic observation"})
            history = read_response_history(root)
            self.assertEqual(history["actions"][0]["recheck"]["scan_id"], "later")
            self.assertEqual((root / "response-actions.jsonl").stat().st_mode & 0o777, 0o600)
            self.assertEqual(history["actions"][0]["process_start"], action["process_start"])

    def test_response_recheck_distinguishes_identity_reuse_exit_and_incomplete_snapshots(self):
        action, report, snapshot = response_fixture()
        self.assertEqual(evaluate_response_recheck(action, report)[0], "still_observed")
        snapshot["running_processes"][0]["process_start"] = "new-start"
        self.assertEqual(evaluate_response_recheck(action, report)[0], "pid_reused")
        snapshot["running_processes"] = [{**action, "zombie": True}]
        self.assertEqual(evaluate_response_recheck(action, report)[0], "zombie_observed")
        snapshot.update(process_count=0, running_processes=[])
        outcome, explanation = evaluate_response_recheck(action, report)
        self.assertEqual(outcome, "not_observed")
        self.assertIn("does not prove", explanation)
        snapshot["snapshot_truncated"] = True
        self.assertEqual(evaluate_response_recheck(action, report)[0], "unable_to_verify")
        self.assertEqual(evaluate_response_recheck({"pid": 4242}, report)[0], "unable_to_verify")

    def test_response_recheck_accepts_collector_observed_status_and_requires_absence_completeness(self):
        action, report, snapshot = response_fixture()
        report["findings"][0]["status"] = "Observed"
        self.assertEqual(evaluate_response_recheck(action, report)[0], "still_observed")
        snapshot.update(process_count=0, running_processes=[])
        self.assertEqual(evaluate_response_recheck(action, report)[0], "not_observed")
        for value in (None, False, 1, "true"):
            snapshot["inventory_complete"] = value
            self.assertEqual(evaluate_response_recheck(action, report)[0], "unable_to_verify")

    def test_live_process_inventory_records_parse_gaps_without_discarding_observations(self):
        from macos_inspector.core.runner import CommandResult

        class Runner:
            def __init__(self, output):
                self.output = output

            def run(self, argv):
                return CommandResult(tuple(argv), 0, self.output if argv[0] == "ps" and "uid=,user=,stat=,comm=" in argv[-1] else "", "")

        valid = "4242 1 501 fixture S /synthetic/tool\n"
        for output, expected in ((valid, True), (valid + "1 0 0 root S kernel_task\n", True), (valid + "unparsed row\n", False),
                                 (valid * 2, False), ("4242 1 fixture /synthetic/tool\n", False)):
            collector = LiveTriageCollector(Runner(output))
            finding = collector.collect()[0]
            self.assertEqual(finding.evidence[0].value["inventory_complete"], expected)
            self.assertEqual(bool(collector.collection_errors), not expected)
            self.assertTrue(finding.evidence[0].value["running_processes"])

    def test_response_recheck_rejects_invalid_chronology_host_and_ambiguous_inventory(self):
        action, report, snapshot = response_fixture()
        for field, value in (("started_at", "2025-12-31T23:59:00Z"), ("started_at", "2026-01-01T00:03:00Z"),
                             ("started_at", "2026-01-01T00:01:00"), ("completed_at", "invalid"),
                             ("hostname", "different-host")):
            changed = copy.deepcopy(report)
            changed["metadata"][field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(evaluate_response_recheck(action, changed)[0], "unable_to_verify")
        for value in (None, "2025-12-31T23:59:00Z", "2026-01-01T00:03:00Z", "2026-01-01T00:01:30"):
            changed = copy.deepcopy(report)
            changed["findings"][0]["evidence"][0]["collected_at"] = value
            self.assertEqual(evaluate_response_recheck(action, changed)[0], "unable_to_verify")
        for field, value in (("timestamp", None), ("timestamp", "invalid"), ("hostname", None),
                             ("pid", True), ("uid", True), ("executable", "relative"), ("process_start", {})):
            self.assertEqual(evaluate_response_recheck({**action, field: value}, report)[0], "unable_to_verify")
        snapshot["running_processes"].append(dict(action))
        self.assertEqual(evaluate_response_recheck(action, report)[0], "unable_to_verify")
        snapshot["running_processes"] = [{**action, "pid": True}]
        self.assertEqual(evaluate_response_recheck(action, report)[0], "unable_to_verify")
        for findings in (None, [None], report["findings"] * 2):
            self.assertEqual(evaluate_response_recheck(action, {**report, "findings": findings})[0], "unable_to_verify")

    def test_response_recheck_matches_executable_and_owner_without_claiming_restart(self):
        action, report, snapshot = response_fixture()
        snapshot["running_processes"] = [{**action, "pid": 5000, "process_start": "other-start"}]
        outcome, explanation = evaluate_response_recheck(action, report)
        self.assertEqual(outcome, "executable_observed")
        self.assertIn("5000", explanation)
        self.assertIn("existing instances or a restart", explanation)
        self.assertIn("does not establish identical file contents", explanation)
        snapshot["running_processes"][0]["uid"] = 502
        self.assertEqual(evaluate_response_recheck(action, report)[0], "not_observed")
        snapshot["running_processes"][0].update(uid=501, executable="/synthetic/other")
        self.assertEqual(evaluate_response_recheck(action, report)[0], "not_observed")
        snapshot["running_processes"][0]["executable"] = action["executable"]
        snapshot["snapshot_truncated"] = True
        self.assertEqual(evaluate_response_recheck(action, report)[0], "unable_to_verify")
        snapshot["snapshot_truncated"] = False
        report["metadata"]["collection_errors"] = ["live-triage: failed"]
        self.assertEqual(evaluate_response_recheck(action, report)[0], "unable_to_verify")
        report["metadata"]["collection_errors"] = []
        snapshot["running_processes"] = [{**action, "pid": 5000 + index} for index in range(8)]
        snapshot["process_count"] = 8
        self.assertIn("5000, 5001, 5002, 5003, 5004 and 3 more", evaluate_response_recheck(action, report)[1])

    def test_response_recheck_compares_timezone_offsets_as_instants(self):
        action, report, _ = response_fixture()
        action["timestamp"] = "2026-01-01T02:00:00+02:00"
        self.assertEqual(evaluate_response_recheck(action, report)[0], "still_observed")
        action["timestamp"] = "2026-01-01T00:30:00-02:00"
        self.assertEqual(evaluate_response_recheck(action, report)[0], "unable_to_verify")

    def test_response_recheck_job_requires_a_retained_action_and_exact_scope(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            state = DashboardState(Path(directory))
            with self.assertRaises(ValueError):
                state.create_job(["live-triage"], [], "High", response_action_id="missing")
            append_response_event(state.data_root, {"action_id": "fixture", "scan_id": "source", "timestamp": "2026-01-01T00:00:00Z", "pid": 4242, "signal": "SIGTERM", "status": "signal_sent", "executable": "/synthetic/tool"})
            with self.assertRaises(ValueError):
                state.create_job(["security"], [], "High", response_action_id="fixture")
            with patch("macos_inspector.web.threading.Thread"):
                job = state.create_job(["live-triage"], [], "High", response_action_id="fixture")
            self.assertEqual(job.minimum, "Informational")
            self.assertEqual(job.response_action_id, "fixture")

    def test_completed_response_recheck_persists_link_without_modifying_source_evidence(self):
        from macos_inspector.core.models import Evidence, ScanMetadata, ScanResult
        import threading
        action = {"action_id": "fixture", "scan_id": "source", "timestamp": "2026-01-01T00:00:00Z", "pid": 4242,
                  "uid": 501, "process_start": "fixture-start", "hostname": "fixture", "signal": "SIGTERM", "status": "signal_sent", "executable": "/synthetic/tool"}
        metadata = ScanMetadata("fixture", "later", "2026-01-01T00:01:00Z", "2026-01-01T00:02:00Z", "fixture", "fixture", "fixture", ("live-triage",))
        finding = Finding("LIVE-PROCESS-TREE", "Live Triage", "Synthetic snapshot", Severity.INFORMATIONAL, "Pass", "", "", "", "", "", "",
                          evidence=(Evidence("process_snapshot", "local", {"process_count": 0, "running_processes": [], "inventory_complete": True, "snapshot_truncated": False}, "2026-01-01T00:01:30Z"),))
        result = ScanResult(metadata, (finding,), 100, {})
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ):
            state = DashboardState(Path(directory))
            source = state.output / "macos-inspector-source.json"
            source.write_text('{"synthetic":"unchanged"}', encoding="utf-8")
            before = source.read_bytes()
            append_response_event(state.data_root, action)
            job = ScanJob("job", ["live-triage"], ["json"], "Informational", response_action_id="fixture")
            state.jobs[job.job_id] = job
            state.cancel_events[job.job_id] = threading.Event()
            with patch("macos_inspector.web.run_scan", return_value=result):
                state._execute(job)
            self.assertEqual(job.state, "completed")
            history = state.response_history()["actions"][0]
            self.assertEqual(history["recheck"]["scan_id"], "later")
            self.assertEqual(history["recheck"]["outcome"], "not_observed")
            self.assertEqual(source.read_bytes(), before)

    def test_response_history_is_bounded_and_handles_malformed_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(60):
                append_response_event(root, {"action_id": str(index), "scan_id": "source", "timestamp": f"2026-01-01T00:00:{index:02d}Z",
                    "pid": 4242, "signal": "SIGTERM", "status": "signal_sent", "executable": "/synthetic/tool"})
            append_response_event(root, {"status": "signal_sent", "pid": True})
            history = read_response_history(root)
            self.assertEqual(len(history["actions"]), 50)
            self.assertEqual(history["retained_action_count"], 60)
            self.assertIn("Malformed", history["limitations"][0])
            with patch("macos_inspector.core.response_history.MAX_RESPONSE_LOG_BYTES", 1):
                append_response_event(root, {"synthetic": "rotation"})
            self.assertTrue((root / "response-actions.previous.jsonl").is_file())

    def test_rule_fingerprint_rejects_nonregular_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "directory.json").mkdir()
            result = capture_rule_context("ioc", IOCCollector(object(), directories=(root,)))
            self.assertFalse(result["complete"])
            self.assertEqual(result["file_count"], 0)

    def test_setup_help_links_and_validation_scenarios_are_packaged(self):
        from html.parser import HTMLParser
        from scripts.build_release import release_files
        root = Path(__file__).resolve().parents[1]
        packaged = set(release_files())
        help_path = root / "docs/START_HERE.html"
        self.assertIn(help_path, packaged)
        self.assertIn(root / "src/macos_inspector/core/validation-scenarios.json", packaged)
        self.assertIn(root / "scripts/validate_detections.py", packaged)

        class Links(HTMLParser):
            def handle_starttag(parser, tag, attrs):
                for name, value in attrs:
                    if name == "href" and not value.startswith("https://"):
                        self.assertIn((help_path.parent / value).resolve(), packaged)

        Links().feed(help_path.read_text(encoding="utf-8"))


    @unittest.skipUnless(Path("/bin/zsh").is_file(), "Launcher requires zsh")
    def test_invalid_explicit_python_override_shows_setup_help_without_installing(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(["/bin/zsh", str(root / "macOS Inspector.command")], env={**os.environ,
            "MACOS_INSPECTOR_PORT": "65431", "MACOS_INSPECTOR_PYTHON": "/nonexistent/fixture-python",
            "MACOS_INSPECTOR_NO_OPEN": "1", "MACOS_INSPECTOR_NO_ALERT": "1"}, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("START_HERE.html", result.stderr)
        self.assertIn("No software was installed", result.stderr)


if __name__ == "__main__":
    unittest.main()
