import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from macos_inspector.collectors.yara_rules import YARARulesCollector
from macos_inspector.core.pdf_inspector import inspect_pdf, inspect_pdf_isolated, MAX_PDF_BYTES
from macos_inspector.core.runner import CommandResult
from macos_inspector.reporters.pdf_inspection_reporter import render_pdf_inspection
from macos_inspector.web import DashboardServer, DashboardState


def pdf_fixture(objects, trailer=b"/Root 1 0 R"):
    data = bytearray(b"%PDF-1.7\n")
    offsets = [0]
    for number, value in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f"{number} 0 obj\n".encode() + value + b"\nendobj\n")
    startxref = len(data)
    data.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        data.extend(f"{offset:010d} 00000 n \n".encode())
    data.extend(f"trailer\n<< /Size {len(offsets)} ".encode() + trailer + b" >>\n")
    data.extend(f"startxref\n{startxref}\n%%EOF\n".encode())
    return bytes(data)


def stream_fixture(dictionary, content):
    return b"<< /Length " + str(len(content)).encode() + b" " + dictionary + b" >>\nstream\n" + content + b"\nendstream"


class PDFInspectorTests(unittest.TestCase):
    def test_plain_pdf_is_not_given_a_safety_verdict(self):
        data = pdf_fixture([b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Count 0 /Kids [] >>"])
        report = inspect_pdf(data, "plain.pdf")
        self.assertEqual(report["assessment"]["label"], "No supported active features found")
        self.assertEqual(report["assessment"]["malware_verdict"], "Not determined")
        self.assertEqual(report["file"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["limitations"], [])
        self.assertEqual(report["actions"], [])
        self.assertIn("not establish", report["assessment"]["explanation"])

    def test_javascript_open_action_and_network_strings_are_static_evidence(self):
        data = pdf_fixture([b"<< /Type /Catalog /OpenAction 2 0 R >>",
                            rb"<< /S /JavaScript /JS (app.launchURL\('https://example.invalid/collect', true\);) >>"])
        report = inspect_pdf(data)
        self.assertEqual(report["assessment"]["label"], "Review features")
        self.assertTrue(any(row["type"] == "JavaScript" and row["trigger"] == "Document open" for row in report["actions"]))
        self.assertFalse(report["javascript"][0]["executed"])
        self.assertTrue(report["javascript"][0]["indicators"])
        self.assertEqual(report["destinations"][0]["value"], "https://example.invalid/collect")
        self.assertFalse(report["destinations"][0]["contacted"])

    def test_escaped_names_hex_strings_and_flate_script(self):
        script = b"this.submitForm({cURL:'https://example.invalid/form'});"
        data = pdf_fixture([b"<< /Type /Catalog /OpenAction 2 0 R >>",
                            b"<< /S /Java#53cript /#4AS 3 0 R >>", stream_fixture(b"/Filter /FlateDecode", zlib.compress(script))])
        report = inspect_pdf(data)
        self.assertEqual(report["javascript"][0]["preview"], script.decode())
        self.assertTrue(any(row["type"] == "JavaScript" for row in report["actions"]))
        data = pdf_fixture([b"<< /Type /Catalog /OpenAction << /S /JavaScript /JS <6170702e616c657274283129> >> >>"])
        self.assertEqual(inspect_pdf(data)["javascript"][0]["preview"], "app.alert(1)")

    def test_compressed_objects_expose_javascript(self):
        inner = rb"<< /S /JavaScript /JS (app.alert\(1\)) >>"
        body = b"3 0 " + inner
        data = pdf_fixture([b"<< /Type /Catalog /OpenAction 3 0 R >>",
                            stream_fixture(b"/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode", zlib.compress(body))])
        report = inspect_pdf(data)
        self.assertEqual(report["structure"]["compressed_object_count"], 1)
        self.assertEqual(report["javascript"][0]["preview"], "app.alert(1)")
        self.assertTrue(any(row["trigger"] == "Document open" for row in report["actions"]))

    def test_click_actions_are_not_claimed_to_run_on_open(self):
        data = pdf_fixture([b"<< /Type /Catalog >>", b"<< /Type /Annot /A << /S /URI /URI (https://example.invalid/) >> >>"])
        report = inspect_pdf(data)
        self.assertTrue(any(row["trigger"] == "Annotation or user interaction" for row in report["actions"]))
        self.assertFalse(any(row["trigger"] == "Document open" for row in report["actions"]))
        self.assertFalse(report["destinations"][0]["contacted"])

    def test_launch_form_attachment_and_nested_additional_actions(self):
        data = pdf_fixture([b"<< /Type /Catalog /AcroForm << /Fields [<< /AA << /K 2 0 R >> >>] >> >>",
                            b"<< /S /SubmitForm /F (https://example.invalid/submit) /Next 3 0 R >>",
                            b"<< /S /Launch /F (synthetic-program) >>", b"<< /Type /Filespec /F (attachment.bin) /EF << /F 5 0 R >> >>",
                            stream_fixture(b"/Type /EmbeddedFile", b"not executed")])
        report = inspect_pdf(data)
        self.assertTrue(any(row["type"] == "SubmitForm" and row["trigger"].startswith("Additional action /K") for row in report["actions"]))
        self.assertTrue(any(row["type"] == "Launch" and row["target"] == "synthetic-program" for row in report["actions"]))
        self.assertEqual(report["attachments"][0]["filename"], "attachment.bin")
        self.assertFalse(report["attachments"][0]["extracted"])

    def test_navigation_open_action_is_not_an_executable_feature(self):
        report = inspect_pdf(pdf_fixture([b"<< /Type /Catalog /OpenAction [2 0 R /Fit] >>", b"<< /Type /Page >>"]))
        self.assertEqual(report["actions"], [])
        self.assertEqual(report["assessment"]["label"], "No supported active features found")

    def test_document_javascript_names_are_registered_not_mistaken_for_clicked_links(self):
        report = inspect_pdf(pdf_fixture([b"<< /Type /Catalog /Names << /JavaScript 2 0 R >> >>", b"<< /Names [(startup) 3 0 R] >>", rb"<< /S /JavaScript /JS (app.alert\(1\)) >>"]))
        self.assertTrue(any("Document-level JavaScript" in row["trigger"] for row in report["actions"]))

    def test_encrypted_malformed_unsupported_and_bomb_streams_are_incomplete(self):
        encrypted = inspect_pdf(pdf_fixture([b"<< /Type /Catalog >>"], trailer=b"/Root 1 0 R /Encrypt 2 0 R"))
        self.assertTrue(encrypted["structure"]["encrypted_or_indicated"])
        self.assertEqual(encrypted["assessment"]["label"], "Analysis incomplete")
        for dictionary, raw in ((b"/Filter /LZWDecode", b"unreadable"), (b"/Filter /FlateDecode", b"invalid")):
            report = inspect_pdf(pdf_fixture([b"<< /Type /Catalog /OpenAction 2 0 R >>", b"<< /S /JavaScript /JS 3 0 R >>", stream_fixture(dictionary, raw)]))
            self.assertFalse(report["assessment"]["analysis_complete_within_supported_scope"])
            self.assertEqual(report["javascript"], [])
        with patch("macos_inspector.core.pdf_inspector.MAX_DECODED_STREAM", 100):
            report = inspect_pdf(pdf_fixture([b"<< /Type /Catalog >>", b"<< /S /JavaScript /JS 3 0 R >>", stream_fixture(b"/Filter /FlateDecode", zlib.compress(b"a" * 10000))]))
        self.assertTrue(any("limit" in value for value in report["limitations"]))
        broken = inspect_pdf(b"%PDF-1.7\n1 0 obj << /Type /Catalog")
        self.assertEqual(broken["assessment"]["label"], "Analysis incomplete")

    def test_cycles_missing_references_and_revisions_are_not_hidden(self):
        data = pdf_fixture([b"<< /Type /Catalog /OpenAction 2 0 R >>", b"<< /S /Launch /Next 2 0 R >>"])
        self.assertTrue(any("Cyclic" in item for item in inspect_pdf(data)["limitations"]))
        data = pdf_fixture([b"<< /Type /Catalog /OpenAction 99 0 R >>"])
        self.assertTrue(any("Unresolved" in item for item in inspect_pdf(data)["limitations"]))
        data = pdf_fixture([b"<< /Type /Catalog >>"]) + b"1 0 obj << /Type /Catalog >> endobj\nstartxref\n0\n%%EOF"
        self.assertFalse(inspect_pdf(data)["assessment"]["analysis_complete_within_supported_scope"])

    def test_strings_and_page_content_do_not_become_structural_javascript(self):
        data = pdf_fixture([b"<< /Type /Catalog /Title (text /JavaScript /JS /Launch) >>", stream_fixture(b"", b"/JS /JavaScript 77 0 obj << /S /Launch >> endobj")])
        report = inspect_pdf(data)
        self.assertEqual(report["name_counts"]["JS"], 0)
        self.assertEqual(report["name_counts"]["Launch"], 0)
        self.assertEqual(report["structure"]["object_count"], 2)

    def test_comments_and_trailer_strings_do_not_become_active_or_encrypted_objects(self):
        data = pdf_fixture([b"<< /Type /Catalog /Title (mentions /Encrypt) >>"], trailer=b"/Root 1 0 R /Custom (99 0 obj << /S /JavaScript /JS fake >> endobj)")
        data += b"\n% 88 0 obj << /S /Launch >> endobj\n"
        report = inspect_pdf(data)
        self.assertEqual(report["structure"]["object_count"], 1)
        self.assertFalse(report["structure"]["encrypted_or_indicated"])
        self.assertEqual(report["actions"], [])
        escaped = inspect_pdf(pdf_fixture([b"<< /Type /Catalog >>"], trailer=b"/Root 1 0 R /En#63rypt 2 0 R"))
        self.assertTrue(escaped["structure"]["encrypted_or_indicated"])

    def test_html_escapes_names_metadata_scripts_and_destinations(self):
        report = inspect_pdf(pdf_fixture([rb"<< /Type /Catalog /Title (<img src=x onerror=alert\(1\)>) /OpenAction << /S /JavaScript /JS (<script>alert\(1\)</script>) >> >>"]), "<svg onload=alert(1)>.pdf")
        html = render_pdf_inspection(report)
        self.assertNotIn("<svg", html)
        self.assertNotIn("<img", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("href=", html)
        self.assertIn("&lt;script&gt;", html)

    def test_worker_is_real_and_timeout_invalid_size_and_header_are_rejected(self):
        data = pdf_fixture([b"<< /Type /Catalog >>"])
        self.assertEqual(inspect_pdf_isolated(data, "worker.pdf")["file"]["name"], "worker.pdf")
        for invalid in (b"", b"not a pdf"):
            with self.assertRaises(ValueError):
                inspect_pdf(invalid)
        with patch("macos_inspector.core.pdf_inspector.MAX_PDF_BYTES", 1):
            with self.assertRaises(ValueError):
                inspect_pdf(data)
        with patch("macos_inspector.core.pdf_inspector.subprocess.run", side_effect=subprocess.TimeoutExpired("fixture", 20)):
            with self.assertRaisesRegex(ValueError, "20-second"):
                inspect_pdf_isolated(data)

    def test_yara_failed_commands_never_report_pass_without_stderr(self):
        class Runner:
            def run(self, argv):
                return CommandResult(tuple(argv), returncode, "UnverifiedLine fixture\n", "", timed_out)
        for returncode, timed_out in ((2, False), (1, False), (-9, False), (0, True), (127, False)):
            with patch("macos_inspector.collectors.yara_rules.discover_yara_rules", return_value=([Path("fixture.yar")], [])), patch("macos_inspector.collectors.yara_rules._targets", return_value=([Path("fixture")], [])):
                result = YARARulesCollector(Runner(), settings={"yara": {"enabled": True, "targets": ["fixture"]}}).collect()[0]
            self.assertEqual(result.status, "Unknown")
            self.assertEqual(result.evidence[0].value["matches"], [])
            self.assertTrue(result.evidence[0].value["errors"])

    def test_yara_errors_limit_scan_coverage_and_rule_bounds_are_explicit(self):
        from macos_inspector.core.scan import run_scan
        from macos_inspector.collectors.yara_rules import discover_yara_rules
        class Runner:
            def run(self, argv):
                return CommandResult(tuple(argv), 2, "", "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = root / "fixture.yar"
            rule.write_text("rule Fixture { condition: true }")
            factory = lambda runner: YARARulesCollector(runner, settings={"yara": {"enabled": True, "targets": [str(rule)]}}, rules_directory=root)
            with patch("macos_inspector.core.scan.COLLECTORS", {"yara-rules": factory}):
                result = run_scan(("yara-rules",), runner=Runner())
            self.assertTrue(result.metadata.collection_errors)
            self.assertLess(result.collector_coverage["yara-rules"], 100)
            with patch("macos_inspector.collectors.yara_rules.MAX_RULE_FILES", 0):
                _, errors = discover_yara_rules(root)
            self.assertTrue(any("not inspected" in item for item in errors))


class SessionAndUploadTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = DashboardState(Path(self.directory.name))
        self.server = DashboardServer(("127.0.0.1", 0), self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.directory.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=25)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_launch_credential_cookie_and_server_lifecycle(self):
        status, _, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(set(json.loads(body)), {"status", "version", "session_required"})
        for method, path in (("GET", "/api/settings"), ("GET", "/api/scans"), ("GET", "/reports/macos-inspector-private.json"), ("POST", "/api/processes/terminate"), ("DELETE", "/api/yara-rules/fixture.yar")):
            self.assertEqual(self.request(method, path, headers={"X-MacOS-Inspector": "1"})[0], 401)
        headers = {"Content-Type": "application/json", "X-MacOS-Inspector": "1"}
        self.assertEqual(self.request("POST", "/api/session", json.dumps({"token": "wrong"}), headers)[0], 403)
        status, response_headers, body = self.request("POST", "/api/session", json.dumps({"token": self.server.launch_secret}), headers)
        self.assertEqual(status, 200)
        cookie = response_headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(json.loads(body)["api_token"], self.server.session_secret)
        self.assertNotEqual(self.server.report_secret, self.server.session_secret)
        self.assertEqual(self.request("GET", "/api/config", headers={"Cookie": cookie.split(";", 1)[0]})[0], 401)
        self.assertEqual(self.request("GET", "/api/config", headers={"Authorization": "Bearer " + self.server.session_secret})[0], 200)
        self.assertEqual(self.request("GET", "/api/config", headers={"Cookie": f"{self.server.cookie_name}=expired"})[0], 401)
        self.assertEqual(self.server.session_path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.server.launch_secret.encode(), self.request("GET", "/")[2])
        self.server.server_close()
        self.assertFalse(self.server.session_path.exists())

    def test_private_browser_handoff_does_not_place_credentials_in_process_arguments(self):
        from macos_inspector.web import _open_private_dashboard_url
        url = "http://127.0.0.1:12345/#launch=synthetic-private-capability"
        with patch("macos_inspector.web.sys.platform", "darwin"), patch("macos_inspector.web.subprocess.run") as launch:
            _open_private_dashboard_url(url)
        self.assertEqual(launch.call_args.args[0], ["/usr/bin/osascript", "-"])
        self.assertNotIn("synthetic-private-capability", str(launch.call_args.args))
        self.assertIn(url, launch.call_args.kwargs["input"])

    def test_local_dashboard_binding_never_performs_reverse_dns(self):
        with tempfile.TemporaryDirectory() as directory, patch("socket.getfqdn", side_effect=AssertionError("Loopback startup must not perform DNS lookup")):
            server = DashboardServer(("127.0.0.1", 0), DashboardState(Path(directory)))
            try:
                self.assertEqual(server.server_name, "127.0.0.1")
                self.assertEqual(server.server_port, server.server_address[1])
                self.assertTrue(server.session_path.exists())
            finally:
                server.server_close()

    def test_audit_and_pdf_pages_have_separate_markup_scripts_and_return_links(self):
        for path in ("/", "/index.html"):
            status, _, body = self.request("GET", path)
            self.assertEqual(status, 200)
            self.assertIn(b'id="collectors"', body)
            self.assertIn(b'href="pdf-inspector.html"', body)
            self.assertIn(b'src="app.js"', body)
            self.assertIn(b'src="dashboard-common.js"', body)
            self.assertNotIn(b'id="pdf-file"', body)
            self.assertNotIn(b'src="pdf-inspector.js"', body)
        status, _, body = self.request("GET", "/pdf-inspector.html")
        self.assertEqual(status, 200)
        self.assertIn(b'Back to Mac audit', body)
        self.assertIn(b'href="index.html"', body)
        self.assertIn(b'id="pdf-file"', body)
        self.assertIn(b'src="pdf-inspector.js"', body)
        self.assertIn(b'src="dashboard-common.js"', body)
        for marker in (b'id="collectors"', b'id="history"', b'id="response-history-list"', b'src="app.js"'):
            self.assertNotIn(marker, body)
        self.assertNotIn(self.server.launch_secret.encode(), body)
        self.assertEqual(self.request("GET", "/dashboard-common.js")[0], 200)

    def test_authenticated_upload_reports_private_history_and_invalid_input(self):
        data = pdf_fixture([b"<< /Type /Catalog >>"])
        headers = {"Authorization": "Bearer " + self.server.session_secret, "Content-Type": "application/pdf", "X-MacOS-Inspector": "1", "X-PDF-Filename": "example.pdf"}
        self.assertEqual(self.request("POST", "/api/pdf-inspector", data)[0], 401)
        self.assertEqual(self.request("POST", "/api/pdf-inspector", data, {**headers, "Content-Type": "application/json"})[0], 403)
        self.assertEqual(self.request("POST", "/api/pdf-inspector", b"", {**headers, "Content-Length": str(MAX_PDF_BYTES + 1)})[0], 400)
        self.assertEqual(self.request("POST", "/api/pdf-inspector", data, {**headers, "Transfer-Encoding": "chunked"})[0], 400)
        self.assertEqual(self.request("POST", "/api/pdf-inspector", b"invalid", headers)[0], 400)
        status, _, body = self.request("POST", "/api/pdf-inspector", data, headers)
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(payload["report"]["file"]["sha256"], hashlib.sha256(data).hexdigest())
        for url in payload["reports"].values():
            self.assertEqual(self.request("GET", url)[0], 401)
            self.assertEqual(self.request("GET", url, headers=headers)[0], 200)
            self.assertEqual((self.state.output / url.split("/")[-1]).stat().st_mode & 0o777, 0o600)
            cookie_headers = {"Cookie": f"{self.server.cookie_name}={self.server.report_secret}"}
            self.assertEqual(self.request("GET", url, headers=cookie_headers)[0], 200)
            self.assertEqual(self.request("GET", "/api/config", headers=cookie_headers)[0], 401)
        self.assertFalse(list(self.state.output.glob("*.pdf")))
        self.assertEqual(self.state.list_jobs(), [])
        self.assertEqual(len(self.state.pdf_history()), 1)
        self.state.pdf_slot.acquire()
        try:
            self.assertEqual(self.request("POST", "/api/pdf-inspector", data, headers)[0], 409)
        finally:
            self.state.pdf_slot.release()

    @unittest.skipUnless(Path("/bin/zsh").is_file(), "Portable launcher requires zsh")
    def test_extracted_portable_launcher_pdf_worker_and_graceful_cleanup(self):
        from scripts.build_release import build_release
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = build_release(root / "candidate.zip")
            with zipfile.ZipFile(archive) as handle:
                handle.extractall(root / "package")
            package = next((root / "package").iterdir())
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            output = root / "private-reports"
            state = root / "launcher-state"
            process = subprocess.Popen(["/bin/zsh", str(package / "macOS Inspector.command")], env={**os.environ,
                "PYTHONPATH": "", "MACOS_INSPECTOR_PORT": str(port), "MACOS_INSPECTOR_PYTHON": sys.executable,
                "MACOS_INSPECTOR_OUTPUT": str(output), "MACOS_INSPECTOR_STATE_DIR": str(state),
                "MACOS_INSPECTOR_NO_OPEN": "1", "MACOS_INSPECTOR_NO_ALERT": "1"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            origin = f"http://127.0.0.1:{port}"
            session_path = output / f".macos-inspector-session-{port}.json"
            try:
                deadline = time.monotonic() + 15
                while not session_path.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        self.fail("Extracted portable launcher did not start.")
                    time.sleep(0.05)
                import urllib.parse
                token = urllib.parse.parse_qs(urllib.parse.urlparse(json.loads(session_path.read_text())["url"]).fragment)["launch"][0]
                request = urllib.request.Request(origin + "/api/session", data=json.dumps({"token": token}).encode(), headers={"Content-Type": "application/json", "X-MacOS-Inspector": "1"})
                with urllib.request.urlopen(request, timeout=5) as response:
                    api_token = json.load(response)["api_token"]
                request = urllib.request.Request(origin + "/api/pdf-inspector", data=pdf_fixture([b"<< /Type /Catalog >>"]), headers={"Content-Type": "application/pdf", "X-MacOS-Inspector": "1", "Authorization": "Bearer " + api_token})
                with urllib.request.urlopen(request, timeout=25) as response:
                    payload = json.load(response)
                self.assertEqual(payload["report"]["assessment"]["label"], "No supported active features found")
                self.assertTrue(list(output.glob("macos-inspector-pdf-*.html")))
            finally:
                process.terminate()
                stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertNotIn(token.encode(), stdout + stderr)
            self.assertFalse(session_path.exists())
            self.assertFalse((state / f"dashboard-{port}.pid").exists())


if __name__ == "__main__":
    unittest.main()
