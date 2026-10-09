import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from macos_inspector.collectors.browser_extensions import chromium_extensions, firefox_extensions, safari_legacy_extensions
from macos_inspector.collectors.browser_artifacts import BrowserArtifactsCollector
from macos_inspector.core.decision_support import build_decision_support, write_investigation_summary
from macos_inspector.core.models import ScanMetadata, ScanResult, Severity
from macos_inspector.reporters.html_reporter import write_html
from macos_inspector.reporters.browser_extension_reporter import render_browser_extension_report


class BrowserExtensionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def manifest(self, version="1.0", identifier="exampleextension", **fields):
        path = self.root / "Extensions" / identifier / version / "manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"manifest_version": 3, "name": "Example extension", "version": version.split("_")[0], **fields}))
        return path

    def test_required_optional_and_content_scripts_remain_distinct(self):
        path = self.manifest(permissions=["cookies", "nativeMessaging", "tabs", "activeTab"], host_permissions=["https://example.invalid/*"],
                             optional_permissions=["clipboardRead"], optional_host_permissions=["<all_urls>"],
                             content_scripts=[{"matches": ["https://*/*"], "exclude_matches": ["https://private.invalid/*"], "include_globs": ["*allowed*"], "exclude_globs": ["*private*"]}])
        before = path.read_bytes()
        rows, error = chromium_extensions(self.root / "Extensions")
        self.assertIsNone(error)
        self.assertEqual(path.read_bytes(), before)
        self.assertIsNone(rows[0]["active"])
        analysis = rows[0]["permission_analysis"]
        self.assertTrue(analysis["complete"])
        self.assertEqual(analysis["source_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(analysis["required"]["api_permissions"], ["cookies", "nativeMessaging", "tabs", "activeTab"])
        self.assertEqual(analysis["optional"]["api_permissions"], ["clipboardRead"])
        self.assertEqual(analysis["required"]["content_script_exclusions"], ["https://private.invalid/*"])
        self.assertEqual(analysis["required"]["content_script_include_globs"], ["*allowed*"])
        self.assertEqual(analysis["required"]["content_script_exclude_globs"], ["*private*"])
        features = {(row["key"], row["scope"]) for row in analysis["features"]}
        self.assertIn(("clipboardRead", "Optional declaration"), features)
        self.assertNotIn(("clipboardRead", "Declared requirement"), features)
        self.assertIn(("broad_sites", "Declared requirement"), features)
        self.assertIn(("broad_sites", "Optional declaration"), features)
        self.assertIn("not confirmed grants", analysis["boundary"])

    def test_numeric_version_selection_does_not_claim_active_version(self):
        self.manifest("1.9", permissions=["cookies"])
        self.manifest("1.10_0", permissions=["history"])
        rows, error = chromium_extensions(self.root / "Extensions")
        self.assertIsNone(error)
        self.assertEqual(rows[0]["version"], "1.10")
        self.assertEqual(rows[0]["version_directory"], "1.10_0")
        self.assertEqual(rows[0]["observed_version_directories"], 2)
        self.assertEqual(rows[0]["permission_analysis"]["required"]["api_permissions"], ["history"])
        self.assertIn("not confirmed active version", rows[0]["permission_analysis"]["source"])

    def test_mv2_host_permissions_and_narrow_patterns(self):
        self.manifest(manifest_version=2, permissions=["cookies", "*://*.example.invalid/*", "file:///*"])
        rows, error = chromium_extensions(self.root / "Extensions")
        self.assertIsNone(error)
        analysis = rows[0]["permission_analysis"]
        self.assertEqual(analysis["required"]["api_permissions"], ["cookies"])
        self.assertNotIn("broad_sites", [row["key"] for row in analysis["features"]])
        self.assertIn("file_urls", [row["key"] for row in analysis["features"]])

    def test_invalid_null_and_oversized_manifests_are_explicitly_limited(self):
        path = self.manifest(permissions=None)
        rows, error = chromium_extensions(self.root / "Extensions")
        self.assertFalse(rows[0]["permission_analysis"]["complete"])
        self.assertTrue(error)
        self.assertIn("malformed", " ".join(rows[0]["permission_analysis"]["limitations"]))
        for raw in (b"not json", b"[]", b'{"manifest_version":4}', b"[" * 1500 + b"]" * 1500):
            path.write_bytes(raw)
            rows, error = chromium_extensions(self.root / "Extensions")
            self.assertFalse(rows[0]["permission_analysis"]["complete"])
            self.assertTrue(error)
        self.manifest()
        with patch("macos_inspector.collectors.browser_extensions.MAX_MANIFEST_BYTES", 1):
            rows, error = chromium_extensions(self.root / "Extensions")
        self.assertTrue(error)
        self.assertFalse(rows[0]["permission_analysis"]["complete"])

    def test_malformed_unicode_does_not_break_report_encoding(self):
        self.manifest(name="bad\ud800label", permissions=["cookies", "bad\ud800permission"])
        rows, error = chromium_extensions(self.root / "Extensions")
        self.assertTrue(error)
        self.assertFalse(rows[0]["permission_analysis"]["complete"])
        self.assertEqual(rows[0]["permission_analysis"]["required"]["api_permissions"], ["cookies"])
        json.dumps(rows, ensure_ascii=False).encode("utf-8")

    def test_symlinks_and_missing_manifests_are_not_silently_clean(self):
        source = self.manifest()
        source.unlink()
        external = self.root / "private.json"
        external.write_text('{"manifest_version":3,"permissions":["cookies"]}')
        source.symlink_to(external)
        rows, error = chromium_extensions(self.root / "Extensions")
        self.assertTrue(error)
        self.assertFalse(rows[0]["permission_analysis"]["complete"])
        self.assertEqual(rows[0]["permission_analysis"]["features"], [])
        (self.root / "linked").symlink_to(self.root / "Extensions", target_is_directory=True)
        rows, error = chromium_extensions(self.root / "linked")
        self.assertEqual(rows, [])
        self.assertIn("symlinked", error)

    def test_inventory_permission_and_output_bounds_are_disclosed(self):
        self.manifest(identifier="a", permissions=["cookies", "history", 1])
        self.manifest(identifier="b")
        with patch("macos_inspector.collectors.browser_extensions.MAX_EXTENSIONS", 1):
            rows, error = chromium_extensions(self.root / "Extensions")
        self.assertEqual(len(rows), 1)
        self.assertIn("limit", error)
        self.assertFalse(rows[0]["permission_analysis"]["complete"])
        with patch("macos_inspector.collectors.browser_extensions.MAX_PERMISSION_ENTRIES", 1):
            rows, error = chromium_extensions(self.root / "Extensions")
        self.assertTrue(error)
        self.assertEqual(rows[0]["permission_analysis"]["required"]["api_permissions"], ["cookies"])
        with patch("macos_inspector.collectors.browser_extensions.MAX_PERMISSION_RECORD_BYTES", 1):
            rows, error = chromium_extensions(self.root / "Extensions")
        self.assertIn("size limit", error)
        self.assertEqual(rows[0]["permission_analysis"]["features"], [])
        with patch("macos_inspector.collectors.browser_extensions.MAX_PROFILE_PERMISSION_BYTES", 1):
            rows, error = chromium_extensions(self.root / "Extensions")
        self.assertEqual(rows, [])
        self.assertIn("omitted", error)
        with patch("macos_inspector.collectors.browser_extensions.os.scandir", side_effect=PermissionError):
            rows, error = chromium_extensions(self.root / "Extensions")
        self.assertEqual(rows, [])
        self.assertIn("could not", error)

    def test_firefox_requirements_and_recorded_disabled_state(self):
        addon = {"id": "example@extension.invalid", "version": "2.0", "type": "extension", "active": False,
                 "defaultLocale": {"name": "Example addon"}, "userPermissions": {"permissions": ["nativeMessaging"], "origins": ["https://example.invalid/*"]},
                 "optionalPermissions": {"permissions": ["cookies"], "origins": ["<all_urls>"]}}
        path = self.root / "extensions.json"
        path.write_text(json.dumps({"addons": [addon]}))
        before = path.read_bytes()
        rows, error = firefox_extensions(path)
        self.assertIsNone(error)
        self.assertFalse(rows[0]["active"])
        self.assertEqual(rows[0]["name"], "Example addon")
        self.assertTrue(rows[0]["permission_analysis"]["complete"])
        self.assertEqual(path.read_bytes(), before)
        optional = [row for row in rows[0]["permission_analysis"]["features"] if row["scope"] == "Optional declaration"]
        self.assertIn("cookies", [row["key"] for row in optional])
        self.assertIn("not dynamic permission grants", rows[0]["permission_analysis"]["source"])
        del addon["optionalPermissions"]
        path.write_text(json.dumps({"addons": [addon]}))
        rows, error = firefox_extensions(path)
        self.assertTrue(error)
        self.assertFalse(rows[0]["permission_analysis"]["optional"]["available"])

    def test_firefox_malformed_and_safari_unsupported_are_explicit(self):
        path = self.root / "extensions.json"
        for raw in ('[]', '{"addons":{}}', 'not json'):
            path.write_text(raw)
            self.assertTrue(firefox_extensions(path)[1])
        path.write_text('{"addons":[]}')
        with patch("macos_inspector.collectors.browser_extensions.MAX_ADDON_METADATA_BYTES", 1):
            self.assertTrue(firefox_extensions(path)[1])
        rows, error = safari_legacy_extensions(self.root / "Safari/Extensions")
        self.assertEqual(rows, [])
        self.assertIn("not assessed", error)

    def test_collector_keeps_low_review_priority_and_propagates_limits(self):
        home = self.root / "home"
        profile = home / "Library/Application Support/Google/Chrome/Default"
        profile.mkdir(parents=True)
        with sqlite3.connect(profile / "History") as connection:
            connection.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
            connection.execute("CREATE TABLE downloads (target_path TEXT, tab_url TEXT, start_time INTEGER, state INTEGER, danger_type INTEGER)")
        path = profile / "Extensions/example/1.0/manifest.json"
        path.parent.mkdir(parents=True)
        path.write_text('{"manifest_version":3,"name":"Example","version":"1.0","host_permissions":["<all_urls>"],"optional_permissions":["cookies"]}')
        collector = BrowserArtifactsCollector(object(), home)
        finding = collector.collect()[0]
        self.assertEqual(finding.status, "Review")
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertIn("not proof", finding.observed_result)
        self.assertEqual(collector.collection_errors, [])
        path.unlink()
        collector.collect()
        self.assertTrue(collector.collection_errors)
        # Exercise both export integration points, not only the section renderer.
        path.write_text('{"manifest_version":3,"name":"Example","version":"1.0","permissions":["cookies"]}')
        findings = tuple(collector.collect())
        metadata = ScanMetadata("fixture", "extension-export", "2026-10-09T10:00:00Z", "2026-10-09T10:01:00Z", "fixture-host", "macOS", "fixture-user", ("browser-artifacts",))
        result = ScanResult(metadata, findings, 90, {"Browser Artifacts": 90}, {"Browser Artifacts": 100})
        html_path = self.root / "exports/report.html"
        write_html(result, html_path)
        self.assertIn("Browser extension permissions", html_path.read_text())
        self.assertIn("Cookie access", html_path.read_text())
        report = result.to_dict()
        summary_path = write_investigation_summary(report, build_decision_support(report), self.root / "exports")
        self.assertIn("Browser extension permissions", summary_path.read_text())
        self.assertIn("Cookie access", summary_path.read_text())

    def test_export_escaping_and_legacy_permission_limits(self):
        self.manifest(name="<script>alert(1)</script>", optional_permissions=["cookies"], host_permissions=["https://example.invalid/" + "x" * 300])
        rows, _ = chromium_extensions(self.root / "Extensions")
        findings = [{"finding_id": "BROWSER-EXAMPLE", "evidence": [{"kind": "browser_profile", "value": {"browser": "Chrome", "profile": "Default", "extensions": rows, "collection_notes": []}}]}]
        before = copy.deepcopy(findings)
        html = render_browser_extension_report(findings)
        self.assertEqual(findings, before)
        self.assertNotIn("<script>", html)
        self.assertNotIn("href=", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Optional declaration", html)
        findings[0]["evidence"][0]["value"]["extensions"] = [{"id": "legacy", "version": "1"}]
        html = render_browser_extension_report(findings)
        self.assertIn("Permission analysis limited", html)
        self.assertIn("not established", html)
