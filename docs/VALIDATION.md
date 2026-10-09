# Detection and browser validation

This project separates regression validation from real-world security effectiveness. A passing test proves only that its declared input produced the expected output. It does not establish that all malware, unauthorized applications, or suspicious behavior can be detected.

## Run from the dashboard

1. Open the local dashboard through the double-click launcher.
2. Expand **Detection regression validation** below scan history.
3. Select **Run detection validation**.
4. Review the total, failed scenarios, and expected versus observed outcomes.
5. Use **Download validation JSON** to preserve the result.

This action does not scan your Mac, invoke host commands, signal processes, or contact an online provider. It uses the bundled fictional scenarios and the same classification functions as the product. It does not change findings, investigation status, or local settings.

## Reproduce from a checkout or portable release

```bash
PYTHONPATH=src python3 -m scripts.validate_detections
PYTHONPATH=src python3 -m scripts.validate_detections --output ./validation.json
```

The optional output is written with owner-only permissions. The report includes the tool version, fixture SHA-256, individual expected/observed outcomes, total pass/fail counts, unexpected alerts in declared passing cases, and missed review outcomes in declared review cases. A failed scenario makes the command exit with status 1.

## Bundled scenarios

The 1.4.4 set has 26 scenarios (1.4.3 has 18):

- Accepted Developer ID and Mac App Store trust results, and an Apple component that Gatekeeper cannot assess as a standalone app.
- Signature timeout, unavailable Gatekeeper, and internal trust-service error, which must remain unknown.
- Disallowed extended metadata on an otherwise accepted app, a missing sealed resource, an unsigned executable, Gatekeeper rejection, ad-hoc identity, and a missing declared executable.
- The same process still observed after an action, PID reuse, zombie state, original PID absent from an untruncated snapshot, truncated inventory, and a legacy snapshot without start identity.
- The same executable under another PID, a different numeric owner, a prior or overlapping scan, mismatched host context, missing timezone or process-evidence timestamp, and duplicate PIDs.

The result counts are descriptive for this small synthetic set. Zero unexpected alerts and zero missed review outcomes here are not estimates of real-world false-positive or false-negative rates. These cases do not cover all collector behavior, all macOS releases, races, malformed operating-system outputs, or adversarial evasion. The broader unit suite tests additional parsers, privacy boundaries, report output, comparison gaps, and process authorization.

## Browser and accessibility checks

```bash
npm ci
npx playwright install chromium webkit
npm run test:browser
```

The same dashboard tests run in Chromium and Playwright WebKit. They cover both views, narrow layouts, long evidence values, HTML escaping, snapshot freshness, scope-preserving rechecks, response follow-up, and validation downloads. Targeted axe-core checks exercise WCAG A/AA rules and keyboard focus in synthetic dashboard states.

Checks also exercise rule-context disclosure in both views and the standalone investigation summary, including narrow layouts, escaped pack names, keyboard-accessible details, skipped YARA results, missing context, and isolation between report identities. Delayed-response tests cover report selection, mismatched decision support, blocked process response during loading, and investigation saves tied to the original report. Unit tests check typed fingerprint states, bounded provenance, removal of source URL credentials from the derived summary, and preservation of original evidence.

Playwright WebKit is not branded Safari. This coverage does not claim every shipping Safari version, VoiceOver interaction, operating-system integration, or accessibility requirement was manually tested. Changes affecting those workflows still need dedicated testing on representative Macs. See [Playwright browser documentation](https://playwright.dev/docs/browsers#webkit) for its browser boundary.

## Release checks

The 2.0.0 PDF fixtures cover ordinary documents, JavaScript open actions, document-level script name trees, escaped names, hex strings, Flate script streams, compressed objects, click-only URI actions, nested additional actions, form submission, launch targets, and attachment references. Negative and limit cases cover encryption, missing EOF/object terminators, unsupported/corrupt stream filters, decoded-size bounds, cycles, unresolved references, repeated revisions, page-content strings that are not structural actions, and escaped HTML output. A real worker and authenticated upload endpoint are exercised without executing document content. Session tests cover unauthenticated reads/writes, private report access, report-cookie/API credential separation, stale credentials, and private launch-file cleanup. YARA regression fixtures include failed commands with empty stderr.

Browser fixtures cover explicit PDF upload, busy controls, empty/oversized input, stale-result hiding after errors, escaped scripts/metadata, non-clickable destinations, layouts at 320/375/768/1280 pixels, targeted accessibility, launch-fragment cleanup, and same-origin API credentials. Page-isolation tests verify that PDF entry does not load audit code, Mac inventory, or audit history, reciprocal links and browser back/forward navigate separate documents, clearing removes displayed evidence, and reduced-motion settings disable animations. Real authenticated uploads, report access, and saved PDF history after returning from the audit page are exercised in both engines. These fixtures do not establish malware-detection accuracy or comprehensive resistance to hostile PDFs. Independent parser review and representative real-world document testing remain necessary.

Before publishing, run the unit suite, browser suite, synthetic validation, syntax and compile checks, documentation link checks, a deterministic package rebuild, extracted-package startup, Git integrity checks, and a privacy review. GitHub CI repeats Linux/macOS tests and both browser engines before packaging. Apple signing/notarization and an independent real-world detection evaluation are not provided by these checks.

### 2.1.0 sharing-copy coverage

Additional fixtures check that PDF sharing summaries use an explicit allowlist and do not copy private filenames, metadata, destinations, script contents/hashes, timestamps, raw diagnostics, custom action names, or future report fields. Document SHA-256 requires a strict boolean opt-in. Original files and source report objects remain unchanged. Invalid, oversized, symlinked, missing, or unauthenticated reports are rejected. JSON request framing rejects duplicate lengths, transfer-encoding conflicts, and incomplete bodies.

Both browser engines test real authenticated preview requests, exact JSON downloads, HTML downloads without active or external content, hash opt-in, four display widths, and targeted accessibility checks. Delayed-response fixtures verify that changing the file or hash option invalidates the earlier preview. Parser fixtures distinguish catalog OpenAction chains from entries outside a catalog. This coverage does not validate final PDF revision reachability, prove anonymization, or establish malware-detection accuracy.

### 2.1.0 extension-permission coverage

Fictional Chromium and Firefox profiles exercise required/optional separation, content-script exclusions and glob restrictions, numeric version selection, recorded disabled state, unsupported Safari coverage, malformed/null/schema failures, symlinks, unreadable sources, and input/list/output bounds. Integration fixtures preserve source bytes, retain low review priority, propagate collection limits, and include permission explanations in full HTML and investigation exports. Both browser engines test escaped extension names and patterns, old reports without permission evidence, both audit views, four widths, targeted accessibility, and clearing the panel when another snapshot has no browser evidence. These tests do not establish effective runtime grants or compatibility with every shipping browser.
