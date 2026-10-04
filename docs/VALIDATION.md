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

The development set has 26 scenarios (the published 1.4.3 set has 18):

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

Development checks also exercise rule-context disclosure in both views and the standalone investigation summary, including narrow layouts, escaped pack names, keyboard-accessible details, skipped YARA results, missing context, and isolation between report identities. Unit tests check typed fingerprint states, bounded provenance, removal of source URL credentials from the derived summary, and preservation of original evidence.

Playwright WebKit is not branded Safari. This coverage does not claim every shipping Safari version, VoiceOver interaction, operating-system integration, or accessibility requirement was manually tested. Changes affecting those workflows still need dedicated testing on representative Macs. See [Playwright browser documentation](https://playwright.dev/docs/browsers#webkit) for its browser boundary.

## Release checks

Before publishing, run the unit suite, browser suite, synthetic validation, syntax and compile checks, documentation link checks, a deterministic package rebuild, extracted-package startup, Git integrity checks, and a privacy review. GitHub CI repeats Linux/macOS tests and both browser engines before packaging. Apple signing/notarization and an independent real-world detection evaluation are not provided by these checks.
