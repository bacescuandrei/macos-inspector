# Contributing

Open an issue before starting a large feature or changing a public report schema. Small bug fixes and documentation corrections can be submitted directly.

## Contributor workflow

1. Fork the repository and create a focused branch from `main`.
2. Explain the analyst problem and the proposed evidence source before a large change.
3. Keep each commit limited to one logical change.
4. Add or update tests, public documentation, and the changelog when behavior changes.
5. Run the local verification commands below.
6. Open a pull request using the repository template and describe macOS-specific validation separately from portable tests.

Do not include generated reports, case data, host identifiers, browser records, private keys, provider credentials, local settings, or other personal evidence in issues, tests, commits, or pull requests. Use synthetic fixtures with clearly fictional values.

## Collector contract

Every collector must be read-only, deterministic where the operating system permits, and useful when run without elevated privileges.

A finding must contain a stable ID, category, severity, status, explanation, expected and observed results, recommendation, evidence, and the commands used. Use `CommandRunner`; never use `shell=True`, `sudo`, package installation, network access, or commands that change configuration. Treat unknown and inaccessible states as informational evidence rather than silently assuming compliance.

Add unit tests for parsing and evaluation logic. Tests must run on non-macOS hosts by injecting a fake runner or testing pure functions.

New online providers require an explicit privacy boundary, a bounded request and response size, TLS validation, schema validation, provenance recording, predictable timeout behavior, and tests for malformed or unavailable responses. Do not add telemetry or automatic evidence upload.

UI changes must remain usable at 320 CSS pixels, keep long evidence inside its container, support keyboard focus, respect reduced-motion preferences, and remain English-only.

## Local verification

Run the unit tests and JavaScript syntax check before opening a pull request:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
node --check src/macos_inspector/webui/app.js
PYTHONPATH=src python3 -m scripts.build_release
```

The dashboard is intentionally local-only and must not expose arbitrary command execution. New UI actions must call a registered collector through `core.scan.run_scan`, preserve collection errors, and keep report files owner-readable only.

Review [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/THREAT_MODEL.md), [Usage and interpretation](docs/USAGE.md), and [Security policy](SECURITY.md) before changing a security boundary.
