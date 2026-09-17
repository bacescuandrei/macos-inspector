# Contributing

Open an issue before starting a large feature or changing a public report schema. Small bug fixes and documentation corrections can be submitted directly.

Create a focused branch, keep commits limited to one logical change, and explain the analyst problem in the pull request. Do not include generated reports, case data, private keys, provider credentials, or local settings.

Every collector must be read-only, deterministic where the operating system permits, and useful when run without elevated privileges.

A finding must contain a stable ID, category, severity, status, explanation, expected and observed results, recommendation, evidence, and the commands used. Use `CommandRunner`; never use `shell=True`, `sudo`, package installation, network access, or commands that change configuration. Treat unknown and inaccessible states as informational evidence rather than silently assuming compliance.

Add unit tests for parsing and evaluation logic. Tests must run on non-macOS hosts by injecting a fake runner or testing pure functions.

Run the unit tests and JavaScript syntax check before opening a pull request:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
node --check src/macos_inspector/webui/app.js
```

The dashboard is intentionally local-only and must not expose arbitrary command execution. New UI actions must call a registered collector through `core.scan.run_scan`, preserve collection errors, and keep report files owner-readable only.
