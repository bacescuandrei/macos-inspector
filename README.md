# macOS Inspector

macOS Inspector is a dependency-free, read-only macOS security auditing and DFIR framework. It collects verifiable evidence, produces normalized findings, calculates transparent security scores, and exports professional reports.

> Status: early MVP. The current release audits launchd, cron and shell-profile persistence, application trust (main-executable SHA-256 and metadata, signature identity, Gatekeeper/notarization, hardened runtime, security-sensitive entitlements, quarantine and download-source metadata), TCC/privacy permissions, Login Items/ServiceManagement state, local network configuration, certificates, system extensions, browser artifacts, local IOC packs, and a focused set of macOS security controls. Evidence timestamps are normalized into a shared DFIR timeline. The architecture is intentionally modular; roadmap items are not implied coverage.

## Safety contract

- No remediation, deletion, quarantine, privilege escalation, or configuration changes.
- Commands are executed without a shell, with timeouts and captured output.
- The tool never invokes `sudo` and does not request Full Disk Access.
- Permission failures are reported as collection notes instead of bypassed.
- Reports record the commands used and the evidence supporting each finding.

Some macOS commands may update their own access metadata or unified logs simply by executing. Run from trusted media and validate the workflow against your evidence-handling policy before use in a legal investigation.

## Quick start

For normal use on macOS, double-click **macOS Inspector.command**. The launcher starts the local read-only dashboard and opens `http://127.0.0.1:8765/` automatically. If the dashboard is already running, it simply reopens the page. No terminal commands are required for routine scans.

The small launcher window remains open while the dashboard is running so macOS preserves access to the folder containing the tool. It does not require any input; closing that window stops only the local dashboard server.

The launcher requires Python 3.10 or newer. Missing or incompatible Python installations are reported through a macOS alert instead of failing silently.

To create the portable final ZIP package during development:

```bash
PYTHONPATH=src python3 -m scripts.build_release
```

The archive contains the executable double-click launcher, dashboard source, collector modules, documentation, and IOC templates. Existing reports, temporary files, and case evidence are deliberately excluded.

```bash
python3 -m macos_inspector --output ./reports
python3 -m macos_inspector --collectors application-trust,persistence,security --formats html,json,markdown,csv,sarif,manifest
```

PDF export is optional. Install its isolated dependency, then select `PDF` in the dashboard or add `pdf` to `--formats`:

```bash
python3 -m pip install '.[pdf]'
python3 -m macos_inspector --collectors security --formats html,pdf --output ./reports
```

For the local dashboard, start the read-only web interface once:

```bash
python3 -m macos_inspector --web
```

It binds to `127.0.0.1:8765` by default. The dashboard provides a button for each audit section, progress and scan history, finding details with evidence and commands, and links to every report export. Long collectors such as Application Trust also report the current application, item count, progress bar, and estimated remaining time. PDF is unchecked by default and becomes available after installing the optional dependency above. The dashboard never accepts arbitrary commands from the browser; every action maps to a registered collector and the same read-only command allowlist used by the CLI.

Active scans can be cancelled from the dashboard. Unfinished jobs are journaled locally with owner-only permissions (`0600`); if the dashboard stops unexpectedly, they are restored as **interrupted** on the next start. Partial results are never published as completed reports.

The header continuously shows the local server connection state and retries automatically after a restart. `GET /api/health` provides a minimal operational status for diagnostics without exposing the report directory or evidence content. Dashboard assets and reports use `Cache-Control: no-store`.

Every evidence manifest contains SHA-256 digests for the normalized evidence and generated reports. The dashboard's **Verify evidence** button rechecks all exported files and any attached signature. Selecting **Case bundle ZIP** packages every report from that scan, the manifest, a SHA-256 bundle index, and offline verification instructions into one download; artifacts from other cases and private signing keys are never included.

For a portable asymmetric identity, install the optional dependency and provide an Ed25519, RSA, or EC private key in PEM format. The manifest contains only the public key and its SHA-256 fingerprint; the private key is never written to a report.

```bash
python3 -m pip install '.[signing]'
MACOS_INSPECTOR_SIGNING_KEY=/secure/inspector-ed25519.pem python3 -m macos_inspector --formats html,json,manifest
python3 -m macos_inspector --verify-manifest ./macos-inspector-reports/macos-inspector-SCAN_ID.manifest
```

Encrypted private keys are supported through `MACOS_INSPECTOR_SIGNING_KEY_PASSWORD`. Existing HMAC-SHA256 signing remains available through `MACOS_INSPECTOR_MANIFEST_KEY`; asymmetric signing takes precedence when both are configured. For identity trust, compare the displayed public-key fingerprint with a value obtained through a separate trusted channel or pass a trusted PEM key with `--public-key`.

For development without installation:

```bash
PYTHONPATH=src python3 -m macos_inspector --output ./reports
python3 -m unittest discover -s tests -v
```

Useful options:

```text
--list-collectors       Show available collectors
--verify-manifest PATH  Verify a manifest, signature, and report digests
--public-key PATH       Require a trusted PEM public key during verification
--collectors LIST       Comma-separated collector IDs
--formats LIST          html,json,markdown,csv,sarif,manifest,pdf,bundle
--min-severity LEVEL    Minimum severity included in reports
--case-reference TEXT   Optional case or incident reference
--analyst TEXT          Optional analyst name or team
--output DIRECTORY      Report destination
--web                   Start the local dashboard
--host HOST             Dashboard bind address (local addresses only)
--port PORT             Dashboard port
```

The process exits `0` when collection completes, `1` when an internal collection error occurs, and `2` for invalid CLI input. Findings themselves do not change the exit code.

## Architecture

```text
src/macos_inspector/
  core/          immutable result models, safe command execution, scoring
  collectors/    isolated read-only audit modules
  reporters/     JSON, Markdown, CSV, and self-contained HTML exporters
  cli.py         orchestration and public command-line interface
```

Collector modules return `Finding` objects. They do not write reports and reporters do not collect data. This separation makes checks testable and helps keep forensic behavior reviewable.

## Roadmap

1. Additional forensic fixtures and broader collector coverage

See [CONTRIBUTING.md](CONTRIBUTING.md) for the collector contract.
