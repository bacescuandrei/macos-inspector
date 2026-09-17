# macOS Inspector

macOS Inspector is a read-only macOS security auditing and DFIR framework with a dependency-free core. It collects verifiable evidence, produces normalized findings, calculates transparent security scores, and exports professional reports through a local web dashboard.

> Status: version 1.2.4 is feature-complete for the documented scope. Fifteen collectors cover accounts, persistence, Application Trust, privacy, browsers, management, network, extensions, security controls, live process/network triage, managed IOC/YARA rules, and explicit online vulnerability intelligence. The responsive English security dashboard provides case management, provider settings, cache provenance, scan controls, findings, comparisons, and nine report formats. Evidence timestamps are normalized into a shared DFIR timeline. Validate the workflow against the applicable evidence-handling policy before relying on it in a legal investigation.

## Safety contract

- No remediation, deletion, quarantine, privilege escalation, or configuration changes.
- Commands are executed without a shell, with timeouts and captured output.
- The tool never invokes `sudo` and does not request Full Disk Access.
- Permission failures are reported as collection notes instead of bypassed.
- Reports record the commands used and the evidence supporting each finding.
- Local profiles and the default CLI collection never access an OSINT service.
- Online vulnerability intelligence is opt-in. Common Apple CVE identifiers may be requested from Apple, CISA, FIRST, and NIST; no hash, file, hostname, user, case, or collected evidence is sent.
- ThreatFox is disabled by default and is never queried automatically. Only an indicator typed by the analyst is submitted after a separate confirmation.

Some macOS commands may update their own access metadata or unified logs simply by executing. Run from trusted media and validate the workflow against your evidence-handling policy before use in a legal investigation.

## Quick start

For normal use on macOS, double-click **macOS Inspector.command**. The launcher starts the local read-only dashboard and opens `http://127.0.0.1:8765/` automatically. If the dashboard is already running, it simply reopens the page. No terminal commands are required for routine scans.

Do not use `src/macos_inspector/webui/index.html` as the application launcher: it is the dashboard source and cannot start a local Python service from inside a browser. If it is opened directly, it now loads its styling and shows a clear launch page instead of a broken interface.

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

PDF export is built into the portable package and selected by default with the other report formats; no package installation or terminal command is required.

For the local dashboard, start the read-only web interface once:

```bash
python3 -m macos_inspector --web
```

It binds to `127.0.0.1:8765` by default. The responsive dashboard offers Quick triage, Application Trust, Privacy & browsers, Vulnerability Intelligence, Threat Hunting, and Full local collection profiles, plus a separate Run button for every collector. Quick triage is selected by default; Full local collection deliberately excludes online enrichment. Choosing an online collector displays its privacy boundary and requires confirmation before the scan starts.

The **Cases, sources and rules** area provides local case records, provider and cache settings, explicit ThreatFox lookup, IOC/YARA imports, bounded YARA targets, and signing identity management. The English-only interface supports keyboard focus and reduced-motion preferences and has no horizontal content overflow from 320-pixel mobile layouts through wide desktop layouts.

The page also provides collection readiness, progress, cancellation, history, comparison, finding details, timelines, and links to every report export. Long collectors such as Application Trust report the current application, item count, progress bar, and estimated remaining time. All standard report formats are selected by default; the encrypted bundle is deliberately opt-in because it requires a password between 12 and 256 characters. The dashboard rejects invalid formats before evidence collection begins and never accepts arbitrary commands from the browser; every action maps to a registered collector and the same read-only command allowlist used by the CLI.

## Vulnerability intelligence and OSINT

The **Free OSINT threat intelligence** section retrieves CISA's public Known Exploited Vulnerabilities catalog from its [official GitHub mirror](https://github.com/cisagov/kev-data). It validates the feed schema and size, records catalog provenance, and extracts Apple-related entries. Results provide external prioritization context only: the presence of an Apple CVE in KEV is never reported as proof that the inspected Mac is affected. Confirm product and operating-system versions against Apple advisories before assigning host impact.

The **Vulnerability exposure** collector records the exact local macOS version/build and correlates Apple-related KEV entries with Apple Security Releases, FIRST EPSS probability, and NIST NVD applicability/CVSS data. Results are explicitly classified as **Possibly affected**, **Not in affected range**, or **Not enough evidence**. They are prioritization signals, never proof of compromise.

Validated provider responses are cached locally with retrieval time, URL, size, and SHA-256 provenance. Fresh cache entries avoid repeated requests; a validated last-known-good entry can be used if a provider is temporarily unavailable. Cache duration is configurable from 1 to 168 hours and the cache can be cleared from the dashboard.

| Provider | Default | Credential | Data sent |
| --- | --- | --- | --- |
| Apple Security Releases | enabled in online profile | none | common public-page request |
| CISA KEV | enabled in online profile | none | common public-feed request |
| FIRST EPSS | enabled in online profile | none | common Apple CVE identifiers |
| NIST NVD | enabled in online profile | optional API key | common Apple CVE identifiers |
| ThreatFox | disabled | free Auth-Key | only the indicator explicitly entered and confirmed by the analyst |

Provider failures or malformed responses are reported as **Unknown** without invalidating local scan results. Online response bodies never contain or persist local host evidence.

## Live triage, IOC and YARA

Live triage snapshots running processes, parent relationships, listeners, and established connections, then prioritizes bounded review candidates using combined path, parent, runtime, command-context, working-directory, and socket-exposure signals. Equivalent socket rows are deduplicated, loopback-only tooling is kept as low-priority context, and long-running basic development servers exposed beyond localhost are elevated. Persisted command context is length-bounded and redacts common secret-bearing arguments. The collector remains read-only and does not terminate processes or connections.

Versioned IOC JSON packs and `.yar`/`.yara` rule files can be imported from the dashboard. YARA is optional, executes locally through a trusted binary, and accepts at most ten explicit targets; scanning `/` or the entire home directory is rejected. Files, hashes, matches, and rules are never uploaded.

The **Collection readiness** preflight shows macOS and Python compatibility, trusted command availability, report-storage access, visible application coverage, read-only TCC and browser-database access, built-in PDF support, and optional asymmetric signing support. It reports limitations and recommended actions without requesting privileges or exposing evidence paths and content through the health endpoint.

Active scans can be cancelled from the dashboard. Unfinished jobs are journaled locally with owner-only permissions (`0600`); if the dashboard stops unexpectedly, they are restored as **interrupted** on the next start. Partial results are never published as completed reports.

The header continuously shows the local server connection state and retries automatically after a restart. `GET /api/health` provides a minimal operational status for diagnostics without exposing the report directory or evidence content. Dashboard assets and reports use `Cache-Control: no-store`.

Every evidence manifest contains SHA-256 digests for the normalized evidence and generated reports. The dashboard's **Verify evidence** button rechecks all exported files and any attached signature. Selecting **Case bundle ZIP** packages every report from that scan, the manifest, a SHA-256 bundle index, and offline verification instructions into one download; artifacts from other cases and private signing keys are never included.

The dashboard can create a private local signing identity automatically: Ed25519 when the optional cryptography package is present, otherwise built-in HMAC-SHA256. Secret files and local case/settings stores use owner-only permissions and are excluded from reports and release archives. **Encrypted case bundle** uses AES-256-GCM with a Scrypt-derived key; its password exists only for the active export and is not written to settings, job history, or reports.

For a portable asymmetric identity, install the optional dependency and provide an Ed25519, RSA, or EC private key in PEM format. The manifest contains only the public key and its SHA-256 fingerprint; the private key is never written to a report.

```bash
python3 -m pip install '.[signing]'
MACOS_INSPECTOR_SIGNING_KEY=/secure/inspector-ed25519.pem python3 -m macos_inspector --formats html,json,manifest
python3 -m macos_inspector --verify-manifest ./macos-inspector-reports/macos-inspector-SCAN_ID.manifest
```

Encrypted private keys are supported through `MACOS_INSPECTOR_SIGNING_KEY_PASSWORD`. Existing HMAC-SHA256 signing remains available through `MACOS_INSPECTOR_MANIFEST_KEY`; asymmetric signing takes precedence when both are configured. For identity trust, compare the displayed public-key fingerprint with a value obtained through a separate trusted channel or pass a trusted PEM key with `--public-key`.

Encrypted bundles use the optional cryptography dependency as well:

```bash
MACOS_INSPECTOR_BUNDLE_PASSWORD='a long case password' python3 -m macos_inspector --formats html,json,manifest,encrypted-bundle
MACOS_INSPECTOR_BUNDLE_PASSWORD='a long case password' python3 -m macos_inspector --decrypt-bundle ./macos-inspector-reports/macos-inspector-SCAN_ID.zip.enc
```

For development without installation:

```bash
PYTHONPATH=src python3 -m macos_inspector --output ./reports
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Project documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## Continuous integration

The GitHub workflow runs the test suite on Linux and macOS with Python 3.10 and 3.13. It installs the optional cryptography dependency, compiles the Python sources, checks dashboard JavaScript syntax, builds the portable ZIP on macOS, records its SHA-256 checksum, and uploads the verified artifact.

The Gitea workflow in `.gitea/workflows/ci.yml` automatically runs the test suite, compiles Python sources, checks dashboard JavaScript syntax, builds the portable ZIP, verifies its contents, and publishes it as a temporary build artifact. The workflow never packages or uploads locally generated reports, case evidence, environment files, or private keys.

Repository Actions and an `ubuntu-latest` runner must be enabled once on the Gitea server. See [docs/GITEA_ACTIONS.md](docs/GITEA_ACTIONS.md) for the setup and the boundary between portable CI checks and validation that requires a real Mac.

Useful options:

```text
--list-collectors       Show available collectors
--verify-manifest PATH  Verify a manifest, signature, and report digests
--public-key PATH       Require a trusted PEM public key during verification
--collectors LIST       Comma-separated collector IDs
--formats LIST          html,json,markdown,csv,sarif,manifest,pdf,bundle,encrypted-bundle
--decrypt-bundle PATH   Decrypt an AES-256-GCM case bundle
--decrypt-output PATH   Destination ZIP for --decrypt-bundle
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
  core/          immutable result models, safe commands, storage, intelligence, scoring
  collectors/    isolated read-only audit modules
  reporters/     JSON, Markdown, CSV, and self-contained HTML exporters
  cli.py         orchestration and public command-line interface
```

Collector modules return `Finding` objects. They do not write reports and reporters do not collect data. This separation makes checks testable and helps keep forensic behavior reviewable.

## Maintenance

The documented 1.2 scope has no required unfinished modules. Future releases may add compatibility data, fixtures, optional intelligence sources, or new collectors as macOS evolves; those are scope expansions rather than missing functionality.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the collector contract and contribution workflow.
