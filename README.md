# macOS Inspector

[![CI](https://github.com/bacescuandrei/macos-inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/bacescuandrei/macos-inspector/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

macOS Inspector is a macOS security inspection and DFIR triage tool for both everyday Mac users and experienced investigators. It collects local evidence with read-only collectors, evaluates it with documented rules, and explains what needs attention through a guided local dashboard. Technical evidence remains available for analysts, while plain-language summaries and recommended next steps help less experienced users avoid unsafe conclusions.

It was created to make evidence that is normally scattered across command-line tools, property lists, SQLite databases, application bundles, running processes, sockets, and macOS security settings easier to collect and review in one place.

The project is intended for Mac owners who want a clearer security check, as well as incident responders, forensic analysts, security engineers, and system administrators. It does not replace an EDR platform, malware analysis, or a complete forensic acquisition workflow.

Current development version: `v1.3.0`

## What it can help answer

- Which applications have valid signatures, hardened runtime, notarization evidence, suspicious paths, or integrity concerns?
- Which accounts, launch items, background services, privacy grants, profiles, extensions, and network settings deserve review?
- Which applications are running, using the network, or configured to start automatically, and which exact evidence connects those observations?
- Which processes own listeners or established connections, and what local context makes them higher priority?
- Does the installed macOS version require review against current Apple, CISA KEV, FIRST EPSS, or NIST NVD information?
- Did a bounded local IOC or YARA rule match the files explicitly selected by the analyst?
- What changed since the last scan with the same scope, and which observations are connected by the same application path?
- How complete is the evidence behind a result, independently from its severity?

macOS Inspector reports observations and rule outcomes. A `Review`, `Fail`, or `Match` result is not by itself proof of malware, exploitation, or compromise.

## Inspection areas

| Dashboard workflow | Primary purpose | Network use |
| --- | --- | --- |
| Problem-oriented goals | Focused local checks for an unfamiliar app, suspected remote access, strange browser behavior, or an unusually slow Mac | None |
| Quick triage | Accounts, live activity, persistence, security controls, profiles, extensions, network configuration, and IOCs | None |
| Application Trust | Signatures, notarization, Gatekeeper context, entitlements, metadata, bundle layout, and file integrity | None |
| Privacy and browsers | TCC permissions and bounded browser history, download, and extension artifacts | None |
| Vulnerability Intelligence | Local macOS version correlation with public Apple, CISA, FIRST, and NIST data | Explicit opt-in |
| Threat Hunting | Live process and network context plus imported IOC and optional YARA rules | None, except separate manual ThreatFox lookup |
| Full local collection | Every local collector in one scan | None |

Fifteen collectors cover accounts and access, Application Trust, background items, browser artifacts, IOCs, live triage, management profiles, network configuration, free OSINT context, persistence, privacy permissions, security controls, system extensions, vulnerability exposure, and YARA rules.

## Read findings correctly

| Status | Meaning | What it does not mean |
| --- | --- | --- |
| Pass | The specific rule met its documented expectation | The host or application is safe |
| Observed | Inventory or state was recorded without a negative rule outcome | The observation is benign or malicious |
| Review | Context is required before the observation can be accepted or escalated | Compromise was detected |
| Fail | A defined security expectation was not met | Malware was proven |
| Unknown | Evidence was unavailable, incomplete, or could not be evaluated | The check passed |
| Match | An imported IOC or YARA rule matched within the selected scope | The matched object is conclusively malicious |
| Not Applicable | The component or optional feature was not present in the inspected scope | The entire category was assessed |

Severity is a review priority, not a malware verdict. Always inspect the finding explanation, observed evidence, collection notes, and host context before reaching a security conclusion.

## Install the portable release

Requirements:

- macOS
- Python 3.10 or newer
- no `sudo`
- no mandatory Full Disk Access

1. Download `macos-inspector-1.3.0-macos.zip` and `SHA256SUMS` from the latest GitHub release.
2. Verify the archive before opening it:

   ```bash
   shasum -a 256 macos-inspector-1.3.0-macos.zip
   ```

   Compare the result with the value in `SHA256SUMS` on the same release.
3. Extract the ZIP.
4. Double-click **macOS Inspector.command**.

The release is not Apple-signed or notarized. After verifying the checksum, use Finder's Control-click, then **Open**, if macOS blocks the first launch. Do not disable Gatekeeper globally and do not remove quarantine attributes from unrelated files.

The launcher starts a local service on `http://127.0.0.1:8765/` and opens the dashboard. Keep the launcher window open while using the application. Closing it stops the local service.

Do not open `src/macos_inspector/webui/index.html` as the application. That file is only the dashboard source and cannot start the local Python service.

See [Installation](docs/INSTALLATION.md) for source installation, permission behavior, troubleshooting, release verification, and removal.

## Run a first scan

1. Open the dashboard with the launcher.
2. Select **Check this Mac** in the start guide. This runs the recommended offline Quick triage profile.
3. Read the guided summary and open the items listed under **Needs review**, **High-risk behavior**, or **Unable to verify**.
4. Follow the recommended next steps and expand **Details** when technical evidence is needed.
5. Record the investigation state as `Expected`, `Suspicious`, `Contained`, or `Resolved`. Notes remain local and do not modify scan evidence.
6. Run the same profile again after containment or remediation and compare it with the earlier scan.

After a report loads, **Changes since last comparable scan** selects the newest earlier report with the same collection scope. For a focused application check, that includes the exact target application. Evidence confidence explains how complete the supporting data is without changing the severity. Correlated investigation stories appear only when an application path connects trust, process, network, or persistence evidence. Use **Export investigation summary** for a compact standalone HTML handoff; the original scan evidence remains unchanged.

Routine use does not require terminal commands. The CLI remains available for automation and reproducible collections.

## Practical examples

### Validate an unfamiliar application

Goal: determine whether an application has the expected macOS trust signals.

Steps: use **Check one application** to search the local application list and select the app. Choose **Check trust only** for the fastest signature and integrity check, or **Check trust and activity** to add running-process, network, and startup context. Review its signature, Team ID, notarization result, hardened runtime, entitlements, quarantine metadata, bundle paths, and executable integrity. Use the full **Application Trust** profile when you need an inventory of every visible application. The application review queue then separates results into **Review first**, **Needs context**, **Unable to verify**, **Checks passed**, and **Reviewed locally**. When the same scan also includes Live Triage or Persistence, each row shows whether the exact application bundle was running, had network endpoints, or was referenced by a startup item. These activity labels provide context and do not make the application suspicious by themselves.

Representative result:

```text
Status: Pass
Severity: Informational
Observed: Valid Developer ID signature, hardened runtime enabled,
notarization accepted, executable located inside the application bundle.
```

Interpretation: the application met the checks shown in the finding. This does not prove that the software is harmless or that its publisher is trustworthy. Confirm the publisher, expected installation source, hashes, and behavior before closing the review.

### Investigate a listening process

Goal: connect a network listener to its owning process and execution context.

Steps: run **Threat Hunting**, open **Process and network connection correlation**, and inspect the local address, owning PID, executable path, parent process, command context, working directory, runtime, and exposure beyond loopback.

Representative result:

```text
Status: Review
Severity: High
Observed: 1 listener, 0 established connections, 1 high-priority candidate,
0 medium-priority candidates, 0 loopback-limited candidates.
```

Interpretation: the combined context raised review priority. A listener alone is not malicious. Confirm whether the service is expected, identify its owner, inspect its files and launch mechanism, and compare it with a known-good baseline.

If containment is required, expand the finding and use **Terminate** first. This sends `SIGTERM` only after the dashboard confirms that the PID still belongs to the same executable and current user recorded in the scan. **Force kill** sends `SIGKILL`, is separately confirmed, and can cause data loss. Preserve volatile evidence before either action and rerun Live Triage afterward. A zombie has already exited and cannot be killed; its parent must reap it.

### Review macOS vulnerability exposure

Goal: prioritize operating-system updates using public vulnerability information.

Steps: opt in to **Vulnerability Intelligence**, confirm the network disclosure notice, run the profile, and open **Apple KEV applicability correlation**.

Representative result:

```text
Local version: macOS 26.5.2, build 25F84
Latest release observed: macOS 26.6
Status: Review
Observed: 1 possibly affected; 1 requires vendor-advisory review;
0 outside the evaluated version range.
```

Interpretation: the version correlation is a prioritization signal. It is not proof that the host is exploited or compromised. Confirm the exact model, OS build, Apple security advisory, remediation state, and organizational exception policy.

More workflows, including privacy grants, persistence, IOC/YARA matches, scan comparison, and evidence verification, are documented in [Usage and interpretation](docs/USAGE.md).

## Data, privacy, and system behavior

- The dashboard binds to loopback only. Non-local bind addresses, non-loopback `Host` authorities, and non-local browser origins are rejected.
- Collectors use an allowlist of read-only commands without a shell. The tool does not execute browser-supplied commands.
- Collection remains read-only. The only host-changing response action is an explicit, confirmed signal to a current-user process already listed as a Live Triage review candidate.
- Process response is disabled when the dashboard runs as root, rejects arbitrary PIDs and stale process identities, protects the dashboard and its parent, and records successful actions in a private local log.
- The tool does not delete or quarantine files, install software, invoke `sudo`, elevate privileges, or change macOS configuration.
- Local profiles and the default CLI collection do not contact intelligence providers.
- The online profile is opt-in. It sends only public Apple CVE identifiers to the enabled Apple, CISA, FIRST, and NIST endpoints.
- VirusTotal, MalwareBazaar, and ThreatFox are disabled by default and are separate from scans. An application hash lookup runs only after confirmation and sends only the displayed SHA-256 to enabled providers. It never uploads the application file. A missing provider record is not proof that a file is safe.
- Imported IOC packs and YARA rules remain local. YARA scans at most ten explicit targets and rejects `/` and the entire home directory.
- Report files, case records, settings, cache entries, signing secrets, and unfinished job journals remain on the Mac. Private local stores use owner-only permissions.
- Common secret-bearing command arguments are redacted from collected process context. This reduces exposure but cannot guarantee that every sensitive value is recognized.
- Live Triage retains a minimal PID, process state, runtime, and executable-path inventory so exact applications can be correlated with activity. It does not retain the complete command line for every process.
- Full Disk Access is not requested automatically. If policy permits broader coverage, grant it to the application that launches Python, such as Terminal, then restart the launcher. Never bypass TCC protections for convenience.
- Running read-only macOS commands may still create normal unified-log entries or update access metadata.

Browser artifacts and reports may contain sensitive history, downloads, usernames, paths, network endpoints, case notes, and host identifiers. Store, transfer, and dispose of them under the applicable evidence-handling policy.

The portable dashboard stores reports in `macos-inspector-reports` beside the launcher and keeps its private settings, cases, caches, imported rules, and signing material under that report directory in `.macos-inspector-data`. Source or CLI operations that use shared application state default to `~/Library/Application Support/macOS Inspector` unless `MACOS_INSPECTOR_DATA_DIR` is set.

## Reports and evidence handling

The dashboard supports HTML, JSON, Markdown, CSV, SARIF, PDF, evidence manifests, case-bundle ZIP files, and optional encrypted bundles. Every manifest records SHA-256 digests for normalized evidence and generated reports. The dashboard can verify those files and any attached signature.

Encrypted bundles require the optional `cryptography` dependency. The password is used only for the active export and is not saved in settings, scan history, or reports. A lost password cannot be recovered.

The built-in signing identity uses Ed25519 when the optional dependency is available and otherwise uses HMAC-SHA256. HMAC can detect later changes for a party that possesses the same secret, but it does not provide public-key identity assurance. For portable third-party verification, use an Ed25519, RSA, or EC private key and verify its public-key fingerprint through a separate trusted channel.

## Limitations

- macOS Inspector performs live inspection, not a bit-for-bit forensic acquisition.
- Results reflect the current user's visibility and the permissions available at collection time.
- Some TCC and browser databases may be unavailable while protected or locked.
- Browser collection is bounded to supported profiles and recent rows; it is not complete browsing-history recovery.
- Application signatures, notarization, and Gatekeeper results are trust signals, not a behavioral verdict.
- IOC and YARA results are only as reliable as the imported rules and selected scan targets.
- External intelligence can be delayed, incomplete, unavailable, or ambiguous for a particular build.
- Volatile process and network state can change during collection.
- Process termination can interrupt work or lose unsaved data. `SIGKILL` does not allow cleanup, and a zombie cannot receive another signal.
- The portable release is not Apple-signed or notarized.
- There is no remote agent, continuous monitoring service, automatic remediation, or cloud console. Process response always requires a local analyst confirmation.
- Legal admissibility and chain-of-custody requirements depend on the analyst's process and jurisdiction.

## Development

```bash
git clone https://github.com/bacescuandrei/macos-inspector.git
cd macos-inspector
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[signing]'
PYTHONPATH=src python -m unittest discover -s tests -v
node --check src/macos_inspector/webui/app.js
PYTHONPATH=src python -m scripts.build_release
```

CLI example:

```bash
macos-inspector --collectors application-trust,persistence,security \
  --formats html,json,markdown,csv,sarif,manifest \
  --output ./macos-inspector-reports
```

Findings do not change the process exit code. The CLI exits `0` when collection completes, `1` for an internal collection error, and `2` for invalid input.

## Documentation

- [Installation and verification](docs/INSTALLATION.md)
- [Usage and interpretation](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Changelog](CHANGELOG.md)

## Contributing and license

Contributions are welcome when they preserve the read-only collector boundary, keep response actions narrowly constrained, and include tests for evaluation logic. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

macOS Inspector is released under the [MIT License](LICENSE).
