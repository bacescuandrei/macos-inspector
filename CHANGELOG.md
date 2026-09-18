# Changelog

## 1.2.7 - Unreleased

- Added automatic **Changes since last comparable scan** analysis for applications, executable identity, startup items, network listeners, security controls, new findings, and resolved findings.
- Added deterministic investigation stories that connect application, process, network, and persistence evidence only when an exact application path relationship is present.
- Added evidence confidence as a separate concept from severity, with a rationale and visible missing-evidence list for each finding.
- Added problem-oriented local scan goals for an unfamiliar application, suspected remote access, unusual browser behavior, and unexpected Mac performance.
- Added explicit hash-only reputation checks for VirusTotal, MalwareBazaar, and ThreatFox. Providers are disabled by default, require user configuration, never receive the file, and run only after confirmation.
- Added a simplified, responsive investigation summary that can be exported to standalone HTML without changing the original scan evidence.
- Added protected decision-support and summary-export APIs, local reputation caching, and regression coverage for baseline selection, correlations, confidence, export protection, and hash-only privacy behavior.

## 1.2.6 - 2026-09-18

- Added a first-run **Check this Mac** workflow that starts the recommended offline Quick triage profile without requiring security knowledge.
- Added a guided investigation summary that separates items needing attention, checks that could not be completed, and results that look normal or were resolved.
- Added plain-language verdicts, short explanations, concrete next steps, and an investigation workflow from detection through closure without treating a review signal as proof of malware.
- Added focused application and process investigation context while keeping commands and raw evidence behind expandable technical details.
- Added local investigation states and analyst notes for `Investigating`, `Expected`, `Suspicious`, `Contained`, and `Resolved` findings.
- Kept investigation decisions separate from immutable scan reports and automatically invalidated an expected decision when the application's identity, executable hash, signature, Gatekeeper result, or other security evidence changes.
- Added protected guidance and investigation APIs, owner-only local storage, responsive layouts, and regression tests for evidence separation and stale-decision handling.

## 1.2.5 - 2026-09-17

- Added analyst-confirmed `SIGTERM` and `SIGKILL` controls for current-user processes explicitly listed as Live Triage review candidates.
- Revalidate the live PID owner and executable immediately before signaling, reject stale or arbitrary targets, protect the dashboard and its parent, and disable response when running as root.
- Added process-state collection and explicit zombie handling; zombies are explained as already-exited processes that must be reaped by their parent rather than signaled.
- Added a bounded owner-only response audit log, responsive dashboard controls, and tests for authorization, PID reuse, root mode, zombies, HTTP request protection, and real `SIGTERM` delivery to a controlled test process.

- Hardened the local dashboard against DNS rebinding and cross-origin writes by validating request authorities and browser origins against the active loopback server.
- Added same-origin response protections and end-to-end regression coverage for the local web boundary.
- Moved comparison-report generation to a protected `POST` request so read-only `GET` routes cannot create local files.
- Bounded local JSON, manifest, key, cache, IOC pack, and scan-history reads, and streamed report downloads to avoid loading large artifacts into server memory.
- Updated GitHub CI actions to current Node.js 24 releases and pinned each action to an immutable commit.

## 1.2.4 - 2026-09-17

- Reworked the README around product purpose, intended users, safe installation, practical workflows, result interpretation, privacy behavior, evidence handling, and known limitations.
- Added complete installation and usage guides with fixture-derived examples that distinguish observations from security conclusions.
- Expanded contributor and security guidance and added documentation-link validation.
- Corrected Full Disk Access guidance to identify the application that launches Python as the permission subject.
- Added GitHub CI for Linux and macOS with Python 3.10 and 3.13.
- Added security, support, conduct, architecture, threat-model, issue, and pull-request documentation.
- Included the public project documentation in the portable release archive.
- Replaced long dashes and decorative punctuation in dashboard and report text with plain ASCII punctuation.
- Added checks that keep the dashboard English-only and reject long dash characters.

## 1.2.3 - 2026-08-09

- Reworked Live Triage correlation around socket exposure, process runtime, parent state, redacted command context, and working directory instead of treating every suspicious-path listener as high priority.
- Kept loopback-only correlations as low-priority context while elevating long-running basic development servers bound beyond localhost, including stale servers publishing temporary directories.
- Deduplicated equivalent IPv4/IPv6 socket rows and retained their underlying socket count in evidence.
- Added bounded command-line collection with common password, token, secret, credential, cookie, authorization, and API-key argument redaction.
- Refined Application Trust conclusions for world/group-writable files, Apple system components that Gatekeeper does not assess independently, system-managed Cryptex symlinks, disallowed extended metadata, and missing sealed resources.
- Fixed current-format `systemextensionsctl` parsing so real third-party extensions are recorded instead of the table header.
- Distinguished enabled third-party background services from disabled third-party context.
- Expanded the regression suite to 55 tests.

## 1.2.2 - 2026-08-09

- Removed the Romanian locale and language selector; the security dashboard and direct-file launch page are now English-only.
- Removed the persisted language preference from local settings while safely ignoring older stored values.

## 1.2.1 - 2026-08-09

- Fixed the dashboard source opened through `file://` loading without CSS or JavaScript because its asset links were root-relative.
- Added a polished, responsive direct-file launch page that explains the local-server boundary and links to the running dashboard.
- Kept the same relative assets valid when the dashboard is served normally from `127.0.0.1`.
- Added regression coverage for the direct-file launcher state.

## 1.2.0 - 2026-08-09

- Added exact macOS version/build exposure correlation across Apple Security Releases, CISA KEV, FIRST EPSS, and NIST NVD without claiming evidence of compromise.
- Added validated, provenance-recorded OSINT caching with configurable TTL, stale last-known-good fallback, provider controls, and cache clearing.
- Added explicit ThreatFox lookup; it is disabled by default and submits only the analyst-entered indicator after confirmation.
- Added live incident triage for process trees, listeners, established connections, suspicious execution paths, and process/network correlation.
- Added dashboard-managed IOC packs and optional local YARA rules with bounded explicit targets.
- Added private local case records, saved-case attachment, archived state, analyst identity, and notes.
- Added automatic Ed25519 or built-in HMAC-SHA256 signing identities and dashboard signature verification.
- Added password-protected AES-256-GCM case bundles using Scrypt and a CLI decrypt workflow; passwords are never journaled or persisted.
- Added Romanian/English UI localization, visible keyboard focus, reduced-motion support, and responsive layouts verified at 1280, 1024, 768, 390, and 320 pixels without text escaping its card.
- Added the Vulnerability Intelligence and Threat Hunting profiles, bringing the project to 15 collectors and nine report formats.
- Added cache, settings, case, exposure, live triage, YARA, signing, and encryption tests; the complete suite now contains 52 tests.

## 1.1.0 - 2026-08-09

- Added an explicit Online OSINT profile backed by CISA's free Known Exploited Vulnerabilities catalog and official GitHub mirror.
- Added validated catalog provenance and Apple-related KEV context without inferring that the inspected host is vulnerable.
- Added visible online/privacy labels and a confirmation step before any external request from the dashboard.
- Kept Quick triage, Full local collection, and the default CLI collection offline; OSINT must be selected explicitly.
- Added bounded HTTPS retrieval with trusted redirect-host, response-size, and feed-schema validation.
- Added fixture-based OSINT tests and completed a live end-to-end validation against the public feed.
- Fixed horizontal dashboard overflow caused by long scan-history entries.

## 1.0.0 - 2026-08-08

- Completed the local HTML dashboard with scan profiles, individual audit buttons, progress, cancellation, history, comparisons, readiness checks, and in-page findings.
- Added 11 read-only audit sections covering accounts, Application Trust, background items, browsers, IOC packs, persistence, privacy, network, management profiles, system extensions, and security controls.
- Added HTML, JSON, Markdown, CSV, SARIF, evidence manifest, portable PDF, and case-bundle ZIP reports.
- Added evidence hashing, manifest verification, optional HMAC/asymmetric signatures, normalized timelines, and report comparison.
- Added the portable double-click macOS launcher, private local report storage, crash recovery, Gitea CI, and release packaging.
- Added a dependency-free PDF engine so every report format works from the portable package without terminal installation.

The 1.0 release remains read-only: it does not remediate, delete, quarantine, elevate privileges, or change host configuration.
