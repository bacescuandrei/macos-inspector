# Changelog

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
