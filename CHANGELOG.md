# Changelog

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
