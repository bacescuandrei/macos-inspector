# Architecture

macOS Inspector is a local Python application with a browser-based interface. The dashboard binds to the loopback interface and calls a fixed HTTP API exposed by the local process.

## Collection path

1. The CLI or dashboard selects registered collectors.
2. Each collector uses `CommandRunner` for allowlisted commands with fixed argument rules and timeouts.
3. Collectors return immutable `Finding` and `Evidence` records.
4. The scan layer records metadata, errors, scores, coverage, and timeline events.
5. The guidance layer derives plain-language verdicts and next steps from the completed report without changing its findings.
6. Reporters serialize the completed result without collecting additional evidence.

Collectors do not write reports. Reporters do not run host commands. This boundary keeps collection behavior reviewable and allows parser tests to run with fixtures on non-macOS systems.

## Main packages

- `collectors`: read-only host inspection and parsing logic.
- `core`: models, command execution, scan orchestration, scoring, storage, comparison, guided interpretation, intelligence caching, and timeline generation.
- `core.process_control`: guarded validation and signaling for report-listed current-user processes.
- `reporters`: HTML, JSON, Markdown, CSV, SARIF, PDF, manifest, ZIP, and encrypted ZIP output.
- `web.py`: loopback-only dashboard API, job state, cancellation, settings, cases, and report access.
- `webui`: static HTML, CSS, and JavaScript served by the local dashboard.

## Trust boundaries

Host commands, local files, imported rules, intelligence responses, and browser requests are treated as untrusted input. Values are parsed, bounded, escaped, or validated before they are stored or rendered. Persisted JSON stores, imported packs, manifests, and scan reports use explicit read limits. Downloadable reports are streamed instead of being copied into server memory. The web boundary validates each `Host` and any browser `Origin` against the active loopback server port before routing a request.

Online intelligence is separate from local collection. Providers receive public vulnerability identifiers or an indicator entered by the analyst. Collected host evidence is not uploaded. Explicit hash reputation sends only a confirmed SHA-256 to enabled providers and never uploads the application file.

Process response is separate from collection. The web API loads a managed report, accepts only candidates produced by two Live Triage findings, and delegates identity revalidation and signaling to `core.process_control`. The response module cannot accept an arbitrary command line. It exposes only `SIGTERM` and `SIGKILL`, after an exact UID and executable match, and the dashboard records the result locally.

Guided interpretation is also separate from collection. It maps existing finding fields to plain-language verdicts, evidence confidence, recommended investigation steps, comparable-scan changes, and exact-path correlations. Local investigation states and notes are stored outside the report with owner-only permissions. Each decision is tied to a fingerprint of the security-relevant evidence, so an `Expected` decision returns to `New` when that evidence changes. Decision-support output is derived from completed reports and never changes the original evidence.

## Extension rules

A new collector must have a stable identifier, remain read-only, remain useful without elevated privileges, report unavailable data honestly, and return normalized findings. A new dashboard action must map to a registered operation and must not accept arbitrary commands. Any new response capability requires an explicit threat-model update, narrow authorization, current-state revalidation, confirmation, audit behavior, and regression tests.
