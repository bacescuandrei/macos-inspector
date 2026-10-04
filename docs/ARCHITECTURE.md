# Architecture

macOS Inspector is a local Python application with a browser-based interface. The dashboard binds to the loopback interface and calls a fixed HTTP API exposed by the local process.

## Collection path

1. The CLI or dashboard selects registered collectors.
2. Each collector uses `CommandRunner` for allowlisted commands with fixed argument rules and bounded default or per-call timeouts. Deep application signature and Gatekeeper checks receive longer bounds because large bundles can require more time without implying failure.
3. Collectors return immutable `Finding` and `Evidence` records.
4. The scan layer records metadata, errors, scores, per-category and per-collector coverage, and timeline events. A selected collector that fails or returns no findings has zero collector coverage.
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

Process response is separate from collection. The web API loads a managed report, accepts only candidates produced by two Live Triage findings, and delegates identity revalidation and signaling to `core.process_control`. The response module cannot accept an arbitrary command line. It exposes only `SIGTERM` and `SIGKILL` from a snapshot no more than 15 minutes old, after matching UID, parent PID, executable, and process start; the dashboard records the result locally.

Targeted Application Trust is also bounded by server-side discovery. The dashboard lists application bundles found under the standard macOS application roots and accepts only an exact path from that current inventory. The browser cannot submit an arbitrary file-system target. Target scope is written into report metadata and participates in comparable-baseline selection.

Application activity correlation is path-based. A process, socket, or launch item is associated with an Application Trust result only when its recorded executable is inside that exact bundle path. The live process evidence keeps a minimal inventory of PID, parent PID, process state, elapsed runtime, and executable path for this purpose. Complete command lines remain limited to review candidates and are sanitized before persistence.

Guided interpretation is also separate from collection. It maps existing finding fields to plain-language verdicts, evidence confidence, recommended investigation steps, comparable-scan changes, and exact-path correlations. The Simple view consumes a derived assessment and at most three prioritized actions. The Analyst view exposes the complete evidence and controls. Both views show the collection window, scope, and automatic comparison baseline from immutable reports. Automatic baseline selection requires matching nonempty collector sets, application targets, and recorded hostnames, consistent file/report identities, and strictly earlier timezone-aware completion times. Missing host or time metadata prevents automatic comparison. Hostname equality is not a device-authentication mechanism. Repeating a report reuses its recorded collectors and application target through the existing scan API, with current local settings and online confirmation; it does not override automatic baseline selection. Local investigation states and notes are stored outside the report with owner-only permissions. Each decision is tied to a fingerprint of the security-relevant evidence, so an `Expected` decision returns to `New` when that evidence changes. Decision-support output is derived from completed reports and never changes the original evidence.

Presence inference has a separate completeness gate. New scans include an additive `minimum_severity` metadata field. An absence claim requires an unfiltered snapshot with a recorded total matching the full findings list, selected relevant collectors, 100% recorded completion for those collectors, and no relevant collection error. Addition claims apply that gate to the earlier snapshot; disappearance claims apply it to the later snapshot. Collector errors with no usable attribution are conservative blockers. Shared-record field differences remain available. In decision-support JSON, blocked or out-of-scope presence counts are null, and `comparison_context.limitations` explains evidence gaps. The browser must not coerce null to zero. The original report and older metadata are never rewritten to infer completion.

Manual comparison retains raw finding-ID differences regardless of completeness. Its legacy `resolved` field is a baseline-only record set; user-facing labels do not imply remediation. Numeric index deltas additionally require matching selected sections, targets, recorded hosts and tool versions, complete unfiltered reports, and assessed findings. Insufficient context produces null deltas and explicit limitations without discarding the record differences. The shared completeness checks live in `core/report_context.py` so automatic interpretation and manual index comparison use the same evidence rules. Both comparison interfaces preserve their source reports.

## Inventory, rule context, and response history

Application discovery preserves directory errors in collector metadata and an unknown finding while retaining successfully discovered applications. A collector with any unknown result or attributed error cannot round up to 100% completion. Missing optional roots do not produce access errors; discovery remains bounded to roots and one grouping directory.

`core.rule_context` records additive `detection_context` metadata for IOC and YARA. It hashes rule bytes and resolved file identities plus only relevant YARA settings, not provider secrets. Bounded before/after capture detects ordinary changes during collection; it is not an atomic filesystem snapshot and cannot defend against a hostile same-user race. Cross-report rule context gates finding inventory interpretation and manual index deltas; independent complete application and listener inventories remain usable.

`core.response_history` maintains the existing private, rotating JSONL action log. New signals record owner and process-start identity. A job with a retained `response_action_id` must collect only Live Triage, without an application target, and uses the Informational filter. Completed rechecks append a separate observation linking the new report to the action. No source report or investigation state is modified. A recheck-log write failure does not discard completed scan evidence.

`core.detection_validation` runs packaged synthetic scenarios without host commands or network requests. The dashboard exposes the same pure evaluation as the developer script, and includes fixture hashes and expected/observed outcomes in downloadable JSON. These are regression checks, not an independent threat-detection evaluation.

## Extension rules

A new collector must have a stable identifier, remain read-only, remain useful without elevated privileges, report unavailable data honestly, and return normalized findings. A new dashboard action must map to a registered operation and must not accept arbitrary commands. Any new response capability requires an explicit threat-model update, narrow authorization, current-state revalidation, confirmation, audit behavior, and regression tests.
