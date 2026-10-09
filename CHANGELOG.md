# Changelog

## Unreleased

## 2.1.0 - 2026-10-09

- Explain browser extension API permissions, host patterns, content-script scope, and optional requests from bounded Chromium manifests and Firefox addon metadata. Keep declaration, recorded addon state, actual grants, and observed behavior distinct. Select numeric version directories without claiming the chosen version is active.
- Add a plain-language extension permission panel in both audit views and include explanations in full HTML reports and investigation summaries. Preserve raw requirements, source context, manifest hashes, and collection limits. Broad requests alone do not raise severity or establish malware; no extension is disabled or removed.
- Bound manifest/addon inputs, directory enumeration, lists, normalized records, and per-profile evidence. Missing, malformed, unsupported, oversized, symlinked, or truncated declarations remain limited. Propagate browser source limits into scan metadata and explicitly disclose unsupported Safari permission coverage.

- Add an explicit PDF sharing-preview workflow with reduced HTML/JSON downloads. Use a field allowlist rather than text replacement: omit document and attachment names, metadata, timestamps, inspection identifiers, destinations, file paths, script text/hashes, and raw context/diagnostics. Document SHA-256 is omitted unless explicitly selected. Original reports remain unchanged and no sharing copy is saved on the server.
- Disclose that reduced exports are not anonymized, authenticated evidence, or safety verdicts. Show every JSON field before downloading and preserve the same fields in the HTML presentation. Changing the document or hash option invalidates the preview; late responses cannot restore an older copy.
- Record OpenAction entries outside a catalog without claiming a document-open trigger, and disclose the unresolved interpretation. Preserve ordinary catalog actions and their chains.
- Require unambiguous bounded lengths for JSON request bodies, reject transfer-encoding conflicts and incomplete bodies, and limit body read time. Sharing previews require the same authenticated local session as other private APIs.
- Extend privacy, request-boundary, parser, download, responsive-layout, accessibility, and stale-preview regression coverage. Preserve the released 2.0.0 tag and artifact.

## 2.0.0 - 2026-10-09

- Add a dependency-free PDF Inspector on its own HTML page. Inspect local uploads without rendering pages, running JavaScript, extracting attachments, or contacting destinations.
- Separate PDF analysis and PDF history from Mac audit controls, process actions, and scan history. Each page loads only its module script, with shared session helpers and clear links between pages. Opening the PDF page does not load audit code, Mac inventory, or audit history. Saved PDF reports remain available after returning; warn before leaving an in-progress analysis.
- Introduce a responsive PDF layout with a document selection card, inspection steps, grouped evidence, mobile-friendly labeled rows, a clear action, and subtle reduced-motion-aware transitions.
- Record document SHA-256, headers, recovered objects, escaped names, supported compressed object streams, JavaScript excerpts, action triggers/chains, destinations, embedded-file references, and declared metadata.
- Distinguish document-open actions, document-level JavaScript registration, additional events, and user interaction. URL strings are not labeled as observed requests; no result declares a document safe or malicious.
- Bound uploads, worker time/CPU, decoded bytes, objects, tokens, nesting, and output. Encrypted, malformed, unsupported, revised, and limited documents disclose incomplete interpretation.
- Save owner-only HTML/JSON PDF reports and expose the latest 25 inspections separately from Mac scan history. Do not retain original PDFs.
- Require per-launch authorization for API calls and report access. The launcher exchanges a private fragment without a user account. API credentials are origin-scoped; report cookies use separate credentials and a private path. Restarting the server invalidates earlier credentials. Unauthenticated health is minimal.
- Fix YARA failure handling, including nonzero exit codes with empty stderr, and propagate collection errors to coverage context.
- Avoid reverse DNS during loopback server binding so slow hostname resolution cannot delay dashboard or portable-launcher startup.
- Preserve the previously released 1.4.4 history and tag. These are new changes, not a rewrite of the published release.

## 1.4.4 - 2026-10-04

- Document the trusted-local-session requirement and distinguish browser-origin protections from API client authentication. The local API is not intended as a shared service on a host with untrusted local accounts.
- Load report evidence, decision support, and export links as one selected snapshot. Ignore late responses from older selections and block process response while a report is loading.
- Keep investigation saves tied to the originating report when the user switches scans, and discard process candidates no longer displayed. Reject decision support with a mismatched scan identity while preserving access to the recorded report.
- Show local IOC/YARA rule context in both dashboard views, the standalone HTML report, and the investigation summary. Separate stable fingerprints from actual result availability, omitted checks, matches, and incomplete collection.
- Show bounded IOC pack provenance with declared version, update label, and source hostname. Do not copy URL credentials, query strings, fragments, or full source paths into the derived summary, and do not contact a source when opening it.
- Keep unsupported or missing historical rule context explicit, and prevent a loaded report from displaying another scan's rule summary. Preserve original evidence and comparison decisions.
- Distinguish an absent original PID from the same executable path and owner observed under another PID after a process action. Show the observed PIDs without claiming a restart, identical file contents, malware, or successful remediation.
- Require matching recorded host context and timezone-aware action, scan, and evidence times before interpreting a linked process follow-up. Prior, overlapping, malformed, and ambiguous snapshots remain unverifiable.
- Record the local hostname with new process actions. Older action logs remain visible; missing host or identity evidence prevents a verified follow-up outcome.
- Expand bundled synthetic validation from 18 to 26 scenarios, including alternate PIDs, different owners, invalid chronology, missing timestamps, different hosts, and duplicate process records.
- Accept Live Triage's normal `Observed` process status during follow-up, and record process-inventory completeness explicitly. Unparsed lines, duplicate PIDs, missing numeric owners, command failures, and collection bounds prevent absence inferences without discarding successfully observed processes.

## 1.4.3 - 2026-10-04

- Preserve application discovery errors as unknown inventory evidence instead of silently skipping unreadable directories. Keep discovered applications and block disappearance inferences from incomplete inventories.
- Prevent an unknown result or recorded collection gap from rounding a collector's completion up to 100%.
- Fingerprint local IOC/YARA bytes, locations, and relevant nonsecret configuration before and after collection. Withhold finding-presence and numeric index comparisons when fingerprints are missing, incomplete, unstable, or different.
- Add local process action history in both dashboard views, with preserved source-report access and linked read-only outcome rechecks. Distinguish the original identity still observed, PID reuse, zombie state, no longer observed, and unverifiable results without automatically resolving a finding.
- Include numeric process owner and start identity in the bounded process inventory and private action log so later snapshots can be compared safely. Older actions remain visible but cannot establish an identity-aware outcome.
- Add 18 bundled, synthetic trust and response regression scenarios, a dashboard validation action with downloadable JSON, a reproducible developer command, and explicit limits on interpreting fixture metrics.
- Test the dashboard in Chromium and WebKit and add targeted WCAG accessibility, keyboard-focus, responsive action-history, and validation-download checks.
- Make the double-click launcher try compatible Python candidates and open an offline setup-help page when none is available. No software installation, privilege escalation, or new online lookup is automatic.
- Replace manual comparison's "Resolved" and "New" presentation with baseline-only and comparison-only record labels, while preserving the legacy JSON field names for compatibility.
- Withhold manual overall and category index deltas when collection scope, recorded host, tool version, filtering, completion, or assessment context is insufficient; retain raw finding-record differences.
- Include selected snapshot times, comparison limits, and non-remediation wording in the dashboard and standalone comparison HTML, with responsive layouts for long evidence values.
- Record the scan's minimum severity in report metadata and show its finding filter in the dashboard and investigation summary.
- Withhold automatic inventory additions or disappearances when the relevant snapshot is filtered, incomplete, or missing collection-completion evidence. Preserve changes between records observed in both scans.
- Display unavailable comparison counts as "Not comparable", with explicit reasons, instead of silently substituting zero. Keep complete sections comparable when a different section fails.
- Include the collector's `CONTROL-` findings in security-control change highlights, including shared-record regressions in otherwise limited comparisons.
- Show comparable-scan changes in both dashboard views, including the earlier report's completion time and ID, a read-only action to open it, and expandable counts and highlights.
- Select automatic baselines by timezone-aware completion time rather than timestamp text, and require matching recorded hosts, valid section lists, and consistent report file identities.
- Describe missing findings and listeners as no longer recorded, not automatically resolved, and include baseline identity and interpretation limits in investigation summaries.
- Show the collection window, report age, selected sections, application target, and tool version in an "About this scan" panel visible in both dashboard views.
- Label the assessment as belonging to the recorded scan and include collection times and scope in standalone investigation summaries.
- Add a one-click repeat action that preserves the report's section list and application target, uses current scan settings, and retains confirmation for online checks.
- Block repeating when the recorded section list is incomplete or unsupported, and prevent duplicate scan requests while a collection is active.
- Add "Refresh Live Triage" beside process-response controls to collect a new snapshot before or after an explicit process action.
- Show scan-start errors beside the loaded report and refer connection failures to the double-click launcher.

## 1.4.2 - 2026-10-02

- Keep Application Trust verdicts consistent with verification-completion evidence when macOS trust services return internal errors.
- Label signed Apple components that Gatekeeper cannot assess as standalone apps as "Gatekeeper not applicable", not rejected or unknown.
- Base application evidence confidence on completed checks and make release-checksum tests compatible with post-release development.
- Keep a separate permissions or integrity review visible when signature or Gatekeeper verification is incomplete, while showing the missing check and lowering evidence confidence.
- Require a Live Triage process snapshot no more than 15 minutes old and recheck the recorded process start, owner, parent, and executable before sending a termination signal; older reports cannot be used for process response.
- Keep isolated low-priority process signals, such as execution from a hidden user directory, as recorded context instead of presenting them as a process-response finding without corroboration.

## 1.4.1 - 2026-09-26

- Separate `Not Applicable` from passing checks in guided review. Disabled YARA, absent IOC packs, and missing supported browser profiles now appear as "Not assessed" with a relevant setup or scope check, rather than "Looks normal".
- Show a limited-scope assessment when a selected check finishes without an applicable target. Execution coverage remains distinct from whether the check assessed files or activity.
- Clarify `Not Applicable` in standalone HTML reports and show `N/A` instead of a score when no findings were assessed.
- Keep `Unknown` and `Not Applicable` findings in reports even when a higher minimum severity is selected, so filtering cannot hide collection or applicability gaps.
- Mark pre-1.4.0 application trust failures with incomplete historical check metadata as needing a fresh verification. Preserve the original result while lowering evidence confidence and showing a recheck cue.
- Remove a dead IOC/YARA confidence shortcut; a single local rule match remains one evidence source, not multiple independent confirmations.
- Describe failed application trust checks as trust or integrity findings, not observed behavior. Indicator matches now enter the review queue without asserting that software is unwanted.
- Add Chromium dashboard smoke tests for Simple and Analyst views, incomplete-scan messaging, and narrow-screen layout. GitHub CI runs them before packaging.
- Record coverage for every selected collector, including collectors that fail or return no findings.
- Treat missing collection evidence as an incomplete scan in the guided assessment and provide a recheck step.
- Lower overall evidence confidence when selected checks are incomplete.
- Build portable ZIP archives with fixed metadata and without environment-dependent compression so identical source files produce identical archives.
- Show `N/A` instead of a numeric rule outcome index when no findings were assessed in dashboard history, comparisons, HTML, Markdown, and PDF. Preserve the raw JSON score with assessed-finding counts for compatibility, and use a null SARIF score for unassessed scans.
- Infer assessment counts for complete older reports without rewriting them. Keep finding-level comparison available when an index delta is not meaningful.
- Label the percentage shown to users as collection completion, not target assessment. An all-`Not Applicable` category no longer inflates the overall rule outcome index; unknown evidence still reduces it.
- Explain status availability in exported category tables and preserve clear scope notes for checks that did not assess a target.

## 1.4.0 - 2026-09-21

- Added Simple and Analyst dashboard views. Simple view keeps the recommended profiles, focused application check, current assessment, application review, reports, and history visible while Analyst view exposes complete collection and evidence controls.
- Added a four-state current assessment: no immediate warning identified, needs review, action recommended, or scan incomplete.
- Limited the primary response plan to three prioritized items. Each item explains what was observed, why it matters, what it does not prove, the next safe verification step, and the risk of taking action.
- Replaced the dashboard safety-style score presentation with separate review priority, collection coverage, and evidence confidence indicators. Existing report compatibility retains the numeric value under the more accurate rule outcome index label.
- Fixed large application bundles such as Xcode being shown with a false invalid-signature label when deep signature verification reached the generic command timeout.
- Added bounded per-command timeouts for deep signature and Gatekeeper checks and recorded incomplete checks as unknown instead of invalid or rejected.
- Distinguished Mac App Store acceptance from a separately reported notarization result.
- Corrected stale portable-release filenames and clarified that process containment is the only explicit host-changing response action.

## 1.3.3 - 2026-09-21

- Added a comparison note when the baseline and current reports were created by different macOS Inspector versions, so expanded collector coverage is not mistaken for proof that the system changed.
- Included the same comparison context in standalone investigation summaries.
- Separated evidence-only coverage updates from actual application changes in dashboard counts and filters.

## 1.3.2 - 2026-09-21

- Replaced generic application-change notices with explanations for possible updates, executable-content changes, signing-identity changes, and signature or Gatekeeper regressions.
- Added previous and current values for version, Team ID, signature state, Gatekeeper state, notarization, hardened runtime, signature type, and executable SHA-256 when those fields change.
- Added a **Changed since last scan** application filter and placed the same change explanation inside the relevant application card.
- Added a concrete validation step to dashboard changes and standalone investigation summaries without treating a change as proof of tampering.
- Added regression coverage for update context, signer replacement, trust regression, changed-content review, and compact hash display.
- Kept the complete application-change set available to the review queue while limiting only the summary highlights, so large inventories no longer lose card-level change context.
- Prioritized trust regressions, Team ID replacements, and bundle-identity changes before routine context in both summary and filtered card views, and recognized Apple-signed system-app changes that coincide with a recorded macOS update.
- Prevented update context from hiding a current failed, review, or unknown trust result, and raised unverifiable new applications above routine additions.
- Added explicit change explanations for weakened executable or Info.plist permissions, bundle path regressions, and newly detected trust concerns.
- Added a visible count for applications no longer present and a plain-language inventory event with a confirmation step for unexpected disappearance.

## 1.3.1 - 2026-09-21

- Added a plain-language publisher and acquisition panel to every Application Trust review card.
- Showed the signing identity, signature type, Gatekeeper source, Team ID, installation scope, download agent, and recorded download time without turning those observations into a trust verdict.
- Reduced recorded download URLs to source hostnames in the application queue and standalone investigation summary so URL paths and query parameters are not copied into the compact view.
- Explained that missing acquisition metadata is not a risk signal by itself and kept the complete local evidence available in the original report.
- Added responsive layouts and regression coverage for publisher context, source-host privacy, and standalone summary output.

## 1.3.0 - 2026-09-19

- Added exact-path activity context to every Application Trust review row when the same scan includes Live Triage or Persistence evidence.
- Added a focused **Check trust and activity** action for one selected application alongside the faster trust-only check.
- Added plain-language labels for running processes, network listeners or established connections, and startup items, with expandable source details.
- Added an **Active in this scan** filter while keeping activity separate from trust severity and malware conclusions.
- Added a privacy-limited process inventory containing PID, parent PID, state, runtime, and executable path without retaining the complete command line for every process.
- Included application activity context in standalone investigation summaries.
- Prevented similarly named neighboring bundles from being correlated by requiring the executable to be inside the exact application path.

## 1.2.9 - 2026-09-19

- Added a plain-language application review queue that separates results into **Review first**, **Needs context**, **Unable to verify**, **Checks passed**, and **Reviewed locally** without treating a trust observation as a malware verdict.
- Added concise evidence-backed signals for signature failures, Gatekeeper rejection, escaped bundle executables, unstable hashes, writable executable permissions, sensitive entitlements, missing hashes, and incomplete notarization or signing identity.
- Added one-click access to the complete finding and a focused recheck for the exact application path, with the existing server-side inventory validation preserved.
- Included the application review queue in standalone investigation summaries and added responsive layouts for narrow browser windows.
- Corrected portable-release filenames in the public installation documentation.

## 1.2.8 - 2026-09-18

- Added a focused Application Trust workflow that lets a user search the locally discovered application inventory and inspect one selected app without waiting for a full inventory scan.
- Restricted targeted scans to exact application paths found under the standard macOS application folders; the dashboard does not accept an arbitrary file-system path.
- Recorded the target application in JSON, HTML, Markdown, SARIF, job history, and comparison scope.
- Limited automatic change analysis to earlier scans with the same collectors and the same target application, preventing focused and full scans from being treated as equivalent baselines.
- Made portable builds write and refresh their adjacent `SHA256SUMS` file automatically.

## 1.2.7 - 2026-09-18

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
