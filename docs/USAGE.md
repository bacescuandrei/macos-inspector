# Usage and interpretation

This guide explains the dashboard workflows, representative results, and the next investigative step. Examples are derived from the project's automated fixtures and are not claims about a real host.

## Guided investigation

Select **Check this Mac** on the start guide for the recommended offline Quick triage profile. After the scan, the dashboard groups results into items that need attention, checks that could not be completed, and findings that look normal or were already resolved.

The dashboard starts in **Simple** view. It shows the recommended workflows, focused application check, current assessment, the three highest-priority next steps, application review, report links, and scan history. Choose **Analyst** when you need individual collectors, custom formats, readiness details, raw findings, commands, timelines, cases, rules, or evidence controls. Opening a technical result switches to Analyst view automatically.

The current assessment has four possible states:

- `No immediate warning identified`: the selected checks produced no result that currently needs attention.
- `Needs review`: one or more observations need owner or analyst context.
- `Action recommended`: at least one high-priority rule outcome needs prompt validation.
- `Scan incomplete`: no immediate warning was identified, but important evidence could not be collected.

The assessment shows review priority, collection coverage, and evidence confidence separately. Coverage includes every selected section, even when a section fails or returns no findings. Incomplete evidence lowers the confidence label and provides a step to check readiness and rerun the same scan. The retained rule outcome index is a compatibility and comparison value, not a probability that the Mac is safe or compromised.

Each recommended action states what was observed, why it matters, what it does not prove, the next safe validation step, and the risk of acting. Expand **Details** for commands, raw evidence, application identity, executable hashes, process context, and the full rule explanation.

Use investigation states to record progress:

- `New`: not yet reviewed.
- `Investigating`: validation is in progress.
- `Expected`: the current evidence matches an accepted application or host condition.
- `Suspicious`: the item requires escalation or deeper analysis.
- `Contained`: an immediate response action was completed.
- `Resolved`: remediation was verified with a new scan.

Investigation notes are stored locally and do not change the signed or exported scan report. An `Expected` decision is not a permanent allowlist. If the underlying application identity, hash, signature, Gatekeeper result, process identity, or other security evidence changes, the dashboard returns the finding to `New` and shows the previous decision as stale.

## Changes and investigation stories

After a scan, **Changes since last comparable scan** automatically selects the newest earlier report with the same collection scope. For a focused application check, that includes the exact target application. It highlights new, changed, or removed applications, new startup items, new listeners, changed security controls, and resolved findings. An application that is no longer present becomes a review item and asks you to confirm that its removal was intentional, without treating the disappearance as a security conclusion. If no equivalent earlier report exists, the current scan becomes the starting point for the next comparison.

When the two reports were created by different macOS Inspector versions, the comparison includes a note about the version difference. New collectors or updated detection rules can expose evidence that was already present but not evaluated by the earlier version. Treat that evidence as newly observed unless the compared field values show that the system itself changed.

If only the available evidence expanded and no compared identity or trust field changed, the application appears under **New evidence coverage** instead of **Changed since last scan**. This keeps collection improvements visible without inflating the application-change count.

For applications, the dashboard explains what changed instead of showing only a generic alert. A version and executable change with the same Team ID is shown as a possible update only when the current trust result does not still need review. A system-application change recorded at the same time as a macOS version change is presented as operating-system update context under the same condition. A current failed, review, or unknown result remains prominent even when update evidence is present. Newly weakened executable or Info.plist permissions and an executable that starts resolving outside its bundle receive their own high-visibility explanations. An executable change without update context is kept for review. A different Team ID or a signature or Gatekeeper regression is raised more prominently and appears before routine changes. Expand the change to compare the previous and current values, then follow the displayed validation step. These categories prioritize investigation and do not prove that an application was updated legitimately or tampered with.

Investigation stories connect findings only when the evidence shares an exact application path. For example, an Application Trust finding can be connected to a running process, listener, or startup mechanism inside the same application bundle. A story is an investigation aid, not a malware verdict.

The application review queue also includes a **Changed since last scan** filter when a comparable baseline is available. Each matching application card contains the same field-level change explanation used by the decision-support section. Current activity appears when the loaded scan contains both Application Trust and the relevant Live Triage or Persistence evidence. **Running**, **network endpoint**, and **startup item** labels mean that an executable path inside the exact bundle appeared in that evidence. A similarly named application is not treated as a match. Activity is useful investigation context, not a negative trust signal.

Confidence describes how complete and direct the supporting evidence is. It does not describe impact. A high-severity finding can have low confidence when collection failed, and a normal observation can have high confidence when several local checks agree.

## Hash reputation

VirusTotal, MalwareBazaar, and ThreatFox are disabled by default. Configure only the providers you intend to use. Select **Check hash reputation** inside an application finding and confirm the exact SHA-256 before the request is sent. Only the hash is transmitted; the application file is never uploaded. Results are cached locally with provider provenance. A result of `not found` means only that the provider returned no record.

## Investigation summary

Select **Export investigation summary** to create a standalone HTML overview with current priorities, high-signal changes, correlated stories, and investigation-state counts. The summary links conclusions back to observations while leaving the original report unchanged.

## Start with readiness

Open **Collection readiness** before the first scan. It checks the macOS and Python environment, trusted command availability, report storage, visible applications, TCC and browser database access, PDF support, and optional asymmetric signing support.

`Limited` means that a collector may have reduced visibility. It does not mean the application failed. Record important limitations in the case notes and do not convert unavailable evidence into a pass.

## Interpret status and severity

Status describes the rule outcome. Severity sets review priority.

- `Pass`: the specific expectation was met. It is not a clean-host verdict.
- `Observed`: state or inventory was recorded without a negative conclusion.
- `Review`: analyst context is needed.
- `Fail`: a defined expectation was not met.
- `Unknown`: evidence was incomplete or unavailable.
- `Match`: an imported IOC or YARA rule matched within the selected scope.
- `Not Applicable`: the component or optional feature was not present in scope.

A high-severity `Review` can be more urgent than a low-severity `Fail`, but neither proves compromise. Read the explanation, expected result, observed result, evidence, commands, and collection notes together.

## Quick triage

### Goal

Create a broad initial view of accounts, running activity, persistence, background items, security controls, management profiles, network configuration, system extensions, and imported IOCs.

### Steps

1. Select **Quick triage**.
2. Attach a saved case or enter a case reference and analyst when required.
3. Run the scan with the default report formats.
4. Review high and critical priorities, unknown coverage, and recent changes.

### Representative result

```text
FileVault: Pass
Gatekeeper: Pass
System Integrity Protection: Pass
Application firewall: Pass
Automatic updates: Pass
Firewall stealth mode: Review
Remote Login: Pass when no service is listed
```

### Interpretation

Each row evaluates one control or observation. Stealth mode being off can deserve review under a hardened baseline, but it is not evidence of intrusion. A passing Gatekeeper check does not validate every installed application.

### Next step

Compare the result with the organization's baseline, record approved exceptions, inspect unexpected accounts or persistence, and use a focused workflow for anything that needs deeper evidence.

### Limitations

Quick triage favors breadth. It is not a disk image, memory acquisition, retrospective network log, or complete malware scan.

## Application Trust

### Goal

Evaluate visible application bundles using macOS trust and integrity signals.

### Steps

For one unfamiliar application:

1. In **Check one application**, type part of the application name or path.
2. Select the application from the filtered local list.
3. Select **Check trust only** for the fastest focused result, or select **Check trust and activity** to collect Live Triage and Persistence context for the same exact app.
4. Review the signature, notarization, Gatekeeper context, hardened runtime, entitlements, quarantine metadata, bundle layout, symlinks, writable components, sealed resources, and executable placement.

For a complete inventory, select **Application Trust**, run the scan, wait for all visible bundles to finish, then filter the results by application name, status, severity, Team ID, or path.

After either scan, use **Which applications should I look at first?** to review the application queue:

- **Review first** contains failed trust checks and high-priority review observations.
- **Needs context** contains lower-priority observations that still need owner or analyst validation.
- **Unable to verify** keeps incomplete evidence separate from passing checks.
- **Checks passed** means only that the displayed trust checks succeeded; it is not a safe-software verdict.
- **Reviewed locally** contains results currently marked `Expected` or `Resolved` in the local investigation record.

Select **Active in this scan** to see applications that were running, owned a listener or established connection, or were referenced by a launch item. Expand **Why this app appears active** to see the matching PID, endpoint, or startup definition. No fuzzy application-name match is used. An active application can be entirely expected, and an inactive application can still require review.

Expand **Who signed this app and where did it come from?** to review the human-readable signing identity, signature type, Team ID, Gatekeeper source, installation scope, download agent, download time, and source hostname available in local macOS metadata. The compact view shows only source hostnames so URL paths and query parameters are not copied into the investigation summary. Complete acquisition evidence remains in the original local report.

Open a result for its complete evidence or select **Recheck this app** to run a new focused Application Trust scan for the exact recorded path. The server validates the path against the current local application inventory before collection.

For a negative Application Trust result from a scan made before 1.4.0, the dashboard checks whether the report recorded completion of signature and Gatekeeper verification. If a negative check lacks that completion evidence, the review card marks it as historical, lowers evidence confidence, and recommends a fresh check. The original finding and saved report remain unchanged. A newer `Pass` after an older `Fail` can reflect improved collection rather than a repaired application; compare the evidence before closing the investigation.

The target path is recorded in the report. Changes since the previous comparable scan use only an earlier scan with the same target and collector scope. The selector includes applications discovered in the standard system, global, and current-user application folders; it does not accept an arbitrary path.

### Representative result

```text
Finding: Application trust: Test
Status: Pass
Severity: Informational
Observed: The signature is valid, hardened runtime is enabled,
notarization is accepted, and the executable is inside the bundle.
```

### Interpretation

The application met those specific checks. Code signing identifies signed content and its signer; it does not prove the publisher is honest or the software's behavior is safe. Download metadata records what macOS observed during acquisition, but it does not authenticate the website or prove that the application remained unchanged. Missing quarantine or source metadata is not suspicious by itself. A validly signed application can still be unwanted or vulnerable. Likewise, a review-queue position is a prioritization aid, not a malware classification.

### Next step

Confirm the expected publisher and Team ID through a trusted source. Compare hashes or versions with approved inventory, inspect requested entitlements, and correlate the application with persistence, process, and network evidence.

### Limitations

Only visible bundles are assessed. Gatekeeper may treat Apple-managed system components differently from third-party applications. Mutable resources, runtime-loaded code, user data, and remote service behavior require separate analysis.

## Privacy and browsers

### Goal

Review sensitive TCC grants and bounded browser artifacts without copying an entire profile.

### Steps

1. Close supported browsers when the case permits it.
2. Select **Privacy and browsers**.
3. Review allowed grants for services such as Full Disk Access, Accessibility, Screen Recording, Camera, and Microphone.
4. Review the recent history, download, and extension rows returned for visible browser profiles.

### Representative result

```text
Status: Review
Observed: One client has an allowed Full Disk Access grant.
```

### Interpretation

An allowed grant is not inherently suspicious. The important questions are whether the client is correctly identified, signed by the expected publisher, required for an approved purpose, and still needed.

### Next step

Resolve the client identifier to an application, validate its signature and owner, compare the grant with policy, and preserve relevant browser records when the investigation requires a fuller acquisition.

### Limitations

TCC and browser databases can be protected or locked. Browser collection is bounded to supported profiles and recent rows, with a maximum of 50 rows per artifact type. Reports can contain sensitive browsing evidence.

## Vulnerability Intelligence

### Goal

Prioritize macOS updates using public vendor and vulnerability information without treating version correlation as compromise evidence.

### Steps

1. Select **Vulnerability Intelligence**.
2. Read and confirm the network disclosure notice.
3. Run the profile.
4. Review the exact local version and build alongside Apple Security Releases, CISA KEV, FIRST EPSS, and NIST NVD context.

### Representative result

```text
Local version: macOS 26.5.2, build 25F84
Latest release observed: macOS 26.6
Finding: Apple KEV applicability correlation
Status: Review
Observed: 1 possibly affected; 1 requires vendor-advisory review;
0 outside the evaluated version range.
```

### Interpretation

`Possibly affected` means the available version evidence did not exclude the local build. It does not prove that the vulnerable component is present, reachable, exploited, or responsible for suspicious activity.

### Next step

Read the Apple advisory, confirm the affected product and build range, verify installed rapid security responses, review compensating controls, and use incident evidence to assess exploitation.

### Limitations

Provider data can be delayed, rate-limited, unavailable, or ambiguous. Cached last-known-good data includes retrieval time and SHA-256 provenance. Provider errors produce `Unknown` context and do not invalidate local collector results.

## Threat Hunting

### Live process and network correlation

Goal: prioritize running processes by combining process tree, executable path, command context, working directory, runtime, and socket exposure.

Steps: select **Threat Hunting**, run the profile, then open **Process and network connection correlation**.

Representative result:

```text
Status: Review
Severity: High
Observed: 1 listener, 0 established connections, 1 high-priority candidate,
0 medium-priority candidates, 0 loopback-limited candidates.
```

Interpretation: the combined signals raised priority. A listener, a temporary path, or a development server is not malicious by itself. Loopback-only tools remain context unless other evidence raises their priority.

Next step: identify the process owner and parent, validate the executable and launch mechanism, inspect the listening address, compare with approved services, and acquire volatile evidence before containment.

For a process listed in the finding's **Process response** section, use **Terminate** to request a normal `SIGTERM`. The server acts only if the PID is still owned by the dashboard user and still resolves to the executable recorded in that scan. Run Live Triage again afterward to confirm the current state.

Use **Force kill** only when a validated process did not respond to normal termination and immediate containment is operationally justified. It sends `SIGKILL`, prevents application cleanup, and can lose unsaved data. Both actions require confirmation and are recorded in the private local response log. A zombie is already dead and cannot receive either signal; review its parent process and the reason it has not reaped the child.

Limitations: this is a point-in-time snapshot. Short-lived processes and connections can disappear during collection. A review candidate is not proof of malware. The identity check reduces PID-reuse risk but does not replace analyst validation. Command arguments are bounded and common secret forms are redacted, but complete secret detection is not guaranteed.

### IOC and YARA rules

Goal: compare explicit local targets with analyst-supplied indicators or YARA rules.

Steps: import a versioned IOC JSON pack or `.yar`/`.yara` file, review its source, enable YARA if required, select no more than ten explicit targets, then run **Threat Hunting**.

Representative result:

```text
Status: Match
Observed: The imported rule matched one file in an explicitly selected target.
```

Interpretation: a match reports rule logic, not a final malware verdict. False positives, overly broad strings, stale hashes, and test fixtures must be excluded.

Next step: preserve the matched object, calculate independent hashes, validate the rule source and version, inspect signature and provenance, and correlate with execution, persistence, and network evidence.

Limitations: YARA is optional and runs through a trusted local executable. The root directory and entire home directory are rejected as targets. Files and rules are not uploaded.

## Persistence review

### Goal

Identify user and system launch items and background services that require ownership and path validation.

### Steps

Run **Quick triage** or **Full local collection**, open persistence findings, then review the label, property-list path, executable, arguments, ownership, writable locations, enabled state, and file existence.

### Interpretation

Launch agents and daemons are common and often legitimate. Temporary or user-writable executable paths, missing executables, unexpected owners, unsigned code, and unexplained recent changes carry more weight than existence alone.

### Next step

Validate the publisher and business purpose, compare against configuration management, preserve the property list and executable, and correlate with Application Trust and live processes.

### Limitations

The scan records the visible current state. It cannot show a removed item unless another evidence source retains it.

## Full local collection

### Goal

Run every local collector without contacting intelligence services.

### Steps

Select **Full local collection**, confirm the report formats and case metadata, run the scan, then review unknown coverage before interpreting passes or scores.

### Result and interpretation

The result is a combined local evidence set and score. The score summarizes documented rule outcomes; it is not a probability that the host is safe or compromised.

### Next step

Export the required formats, verify the manifest, preserve the report directory or case bundle, and document any separate acquisition or containment action.

### Limitations

The workflow can take longer and still reflects live, permission-bounded evidence. It deliberately excludes online intelligence.

## Compare scans

Use scan history to select two completed scans with compatible result data. The comparison identifies added, removed, and changed findings using stable finding IDs.

A changed finding can reflect a real host change, a permission difference, an operating-system update, a rule change, or different collector scope. Confirm collection metadata before attributing the difference to attacker activity.

## Verify reports and bundles

Use **Verify evidence** from scan history to recalculate report and normalized-evidence digests and verify any manifest signature.

A valid digest shows that the checked bytes match the manifest. It does not prove that the original collection was complete, that the host clock was accurate, or that the signing identity belongs to a particular person. Verify asymmetric public-key fingerprints through a separate trusted channel.

Case-bundle ZIP files contain the reports for one scan, its manifest, a bundle index, and offline instructions. Encrypted bundles use AES-256-GCM with a Scrypt-derived key. Preserve the password separately because it cannot be recovered.

## Case notes and reporting

Record at least:

- case or incident reference
- analyst and collection time
- macOS version and build
- collector profile and report formats
- readiness limitations and permissions
- online providers used, if any
- imported IOC or YARA pack source and version
- interpretation, corroborating evidence, and unresolved questions

Do not publish raw reports without review. They can contain usernames, paths, host identifiers, browser activity, network endpoints, case notes, and other sensitive evidence.
