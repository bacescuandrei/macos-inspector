# Threat model

## Security goals

- Keep routine collection read-only.
- Prevent the dashboard from becoming a general command runner.
- Restrict process containment to a current-user identity explicitly recorded by Live Triage.
- Keep reports, settings, keys, and case records local unless the analyst exports them.
- Make report tampering detectable when a manifest is used.
- Prevent imported files and external responses from escaping their intended scope.

## Protected data

Protected data includes collected evidence, reports, case notes, provider keys, signing keys, bundle passwords, imported IOC packs, and YARA rules.

## Main threats

### Arbitrary command execution

Collectors must use `CommandRunner`. Shell execution, `sudo`, package installation, and caller-supplied command lines are not allowed.

### Dashboard exposure

The dashboard accepts loopback addresses only. Every request must use a localhost or loopback IP `Host` authority for the active server port. Browser requests that include an `Origin` must use the same local HTTP boundary. These checks reject DNS rebinding and cross-origin write attempts before an API route is processed. Operations that create or change local state, including investigation notes, use `POST` or `DELETE` and require the dashboard's custom request header. File and report routes resolve paths against managed directories. Responses containing evidence are not cached and include same-origin resource and framing restrictions.

The alternative of relying only on a custom request header was rejected because a DNS-rebound page can become same-origin with its own hostile hostname. Per-launch random bearer tokens would provide another defense, but they would add secret lifecycle and launcher-to-browser transfer complexity. Strict local authority validation preserves the current launcher and CLI behavior while directly enforcing the documented loopback boundary.

Browser-origin validation remains separate from client authentication. Every server instance creates independent random launch, API, and report credentials. The launcher reads an owner-only private link from the output directory; the fragment is exchanged using a protected POST and removed from the address. The API credential is kept in origin-scoped browser session storage and sent as a Bearer header, never attached to cross-origin requests. Report downloads use a distinct HttpOnly, SameSite=Strict cookie scoped to an unguessable private report path. That cookie cannot authorize API calls or process response. HTTP cookies are not inherently port-isolated; a private path and separate report credential reduce that exposure, but do not provide a secure multi-tenant browser environment.

On macOS, the browser handoff passes its private link through AppleScript stdin, not an `open` command argument. The browser still receives the capability URL and remains part of the trusted session. Do not share the launch link, private launch file, browser state, or diagnostic captures of authorization requests.

Static interface assets and minimal status/version health are public on loopback. API data, PDF uploads, report downloads, settings changes, and process response require a credential. Health without authentication exposes no job or evidence context. A restart invalidates old credentials. The launch file is removed on normal shutdown; credentials are not recorded in scan reports, request logs, or packaged artifacts. Session access identifies possession of the launch capability, not a named human or independently authenticated OS user. Process ownership is still checked against the dashboard's effective user. A compromised same-user account, browser, administrator, or operating system can steal credentials or evidence. Keep the dashboard in a trusted local session and close it when finished.

### Process response

Process response is not an arbitrary PID or signal API. A request must reference a managed JSON report and a `Review` candidate from the Live Triage process-tree or process/network finding. Its evidence snapshot must be no more than 15 minutes old and must contain a process start identity. The recorded numeric owner must match the dashboard user. Immediately before acting, the server resolves the PID again and requires the live numeric owner, parent PID, executable path, and process start to match the report. These checks reduce stale-report and PID-reuse errors, but cannot eliminate the race between final revalidation and signal delivery.

PID 1, the dashboard process, and its parent are protected. Response is disabled when the dashboard runs as root. `SIGTERM` and `SIGKILL` are separate choices with separate local confirmations; `SIGKILL` is presented as a last resort because it prevents cleanup and can lose data. A zombie has already exited and is never signaled. Successful actions are appended to a bounded owner-only local audit log.

These controls reduce accidental or cross-user termination but cannot determine whether a candidate is malicious. The analyst remains responsible for validating the finding, preserving volatile evidence, understanding operational impact, and confirming current state with a new scan.

### Malicious or malformed input

IOC packs, YARA rules, browser data, local state files, scan reports, manifests, command output, and intelligence responses may be malformed or hostile. Parsers apply size, count, path, schema, timeout, and output limits. Large report downloads are streamed with bounded memory use. HTML output escapes collected values.

PDF Inspector accepts at most 25 MiB and processes one upload at a time in a separate worker. The upload has a ten-second read timeout; analysis has a twenty-second wall-clock timeout and ten-second worker CPU limit. Linux additionally enforces a 512 MiB address-space limit; macOS uses file, object, token, nesting, decoded-byte, evidence, and time bounds, not a hard address-space limit. The worker is not an OS sandbox and runs as the current user. It contains no renderer, JavaScript interpreter, attachment execution, or destination-fetch path. The original PDF is not persisted; derived reports are owner-only. Unsupported decoding, encryption, unresolved references, revisions, malformed syntax, and resource exhaustion restrict interpretation. Attachment contents, reader exploits, and dynamic/obfuscated script behavior are not comprehensively analyzed. No result establishes that a document is safe or malicious.

### Secret disclosure

Common secret-bearing process arguments are redacted before persistence. Provider credentials and private signing material are omitted from public settings and reports. Bundle passwords are kept only for the active export.

### Evidence tampering

Manifests record SHA-256 digests for normalized evidence and generated reports. Optional signatures bind the manifest to local HMAC material or an asymmetric identity. A valid digest proves consistency with the manifest, not the truth of the original host state.

### External intelligence

Online providers are optional. A provider result supplies context and does not prove compromise or local exposure. The application validates provider responses and records cache provenance.

Hash reputation providers are disabled by default. A request requires a local confirmation and sends only the displayed SHA-256 to the enabled VirusTotal, MalwareBazaar, or ThreatFox API. It does not upload the executable, application bundle, local path, hostname, case data, or report. Provider keys remain in the owner-only settings store. A provider match is context that still requires validation, and a missing record is never presented as proof that a file is safe.

### Derived decision support

Changes, confidence labels, and investigation stories are derived from completed local reports. Automatic baseline selection requires the same collector set. Correlations require an exact application-path relationship and are labeled as investigation aids rather than compromise conclusions. The derived output cannot alter the source report or its evidence manifest.

### Response history and comparison context

The private response log records a successfully sent signal, not a confirmed exit or incident resolution. It is bounded, rotates one previous file, and is not tamper-proof against a same-user attacker. Source evidence and investigation state remain separate. Linked follow-up accepts only a retained local action and a read-only, unfiltered Live Triage scan. Missing identity, truncated inventory, unavailable collection, and legacy logs produce an unverifiable outcome. A PID with a different start identity is not treated as the original process. No outcome authorizes another signal automatically.

Follow-ups validate action, scan-window, and evidence timestamps and require matching recorded hostnames. This prevents ordinary use of a prior, overlapping, or wrong-host report, but does not authenticate the host or protect timestamps from same-user modification or clock changes. A matching executable path and owner under another PID establishes only that recorded observation, not a restart or matching file contents. Process collection is not atomic. Related activity may continue under other owners or executable paths, and a later absence is not proof of containment.

Rule-context fingerprints contain hashes and completion metadata, not provider secrets or rule text. They detect ordinary rule/configuration changes but do not authenticate rule provenance, establish rule quality, or provide an atomic snapshot against malicious filesystem races. Missing or changed context suppresses unsupported finding-presence and numeric-index claims while preserving raw report differences. Synthetic validation scenarios invoke pure classification only and cannot run imported commands, scan arbitrary paths through the dashboard, or send signals.

## Out of scope

macOS Inspector is not an EDR, anti-malware engine, memory acquisition tool, or complete forensic imaging system. It does not continuously monitor or automatically remediate a host. It does not defend a compromised operating system from falsifying command output. It does not guarantee legal admissibility or chain of custody for every jurisdiction.
