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

### Process response

Process response is not an arbitrary PID or signal API. A request must reference a managed JSON report and a `Review` candidate from the Live Triage process-tree or process/network finding. The recorded numeric owner must match the dashboard user. Immediately before acting, the server resolves the PID again and requires the live numeric owner and executable path to match the report. This check limits stale-report and PID-reuse errors.

PID 1, the dashboard process, and its parent are protected. Response is disabled when the dashboard runs as root. `SIGTERM` and `SIGKILL` are separate choices with separate local confirmations; `SIGKILL` is presented as a last resort because it prevents cleanup and can lose data. A zombie has already exited and is never signaled. Successful actions are appended to a bounded owner-only local audit log.

These controls reduce accidental or cross-user termination but cannot determine whether a candidate is malicious. The analyst remains responsible for validating the finding, preserving volatile evidence, understanding operational impact, and confirming current state with a new scan.

### Malicious or malformed input

IOC packs, YARA rules, browser data, local state files, scan reports, manifests, command output, and intelligence responses may be malformed or hostile. Parsers apply size, count, path, schema, timeout, and output limits. Large report downloads are streamed with bounded memory use. HTML output escapes collected values.

### Secret disclosure

Common secret-bearing process arguments are redacted before persistence. Provider credentials and private signing material are omitted from public settings and reports. Bundle passwords are kept only for the active export.

### Evidence tampering

Manifests record SHA-256 digests for normalized evidence and generated reports. Optional signatures bind the manifest to local HMAC material or an asymmetric identity. A valid digest proves consistency with the manifest, not the truth of the original host state.

### External intelligence

Online providers are optional. A provider result supplies context and does not prove compromise or local exposure. The application validates provider responses and records cache provenance.

Hash reputation providers are disabled by default. A request requires a local confirmation and sends only the displayed SHA-256 to the enabled VirusTotal, MalwareBazaar, or ThreatFox API. It does not upload the executable, application bundle, local path, hostname, case data, or report. Provider keys remain in the owner-only settings store. A provider match is context that still requires validation, and a missing record is never presented as proof that a file is safe.

### Derived decision support

Changes, confidence labels, and investigation stories are derived from completed local reports. Automatic baseline selection requires the same collector set. Correlations require an exact application-path relationship and are labeled as investigation aids rather than compromise conclusions. The derived output cannot alter the source report or its evidence manifest.

## Out of scope

macOS Inspector is not an EDR, anti-malware engine, memory acquisition tool, or complete forensic imaging system. It does not continuously monitor or automatically remediate a host. It does not defend a compromised operating system from falsifying command output. It does not guarantee legal admissibility or chain of custody for every jurisdiction.
