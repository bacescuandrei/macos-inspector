# Threat model

## Security goals

- Keep routine collection read-only.
- Prevent the dashboard from becoming a general command runner.
- Keep reports, settings, keys, and case records local unless the analyst exports them.
- Make report tampering detectable when a manifest is used.
- Prevent imported files and external responses from escaping their intended scope.

## Protected data

Protected data includes collected evidence, reports, case notes, provider keys, signing keys, bundle passwords, imported IOC packs, and YARA rules.

## Main threats

### Arbitrary command execution

Collectors must use `CommandRunner`. Shell execution, `sudo`, package installation, and caller-supplied command lines are not allowed.

### Dashboard exposure

The dashboard accepts loopback addresses only. Every request must use a localhost or loopback IP `Host` authority for the active server port. Browser requests that include an `Origin` must use the same local HTTP boundary. These checks reject DNS rebinding and cross-origin write attempts before an API route is processed. File and report routes resolve paths against managed directories. Responses containing evidence are not cached and include same-origin resource and framing restrictions.

The alternative of relying only on a custom request header was rejected because a DNS-rebound page can become same-origin with its own hostile hostname. Per-launch random bearer tokens would provide another defense, but they would add secret lifecycle and launcher-to-browser transfer complexity. Strict local authority validation preserves the current launcher and CLI behavior while directly enforcing the documented loopback boundary.

### Malicious or malformed input

IOC packs, YARA rules, browser data, command output, and intelligence responses may be malformed or hostile. Parsers apply size, count, path, schema, timeout, and output limits. HTML output escapes collected values.

### Secret disclosure

Common secret-bearing process arguments are redacted before persistence. Provider credentials and private signing material are omitted from public settings and reports. Bundle passwords are kept only for the active export.

### Evidence tampering

Manifests record SHA-256 digests for normalized evidence and generated reports. Optional signatures bind the manifest to local HMAC material or an asymmetric identity. A valid digest proves consistency with the manifest, not the truth of the original host state.

### External intelligence

Online providers are optional. A provider result supplies context and does not prove compromise or local exposure. The application validates provider responses and records cache provenance.

## Out of scope

macOS Inspector is not an EDR, anti-malware engine, memory acquisition tool, or complete forensic imaging system. It does not defend a compromised operating system from falsifying command output. It does not guarantee legal admissibility or chain of custody for every jurisdiction.
