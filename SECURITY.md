# Security policy

## Runtime security boundary

macOS Inspector is a local inspection and triage tool with read-only collectors. The dashboard accepts only loopback connections and rejects non-local `Host` authorities and browser `Origin` values before routing requests. Browser actions map to registered operations, system commands come from a fixed allowlist, and commands run without a shell. The project does not invoke `sudo`, install software, delete or quarantine files, or change security configuration.

The only containment operation is an analyst-confirmed signal to a current-user process that a loaded Live Triage report explicitly lists as a review candidate. The server rechecks the live PID owner and executable before sending `SIGTERM` or `SIGKILL`, rejects arbitrary or stale identities, protects its own PID and parent, disables response while running as root, and writes successful actions to an owner-only local audit log. Zombie processes are reported but cannot be signaled because they have already exited.

Local scan profiles do not contact external intelligence services. The online vulnerability profile requires confirmation and sends only public Apple CVE identifiers to enabled providers. Manual ThreatFox lookup is separate, disabled by default, and sends only an indicator entered and confirmed by the analyst.

Reports and application state can contain sensitive host and case data. Private state files use owner-only permissions, but exported reports must be handled under the applicable evidence policy. Common secret-bearing process arguments are redacted on a best-effort basis and should not be treated as a complete data-loss prevention control.

Full Disk Access is optional and is never requested or bypassed automatically. If policy permits broader collection, grant it to the application that launches Python, such as Terminal. Never disable System Integrity Protection, Gatekeeper, or TCC protections to run the tool.

## Supported version

Security fixes are applied to the latest release. Older releases may not receive a backport.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from the repository Security tab. Do not open a public issue for a suspected vulnerability.

Include the affected version, a clear reproduction case, the expected security boundary, and the practical impact. Remove hostnames, usernames, credentials, case material, and collected evidence that is not required to reproduce the problem.

The maintainer will confirm receipt, assess the report, and coordinate a fix and disclosure when the report is valid. No response-time guarantee is provided.

## Scope

Relevant reports include arbitrary command execution, unauthorized or misdirected process signaling, process-identity validation bypass, path traversal, unsafe report access, secret disclosure, bypass of the local-only server boundary, unsafe handling of imported IOC or YARA files, and weaknesses in manifest or encrypted-bundle handling.

Reports about expected read-only permission failures, missing Full Disk Access, or findings produced by third-party intelligence sources are not security vulnerabilities by themselves.

For the detailed trust boundary, see [Threat model](docs/THREAT_MODEL.md). For safe installation and Gatekeeper guidance, see [Installation and verification](docs/INSTALLATION.md).
