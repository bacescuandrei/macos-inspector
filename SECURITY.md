# Security policy

## Supported version

Security fixes are applied to the latest release. Older releases may not receive a backport.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from the repository Security tab. Do not open a public issue for a suspected vulnerability.

Include the affected version, a clear reproduction case, the expected security boundary, and the practical impact. Remove hostnames, usernames, credentials, case material, and collected evidence that is not required to reproduce the problem.

The maintainer will confirm receipt, assess the report, and coordinate a fix and disclosure when the report is valid. No response-time guarantee is provided.

## Scope

Relevant reports include arbitrary command execution, path traversal, unsafe report access, secret disclosure, bypass of the local-only server boundary, unsafe handling of imported IOC or YARA files, and weaknesses in manifest or encrypted-bundle handling.

Reports about expected read-only permission failures, missing Full Disk Access, or findings produced by third-party intelligence sources are not security vulnerabilities by themselves.
