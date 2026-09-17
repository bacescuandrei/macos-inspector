# Architecture

macOS Inspector is a local Python application with a browser-based interface. The dashboard binds to the loopback interface and calls a fixed HTTP API exposed by the local process.

## Collection path

1. The CLI or dashboard selects registered collectors.
2. Each collector uses `CommandRunner` for allowlisted commands with fixed argument rules and timeouts.
3. Collectors return immutable `Finding` and `Evidence` records.
4. The scan layer records metadata, errors, scores, coverage, and timeline events.
5. Reporters serialize the completed result without collecting additional evidence.

Collectors do not write reports. Reporters do not run host commands. This boundary keeps collection behavior reviewable and allows parser tests to run with fixtures on non-macOS systems.

## Main packages

- `collectors`: read-only host inspection and parsing logic.
- `core`: models, command execution, scan orchestration, scoring, storage, comparison, intelligence caching, and timeline generation.
- `reporters`: HTML, JSON, Markdown, CSV, SARIF, PDF, manifest, ZIP, and encrypted ZIP output.
- `web.py`: loopback-only dashboard API, job state, cancellation, settings, cases, and report access.
- `webui`: static HTML, CSS, and JavaScript served by the local dashboard.

## Trust boundaries

Host commands, local files, imported rules, intelligence responses, and browser requests are treated as untrusted input. Values are parsed, bounded, escaped, or validated before they are stored or rendered. The web boundary validates each `Host` and any browser `Origin` against the active loopback server port before routing a request.

Online intelligence is separate from local collection. Providers receive public vulnerability identifiers or an indicator entered by the analyst. Collected host evidence is not uploaded.

## Extension rules

A new collector must have a stable identifier, remain useful without elevated privileges, report unavailable data honestly, and return normalized findings. A new dashboard action must map to a registered operation and must not accept arbitrary commands.
