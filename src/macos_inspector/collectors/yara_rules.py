from __future__ import annotations

import re
from pathlib import Path

from .base import Collector
from macos_inspector.core.models import Evidence, Finding, Severity
from macos_inspector.core.storage import SettingsStore, application_data_dir


MAX_RULE_BYTES = 5 * 1024 * 1024
MAX_RULE_FILES = 50
MAX_TARGETS = 10


def discover_yara_rules(directory: Path) -> tuple[list[Path], list[str]]:
    rules, errors = [], []
    if not directory.is_dir():
        return rules, errors
    for path in sorted((*directory.glob("*.yar"), *directory.glob("*.yara")))[:MAX_RULE_FILES]:
        try:
            if not path.is_file() or path.stat().st_size > MAX_RULE_BYTES:
                errors.append(f"{path.name}: not a regular rule file or exceeds {MAX_RULE_BYTES} bytes")
                continue
            text = path.read_text(encoding="utf-8")
            if not re.search(r"\brule\s+[A-Za-z_][A-Za-z0-9_]*", text):
                errors.append(f"{path.name}: no YARA rule declaration was found")
                continue
            rules.append(path)
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path.name}: {type(exc).__name__}: {exc}")
    return rules, errors


def parse_yara_matches(text: str) -> list[dict[str, str]]:
    matches = []
    for line in text.splitlines()[:5_000]:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            matches.append({"rule": parts[0], "path": parts[1]})
    return matches


def _targets(values: list[str]) -> tuple[list[Path], list[str]]:
    targets, errors = [], []
    for value in values[:MAX_TARGETS]:
        path = Path(value).expanduser()
        try:
            resolved = path.resolve()
        except OSError:
            errors.append(f"{value}: cannot resolve path")
            continue
        if resolved == Path("/") or resolved == Path.home().resolve():
            errors.append(f"{value}: unrestricted root or home-directory scanning is not allowed")
        elif not resolved.exists():
            errors.append(f"{value}: target does not exist")
        else:
            targets.append(resolved)
    return targets, errors


class YARARulesCollector(Collector):
    collector_id = "yara-rules"
    title = "Managed YARA rules"
    description = "Runs locally managed YARA rules against an explicit, bounded target list when the optional yara binary is installed."

    def __init__(self, runner, settings: dict | None = None, rules_directory: Path | None = None) -> None:
        super().__init__(runner)
        self.settings = settings or SettingsStore().load()
        self.rules_directory = rules_directory or application_data_dir() / "yara-rules"

    def collect(self) -> list[Finding]:
        if not self.settings["yara"]["enabled"]:
            return [self._summary("Not Applicable", [], [], ["YARA scanning is disabled in local settings."], ())]
        rules, errors = discover_yara_rules(self.rules_directory)
        targets, target_errors = _targets(self.settings["yara"]["targets"])
        errors.extend(target_errors)
        if not rules or not targets:
            return [self._summary("Unknown", rules, targets, errors or ["No validated rules or targets are available."], ())]
        matches, commands = [], []
        total = min(len(rules) * len(targets), MAX_RULE_FILES * MAX_TARGETS)
        completed = 0
        for rule in rules:
            for target in targets:
                self.report_progress(f"{rule.name} → {target}", completed, total)
                result = self.runner.run(("yara", "-r", "-w", str(rule), str(target)))
                commands.append(result.command)
                if result.returncode == 127:
                    errors.append("The optional yara executable is not installed in a trusted path.")
                    return [self._summary("Unknown", rules, targets, errors, tuple(commands))]
                if result.timed_out:
                    errors.append(f"Timed out: {rule.name} → {target}")
                elif result.returncode not in {0, 1} and result.stderr:
                    errors.append(f"{rule.name}: {result.stderr[:500]}")
                matches.extend({**item, "rule_file": rule.name, "target": str(target)} for item in parse_yara_matches(result.stdout))
                completed += 1
                self.report_progress(None, completed, total)
        status = "Match" if matches else ("Review" if errors else "Pass")
        return [self._summary(status, rules, targets, errors, tuple(commands), matches)]

    def _summary(self, status: str, rules: list[Path], targets: list[Path], errors: list[str], commands: tuple[str, ...], matches: list[dict] | None = None) -> Finding:
        matches = matches or []
        return Finding(
            finding_id="YARA-MANAGED-SCAN", category="IOC Matches", title="Managed YARA local scan",
            severity=Severity.HIGH if matches else (Severity.LOW if errors and status != "Not Applicable" else Severity.INFORMATIONAL),
            status=status, description="Executes imported YARA rules locally against only the explicitly configured targets.",
            why_it_matters="Versioned local rules provide reproducible content-based threat hunting without uploading files or hashes.",
            what_was_checked=f"{len(rules)} rule file(s) against {len(targets)} explicit target(s)",
            expected_result="Rules validate and produce no matches in the configured scope.",
            observed_result=f"{len(matches)} match(es); {len(errors)} limitation(s)." if status != "Not Applicable" else errors[0],
            recommendation="Preserve and validate matched artifacts before remediation; install YARA or correct rules/targets when collection is limited.",
            evidence=(Evidence("yara_scan", "local", {"rules": [path.name for path in rules], "targets": [str(path) for path in targets], "matches": matches[:1_000], "errors": errors, "files_uploaded": False}),),
            commands_used=commands,
        )
