from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def command(self) -> str:
        return " ".join(self.argv)


class ScanCancelled(Exception):
    """Raised when a dashboard scan is cancelled cooperatively."""


class CommandRunner:
    """Executes allowlisted, read-only commands without a shell."""

    ALLOWED = {
        "codesign": "/usr/bin/codesign",
        "csrutil": "/usr/bin/csrutil",
        "defaults": "/usr/bin/defaults",
        "fdesetup": "/usr/bin/fdesetup",
        "launchctl": "/bin/launchctl",
        "plutil": "/usr/bin/plutil",
        "profiles": "/usr/bin/profiles",
        "scutil": "/usr/sbin/scutil",
        "security": "/usr/bin/security",
        "sfltool": "/usr/bin/sfltool",
        "softwareupdate": "/usr/sbin/softwareupdate",
        "socketfilterfw": "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "spctl": "/usr/sbin/spctl",
        "system_profiler": "/usr/sbin/system_profiler",
        "systemextensionsctl": "/usr/bin/systemextensionsctl",
        "uname": "/usr/bin/uname",
        "xattr": "/usr/bin/xattr",
    }

    def __init__(self, timeout: int = 15, cancel_event: threading.Event | None = None) -> None:
        self.timeout = timeout
        self.cancel_event = cancel_event

    def run(self, argv: Sequence[str]) -> CommandResult:
        if self.cancel_event and self.cancel_event.is_set():
            raise ScanCancelled("Scan cancelled by user.")
        if not argv:
            raise ValueError("Empty command")
        requested = str(argv[0])
        executable = Path(requested).name
        if executable not in self.ALLOWED:
            raise ValueError(f"Command is not in the read-only allowlist: {executable}")
        trusted_path = self.ALLOWED[executable]
        if Path(requested).parent != Path(".") and requested != trusted_path:
            raise ValueError(f"Command path is not trusted: {requested}")
        command = (trusted_path, *(str(part) for part in argv[1:]))
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)
            deadline = time.monotonic() + self.timeout
            while True:
                if self.cancel_event and self.cancel_event.is_set():
                    process.terminate()
                    try:
                        process.communicate(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                    raise ScanCancelled("Scan cancelled by user.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.kill()
                    stdout, stderr = process.communicate()
                    return CommandResult(command, 124, stdout.strip(), stderr.strip(), True)
                try:
                    stdout, stderr = process.communicate(timeout=min(0.2, remaining))
                    return CommandResult(command, process.returncode, stdout.strip(), stderr.strip())
                except subprocess.TimeoutExpired:
                    continue
        except FileNotFoundError as exc:
            return CommandResult(command, 127, "", str(exc))
