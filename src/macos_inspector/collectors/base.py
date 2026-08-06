from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from macos_inspector.core.models import Finding
from macos_inspector.core.runner import CommandRunner


class Collector(ABC):
    collector_id: str
    title: str

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self._progress_callback: Callable[[str | None, int, int], None] | None = None

    def set_progress_callback(self, callback: Callable[[str | None, int, int], None] | None) -> None:
        self._progress_callback = callback

    def report_progress(self, item: str | None, completed: int, total: int) -> None:
        if self._progress_callback:
            self._progress_callback(item, completed, total)

    @abstractmethod
    def collect(self) -> list[Finding]:
        raise NotImplementedError
