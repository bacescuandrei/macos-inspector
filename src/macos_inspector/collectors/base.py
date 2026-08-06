from __future__ import annotations

from abc import ABC, abstractmethod

from macos_inspector.core.models import Finding
from macos_inspector.core.runner import CommandRunner


class Collector(ABC):
    collector_id: str
    title: str

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    @abstractmethod
    def collect(self) -> list[Finding]:
        raise NotImplementedError

