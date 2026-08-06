import json
from pathlib import Path

from macos_inspector.core.models import ScanResult
from .common import secure_write_text


def write_json(result: ScanResult, path: Path) -> None:
    secure_write_text(path, json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n")
