from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def read_bytes_limited(path: Path, max_bytes: int) -> bytes:
    """Read at most max_bytes from a file and reject content beyond the limit."""
    if max_bytes < 1:
        raise ValueError("File size limit must be positive.")
    with path.open("rb") as handle:
        payload = handle.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError(f"{path.name} exceeds the {max_bytes}-byte size limit.")
    return payload


def read_text_limited(path: Path, max_bytes: int, encoding: str = "utf-8") -> str:
    return read_bytes_limited(path, max_bytes).decode(encoding)


def read_json_limited(path: Path, max_bytes: int) -> Any:
    return json.loads(read_bytes_limited(path, max_bytes).decode("utf-8"))
