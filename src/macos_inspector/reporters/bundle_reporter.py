from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from macos_inspector.core.models import ScanResult


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_bundle(result: ScanResult, path: Path) -> None:
    """Create a portable ZIP containing only this scan's generated artifacts."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    prefix = f"macos-inspector-{result.metadata.scan_id}."
    artifacts = sorted(
        (
            candidate for candidate in path.parent.iterdir()
            if candidate.is_file()
            and candidate.name.startswith(prefix)
            and candidate.resolve() != path.resolve()
            and candidate.suffix.lower() != ".zip"
        ),
        key=lambda candidate: candidate.name,
    )
    entries = [{"name": artifact.name, "size": artifact.stat().st_size, "sha256": _sha256(artifact)} for artifact in artifacts]
    index = {
        "schema_version": "1.0",
        "scan_id": result.metadata.scan_id,
        "case_reference": result.metadata.case_reference,
        "analyst": result.metadata.analyst,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "digest_algorithm": "SHA-256",
        "artifacts": entries,
    }
    verify = (
        "macOS Inspector evidence bundle\n"
        f"Scan ID: {result.metadata.scan_id}\n\n"
        "Verify the extracted manifest and report digests with:\n"
        f"python3 -m macos_inspector --verify-manifest macos-inspector-{result.metadata.scan_id}.manifest\n\n"
        "The bundle-index.json file records the SHA-256 digest of every file included in this ZIP.\n"
    )
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
        temporary.chmod(0o600)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for artifact in artifacts:
                info = zipfile.ZipInfo.from_file(artifact, artifact.name)
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, artifact.read_bytes(), compresslevel=9)
            for name, content in (
                ("bundle-index.json", json.dumps(index, indent=2, ensure_ascii=False) + "\n"),
                ("VERIFY.txt", verify),
            ):
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, content.encode("utf-8"), compresslevel=9)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
