from __future__ import annotations

import argparse
import hashlib
import stat
import zipfile
from pathlib import Path

from macos_inspector import __version__


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = "macOS Inspector.command"


def release_files() -> list[Path]:
    files = [
        ROOT / "README.md",
        ROOT / "CHANGELOG.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CODE_OF_CONDUCT.md",
        ROOT / "LICENSE",
        ROOT / "SECURITY.md",
        ROOT / "SUPPORT.md",
        ROOT / "pyproject.toml",
        ROOT / LAUNCHER,
    ]
    files.extend(path for path in (ROOT / "docs").rglob("*") if path.is_file())
    files.extend(path for path in (ROOT / "src").rglob("*") if path.is_file())
    files.extend(path for path in (ROOT / "ioc-packs").rglob("*") if path.is_file())
    return sorted(
        (
            path for path in files
            if "__pycache__" not in path.parts
            and not any(part == ".DS_Store" or part.startswith("._") or part.endswith(".egg-info") for part in path.parts)
            and path.suffix not in {".pyc", ".pyo"}
        ),
        key=lambda path: str(path.relative_to(ROOT)).casefold(),
    )


def build_release(destination: Path | None = None) -> Path:
    destination = destination or ROOT / "dist" / f"macos-inspector-{__version__}-macos.zip"
    destination.parent.mkdir(parents=True, exist_ok=True)
    package_root = f"macOS Inspector {__version__}"
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in release_files():
            relative = path.relative_to(ROOT)
            info = zipfile.ZipInfo.from_file(path, f"{package_root}/{relative.as_posix()}")
            permissions = 0o755 if relative.as_posix() == LAUNCHER else 0o644
            info.external_attr = (stat.S_IFREG | permissions) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
    (destination.parent / "SHA256SUMS").write_text(
        f"{checksum}  {destination.name}\n", encoding="ascii",
    )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the portable macOS Inspector dashboard package")
    parser.add_argument("--output", type=Path, help="Destination ZIP path")
    args = parser.parse_args()
    print(build_release(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
