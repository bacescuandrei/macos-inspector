from __future__ import annotations

import os
import tempfile
from pathlib import Path

from macos_inspector.core.models import ScanResult
from macos_inspector.reporters.common import secure_write_bytes


MAGIC = b"MACOS-INSPECTOR-ENC-1\n"
SALT_BYTES = 16
NONCE_BYTES = 12


def encryption_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: F401
        return True
    except ImportError:
        return False


def _key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError("Encrypted case bundle password must contain 12 to 256 characters.")
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise RuntimeError("Encrypted bundles require the optional signing dependency.") from exc
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode("utf-8"))


def encrypt_file(source: Path, destination: Path, password: str) -> None:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("Encrypted bundles require the optional signing dependency.") from exc
    salt, nonce = os.urandom(SALT_BYTES), os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(_key(password, salt)).encrypt(nonce, source.read_bytes(), MAGIC)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=f".{destination.name}.", dir=destination.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(MAGIC + salt + nonce + ciphertext)
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        destination.chmod(0o600)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def decrypt_file(source: Path, destination: Path, password: str) -> None:
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError("Encrypted bundles require the optional signing dependency.") from exc
    data = source.read_bytes()
    minimum = len(MAGIC) + SALT_BYTES + NONCE_BYTES + 16
    if len(data) < minimum or not data.startswith(MAGIC):
        raise ValueError("Not a macOS Inspector encrypted bundle.")
    offset = len(MAGIC)
    salt, nonce, ciphertext = data[offset:offset + SALT_BYTES], data[offset + SALT_BYTES:offset + SALT_BYTES + NONCE_BYTES], data[offset + SALT_BYTES + NONCE_BYTES:]
    try:
        plaintext = AESGCM(_key(password, salt)).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag as exc:
        raise ValueError("Encrypted bundle password is incorrect or the file was modified.") from exc
    secure_write_bytes(destination, plaintext)


def write_encrypted_bundle(result: ScanResult, destination: Path) -> None:
    """Reporter-compatible entry point using a non-command-line environment secret."""
    from macos_inspector.reporters.bundle_reporter import write_bundle
    password = os.environ.get("MACOS_INSPECTOR_BUNDLE_PASSWORD", "")
    if not password:
        raise ValueError("Set MACOS_INSPECTOR_BUNDLE_PASSWORD for an encrypted bundle export.")
    temporary = destination.with_name(f".{destination.name}.zip")
    try:
        write_bundle(result, temporary)
        encrypt_file(temporary, destination, password)
    finally:
        temporary.unlink(missing_ok=True)
