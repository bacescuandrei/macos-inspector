from __future__ import annotations

import hashlib
import hmac
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from macos_inspector.core.models import ScanResult
from macos_inspector.core.io import read_bytes_limited, read_json_limited
from .common import secure_write_text


MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_KEY_BYTES = 1024 * 1024


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _asymmetric_signature(payload: bytes, private_key_path: Path, password: str | None) -> dict:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    except ImportError as exc:
        raise RuntimeError("Asymmetric manifest signing requires: pip install 'macos-inspector[signing]'") from exc
    private_key = serialization.load_pem_private_key(
        read_bytes_limited(private_key_path, MAX_KEY_BYTES), password=password.encode() if password else None,
    )
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        algorithm, signature = "Ed25519", private_key.sign(payload)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = "RSA-PSS-SHA256"
        signature = private_key.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm, signature = "ECDSA-SHA256", private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Unsupported signing key type; use Ed25519, RSA, or EC PEM keys.")
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    public_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return {
        "algorithm": algorithm,
        "value": base64.b64encode(signature).decode("ascii"),
        "public_key": public_pem,
        "public_key_sha256": hashlib.sha256(public_der).hexdigest(),
    }


def write_manifest(result: ScanResult, path: Path, artifacts: Iterable[Path] = ()) -> None:
    artifact_entries = []
    for artifact in sorted((Path(item) for item in artifacts), key=lambda item: item.name):
        if not artifact.is_file() or artifact.resolve() == path.resolve():
            continue
        artifact_entries.append({
            "name": artifact.name,
            "size": artifact.stat().st_size,
            "sha256": _sha256_file(artifact),
        })
    evidence_payload = {
        "metadata": result.to_dict()["metadata"],
        "findings": [finding.to_dict() for finding in result.findings],
        "timeline": [event.__dict__ for event in result.timeline],
    }
    manifest = {
        "schema_version": "1.0",
        "scan_id": result.metadata.scan_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "digest_algorithm": "SHA-256",
        "evidence_sha256": hashlib.sha256(_canonical(evidence_payload)).hexdigest(),
        "artifacts": artifact_entries,
        "signature": None,
    }
    signing_key = os.environ.get("MACOS_INSPECTOR_SIGNING_KEY")
    key = os.environ.get("MACOS_INSPECTOR_MANIFEST_KEY")
    if signing_key:
        manifest["schema_version"] = "1.1"
        manifest["signature"] = _asymmetric_signature(
            _canonical(manifest), Path(signing_key).expanduser(), os.environ.get("MACOS_INSPECTOR_SIGNING_KEY_PASSWORD"),
        )
    elif key:
        manifest["signature"] = {
            "algorithm": "HMAC-SHA256",
            "value": hmac.new(key.encode("utf-8"), _canonical(manifest), hashlib.sha256).hexdigest(),
        }
    secure_write_text(path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")


def verify_manifest(
    path: Path, key: str | None = None, base_directory: Path | None = None,
    public_key: Path | bytes | None = None,
) -> tuple[bool, list[str]]:
    errors = []
    try:
        manifest = read_json_limited(path, MAX_MANIFEST_BYTES)
        directory = base_directory or path.parent
        for artifact in manifest.get("artifacts", []):
            candidate = directory / Path(str(artifact["name"])).name
            if not candidate.is_file():
                errors.append(f"Missing artifact: {candidate.name}")
            elif _sha256_file(candidate) != artifact.get("sha256"):
                errors.append(f"Digest mismatch: {candidate.name}")
        signature = manifest.get("signature")
        if signature:
            unsigned = dict(manifest)
            unsigned["signature"] = None
            algorithm = signature.get("algorithm")
            if algorithm == "HMAC-SHA256":
                if not key:
                    errors.append("Manifest is HMAC-signed but no verification key was provided.")
                else:
                    expected = hmac.new(key.encode("utf-8"), _canonical(unsigned), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(expected, str(signature.get("value", ""))):
                        errors.append("Manifest signature mismatch.")
            elif algorithm in {"Ed25519", "RSA-PSS-SHA256", "ECDSA-SHA256"}:
                try:
                    from cryptography.exceptions import InvalidSignature
                    from cryptography.hazmat.primitives import hashes, serialization
                    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
                    key_bytes = read_bytes_limited(public_key, MAX_KEY_BYTES) if isinstance(public_key, Path) else public_key
                    key_bytes = key_bytes or str(signature.get("public_key", "")).encode("ascii")
                    verifier = serialization.load_pem_public_key(key_bytes)
                    public_der = verifier.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    fingerprint = hashlib.sha256(public_der).hexdigest()
                    if fingerprint != signature.get("public_key_sha256"):
                        errors.append("Public key fingerprint mismatch.")
                    signed_value = base64.b64decode(str(signature.get("value", "")), validate=True)
                    if algorithm == "Ed25519" and isinstance(verifier, ed25519.Ed25519PublicKey):
                        verifier.verify(signed_value, _canonical(unsigned))
                    elif algorithm == "RSA-PSS-SHA256" and isinstance(verifier, rsa.RSAPublicKey):
                        verifier.verify(signed_value, _canonical(unsigned), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                    elif algorithm == "ECDSA-SHA256" and isinstance(verifier, ec.EllipticCurvePublicKey):
                        verifier.verify(signed_value, _canonical(unsigned), ec.ECDSA(hashes.SHA256()))
                    else:
                        errors.append("Signature algorithm does not match the public key type.")
                except ImportError:
                    errors.append("Asymmetric verification requires the optional signing dependency.")
                except (InvalidSignature, ValueError, TypeError):
                    errors.append("Manifest signature mismatch.")
            else:
                errors.append(f"Unsupported signature algorithm: {algorithm}")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    return not errors, errors
