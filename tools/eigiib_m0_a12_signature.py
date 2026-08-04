#!/usr/bin/env python3
"""Detached Ed25519 signature envelopes for M0-A12."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEFAULT_NAMESPACE = "eigiib-m0-a12@eigiib.example"
SIGNATURE_STANDARD = "EIGIIB-M0-A12-DETACHED-SIGNATURE-1.0"
ALLOWED_SIGNERS_STANDARD = "EIGIIB-M0-A12-ALLOWED-SIGNERS-1.0"


class SignatureError(RuntimeError):
    pass


def _message(payload: bytes, namespace: str) -> bytes:
    return b"EIGIIB-M0-A12-SIGNATURE-v1\0" + namespace.encode("utf-8") + b"\0" + payload


def payload_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise SignatureError("cannot load Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError("private key is not Ed25519")
    return key


def load_allowed_signers(path: Path) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignatureError("cannot parse allowed signers") from exc
    if value.get("standard") != ALLOWED_SIGNERS_STANDARD:
        raise SignatureError("invalid allowed signers standard")
    signers = value.get("signers")
    if not isinstance(signers, list):
        raise SignatureError("invalid allowed signers list")
    result: dict[str, dict[str, Any]] = {}
    for signer in signers:
        identity = signer.get("identity")
        if not isinstance(identity, str) or not identity or identity in result:
            raise SignatureError("invalid or duplicate signer identity")
        result[identity] = signer
    return result


def sign_file(
    payload: Path,
    private_key: Path,
    identity: str,
    key_id: str,
    allowed_signers_path: str = "keys/allowed_signers.json",
    namespace: str = DEFAULT_NAMESPACE,
    signed_at: str | None = None,
) -> Path:
    key = load_private_key(private_key)
    data = payload.read_bytes()
    signature = key.sign(_message(data, namespace))
    public_raw = public_key_raw(key.public_key())
    envelope = {
        "standard": SIGNATURE_STANDARD,
        "signedPayloadPath": payload.as_posix(),
        "signedPayloadDigest": payload_sha256(data),
        "signatureAlgorithm": "ed25519",
        "signatureNamespace": namespace,
        "signerIdentity": identity,
        "signerKeyId": key_id,
        "publicKeyDigest": hashlib.sha256(public_raw).hexdigest(),
        "signatureValue": base64.b64encode(signature).decode("ascii"),
        "allowedSignersPath": allowed_signers_path,
        "signedAt": signed_at or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    signature_path = Path(str(payload) + ".sig")
    signature_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8", newline="\n")
    return signature_path


def verify_file(
    payload: Path,
    signature: Path,
    allowed_signers: Path,
    identity: str,
    namespace: str = DEFAULT_NAMESPACE,
) -> None:
    try:
        envelope = json.loads(signature.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignatureError("cannot parse detached signature envelope") from exc
    if envelope.get("standard") != SIGNATURE_STANDARD:
        raise SignatureError("invalid signature standard")
    if envelope.get("signatureAlgorithm") != "ed25519":
        raise SignatureError("unsupported signature algorithm")
    if envelope.get("signatureNamespace") != namespace:
        raise SignatureError("signature namespace mismatch")
    if envelope.get("signerIdentity") != identity:
        raise SignatureError("signer identity mismatch")
    data = payload.read_bytes()
    if envelope.get("signedPayloadDigest") != payload_sha256(data):
        raise SignatureError("signed payload digest mismatch")

    signers = load_allowed_signers(allowed_signers)
    signer = signers.get(identity)
    if signer is None:
        raise SignatureError("signer is not allowed")
    if signer.get("keyId") != envelope.get("signerKeyId"):
        raise SignatureError("signer key id mismatch")
    try:
        public_raw = base64.b64decode(signer.get("publicKeyRawBase64"), validate=True)
        signature_raw = base64.b64decode(envelope.get("signatureValue"), validate=True)
    except Exception as exc:
        raise SignatureError("invalid signature encoding") from exc
    if hashlib.sha256(public_raw).hexdigest() != envelope.get("publicKeyDigest"):
        raise SignatureError("public key digest mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw, _message(data, namespace))
    except (ValueError, InvalidSignature) as exc:
        raise SignatureError("Ed25519 verification failed") from exc
