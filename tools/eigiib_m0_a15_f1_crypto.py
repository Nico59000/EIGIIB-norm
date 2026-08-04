#!/usr/bin/env python3
"""Authenticated envelope verification for M0-A15-F1."""
from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from eigiib_m0_a15_f1_canonical import canonical_bytes, decode_b64, digest_hex


PROFILE_KEYS = {"keyId", "algorithm", "publicKey"}
SIGNATURE_KEYS = {"algorithm", "keyId", "value"}
ENVELOPE_KEYS = {"payload", "signature"}


def verify_envelope(envelope: Any, profile: Any, prefix: str) -> tuple[str | None, list[str]]:
    errors: list[str] = []
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        return None, [f"{prefix}-envelope-shape-invalid"]
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict):
        errors.append(f"{prefix}-payload-invalid")
    if not isinstance(signature, dict) or set(signature) != SIGNATURE_KEYS:
        errors.append(f"{prefix}-signature-shape-invalid")
    if not isinstance(profile, dict) or not PROFILE_KEYS.issubset(profile):
        errors.append(f"{prefix}-profile-key-material-invalid")
    if errors:
        return None, errors

    if profile.get("algorithm") != "ed25519" or signature.get("algorithm") != "ed25519":
        errors.append(f"{prefix}-algorithm-invalid")
    if signature.get("keyId") != profile.get("keyId"):
        errors.append(f"{prefix}-key-id-mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(decode_b64(profile.get("publicKey"), 32))
        signature_bytes = decode_b64(signature.get("value"), 64)
        public_key.verify(signature_bytes, canonical_bytes(payload))
    except InvalidSignature:
        errors.append(f"{prefix}-signature-invalid")
    except Exception:
        errors.append(f"{prefix}-key-or-signature-encoding-invalid")
    return (digest_hex(payload) if not errors else None), errors
