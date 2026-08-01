"""COSE Sign1 helpers for P1-A11."""
from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from eigiib_p1_a11_common import CborTag, decode_cbor, encode_cbor


def public_der(public_key: Path, openssl: str = "openssl") -> bytes:
    return subprocess.run(
        [openssl, "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout


def sign_ed25519(data: bytes, private_key: Path, openssl: str = "openssl") -> bytes:
    with tempfile.TemporaryDirectory(prefix="eigiib-a10-sign-") as temp:
        source = Path(temp) / "source.bin"
        signature = Path(temp) / "signature.bin"
        source.write_bytes(data)
        subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(source),
                "-out",
                str(signature),
            ],
            check=True,
            capture_output=True,
        )
        raw = signature.read_bytes()
    if len(raw) != 64:
        raise ValueError("Ed25519 signature length")
    return raw


def verify_ed25519(
    data: bytes, signature: bytes, public_key: Path, openssl: str = "openssl"
) -> None:
    if len(signature) != 64:
        raise ValueError("Ed25519 signature length")
    with tempfile.TemporaryDirectory(prefix="eigiib-a10-verify-") as temp:
        source = Path(temp) / "source.bin"
        sig = Path(temp) / "signature.bin"
        source.write_bytes(data)
        sig.write_bytes(signature)
        result = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-rawin",
                "-inkey",
                str(public_key),
                "-in",
                str(source),
                "-sigfile",
                str(sig),
            ],
            capture_output=True,
        )
    if result.returncode != 0:
        raise ValueError("Ed25519 verification")


def cose_sign1(
    payload: bytes,
    content_type: str,
    private_key: Path,
    public_key: Path,
    openssl: str = "openssl",
) -> bytes:
    der = public_der(public_key, openssl)
    protected = encode_cbor({1: -8, 3: content_type, 4: hashlib.sha256(der).digest()})
    to_sign = encode_cbor(["Signature1", protected, b"", payload])
    signature = sign_ed25519(to_sign, private_key, openssl)
    return encode_cbor(CborTag(18, [protected, {}, payload, signature]))


def verify_cose_sign1(
    raw: bytes,
    expected_payload: bytes,
    content_type: str,
    public_key: Path,
    openssl: str = "openssl",
) -> None:
    value = decode_cbor(raw)
    if not isinstance(value, CborTag) or value.number != 18:
        raise ValueError("COSE tag")
    if not isinstance(value.value, list) or len(value.value) != 4:
        raise ValueError("COSE structure")
    protected, unprotected, payload, signature = value.value
    if not isinstance(protected, bytes) or unprotected != {}:
        raise ValueError("COSE headers")
    if not isinstance(payload, bytes) or payload != expected_payload:
        raise ValueError("COSE payload")
    if not isinstance(signature, bytes):
        raise ValueError("COSE signature")
    der = public_der(public_key, openssl)
    expected_headers: dict[int, Any] = {
        1: -8,
        3: content_type,
        4: hashlib.sha256(der).digest(),
    }
    if decode_cbor(protected) != expected_headers:
        raise ValueError("COSE protected profile")
    to_verify = encode_cbor(["Signature1", protected, b"", payload])
    verify_ed25519(to_verify, signature, public_key, openssl)
