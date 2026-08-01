"""Closed COSE_Sign1 profile and OpenSSL verification for P1-A7.5."""
from __future__ import annotations

import hashlib
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from eigiib_p1_a7_cose_codec import (
    CborMap, CborTag, CborError, Reject, canonical_decode, decode_cbor,
    encode_cbor, parse_public_key_pem,
)

STANDARD = "EIGIIB-P1-A7.5-1.0"
ROUTE = "reference-python-openssl"
COSE_SIGN1_TAG = 18
ALGORITHM_EDDSA = -8
ISSUER = "https://eigiib.example/p1-a3/issuer"
CONTENT_TYPE = "application/cbor"
TYPE = "application/scitt-statement+cose"

@dataclass(frozen=True)
class Result:
    standard: str
    route: str
    vector_id: str
    accepted: bool
    error_class: str | None
    boundary: str

def _sign1_parts(value: Any) -> tuple[bytes, CborMap, bytes, bytes]:
    if not isinstance(value, CborTag) or value.number != COSE_SIGN1_TAG:
        raise Reject('cose.invalid-structure', 'cose-structure')
    if not isinstance(value.value, list) or len(value.value) != 4:
        raise Reject('cose.invalid-structure', 'cose-structure')
    protected_raw, unprotected, payload, signature = value.value
    if not isinstance(protected_raw, bytes):
        raise Reject('cose.invalid-structure', 'cose-structure')
    if not isinstance(unprotected, CborMap) or unprotected.pairs:
        raise Reject('cose.invalid-structure', 'cose-structure')
    if not isinstance(payload, bytes):
        raise Reject('cose.invalid-structure', 'cose-structure')
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise Reject('cose.invalid-structure', 'cose-structure')
    try:
        protected = decode_cbor(protected_raw)
    except CborError as exc:
        raise Reject('cose.invalid-structure', 'cose-protected-header') from exc
    if encode_cbor(protected) != protected_raw:
        raise Reject('cbor.nondeterministic', 'cbor-protected-header')
    if not isinstance(protected, CborMap):
        raise Reject('cose.invalid-structure', 'cose-protected-header')
    try:
        payload_value = decode_cbor(payload)
    except CborError as exc:
        raise Reject('cose.invalid-structure', 'cose-payload') from exc
    if encode_cbor(payload_value) != payload:
        raise Reject('cbor.nondeterministic', 'cbor-payload')
    return (protected_raw, protected, payload, signature)

def _integer_list(value: Any) -> list[int] | None:
    if not isinstance(value, list):
        return None
    if any((not isinstance(item, int) or isinstance(item, bool) for item in value)):
        return None
    return list(value)

def _require_headers(protected: CborMap, key_der: bytes) -> None:
    critical = protected.get(2)
    if protected.has(2):
        labels = _integer_list(critical)
        if labels is None or not labels:
            raise Reject('cose.invalid-structure', 'cose-protected-header')
        supported = {1, 3, 4, 15, 16}
        if any((label not in supported for label in labels)):
            raise Reject('cose.unsupported-header', 'cose-protected-header')
    expected_keyid = hashlib.sha256(key_der).digest()
    expected = {1: ALGORITHM_EDDSA, 3: CONTENT_TYPE, 4: expected_keyid, 16: TYPE}
    for label, wanted in expected.items():
        if not protected.has(label) or protected.get(label) != wanted:
            raise Reject('cose.unsupported-header', 'cose-protected-header')
    claims = protected.get(15)
    if not isinstance(claims, CborMap):
        raise Reject('cose.unsupported-header', 'cose-protected-header')
    if claims.get(1) != ISSUER or not isinstance(claims.get(2), str):
        raise Reject('cose.unsupported-header', 'cose-protected-header')
    allowed = {1, 2, 3, 4, 15, 16}
    if any((label not in allowed for label, _ in protected.pairs)):
        raise Reject('cose.unsupported-header', 'cose-protected-header')
    if len({key for key, _ in protected.pairs}) != len(protected.pairs):
        raise Reject('cose.invalid-structure', 'cose-protected-header')

def sig_structure(protected_raw: bytes, payload: bytes) -> bytes:
    return encode_cbor(['Signature1', protected_raw, b'', payload])

def verify_ed25519(public_key_pem: str, message: bytes, signature: bytes, openssl: str) -> bool:
    with tempfile.TemporaryDirectory(prefix='eigiib-p1-a7-5-') as temporary:
        temp = Path(temporary)
        key = temp / 'issuer-public-key.pem'
        msg = temp / 'sig-structure.cbor'
        sig = temp / 'signature.bin'
        key.write_text(public_key_pem, encoding='utf-8', newline='\n')
        msg.write_bytes(message)
        sig.write_bytes(signature)
        completed = subprocess.run([openssl, 'pkeyutl', '-verify', '-pubin', '-inkey', str(key), '-rawin', '-in', str(msg), '-sigfile', str(sig)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return completed.returncode == 0

def evaluate(raw: bytes, public_key_pem: str, vector_id: str, openssl: str='openssl', route: str=ROUTE) -> Result:
    try:
        _, key_der = parse_public_key_pem(public_key_pem)
        value = canonical_decode(raw, 'cbor-sign1')
        protected_raw, protected, payload, signature = _sign1_parts(value)
        _require_headers(protected, key_der)
        if not verify_ed25519(public_key_pem, sig_structure(protected_raw, payload), signature, openssl):
            raise Reject('signature.invalid', 'cose-signature')
    except Reject as exc:
        return Result(STANDARD, route, vector_id, False, exc.error_class, exc.boundary)
    except OSError as exc:
        raise RuntimeError(f'OpenSSL route unavailable: {exc}') from exc
    except ValueError as exc:
        return Result(STANDARD, route, vector_id, False, 'cose.invalid-structure', 'cose-structure')
    return Result(STANDARD, route, vector_id, True, None, 'cose-signature')
