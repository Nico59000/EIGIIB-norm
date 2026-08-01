#!/usr/bin/env python3
"""Portable P1-A7.4 manifest, DSSE and Ed25519 signature adapter."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A7.4-1.0"
CARRIER_STANDARD = "EIGIIB-P1-A7.4-CARRIER-1.0"
PROFILE = "manifest-dsse-signature-carrier-v1"
ROUTE = "reference-python-openssl"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MEMBER_ORDER = ["payload", "signature", "public-key-spki"]


@dataclass(frozen=True)
class Result:
    standard: str
    route: str
    vector_id: str
    accepted: bool
    error_class: str | None
    boundary: str


class Reject(Exception):
    def __init__(self, error_class: str, boundary: str) -> None:
        super().__init__(error_class)
        self.error_class = error_class
        self.boundary = boundary


def strict_json_loads(raw: bytes, label: str = "P1A7.4") -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise Reject("signature.malformed", "signature-carrier") from exc

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out

    try:
        return json.loads(
            text,
            object_pairs_hook=hook,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise Reject("signature.malformed", "signature-carrier") from exc


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def identity(raw: bytes) -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "digest": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def canonical_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def decode_canonical_b64(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise Reject("signature.malformed", "signature-carrier")
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise Reject("signature.malformed", "signature-carrier") from exc
    if canonical_b64(decoded) != value:
        raise Reject("signature.malformed", "signature-carrier")
    return decoded


def parse_public_key_pem(value: Any) -> tuple[bytes, bytes]:
    if not isinstance(value, str):
        raise Reject("signature.malformed", "signature-carrier")
    raw = value.encode("utf-8")
    lines = value.splitlines()
    if len(lines) != 3:
        raise Reject("signature.malformed", "signature-carrier")
    if lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[2] != "-----END PUBLIC KEY-----":
        raise Reject("signature.malformed", "signature-carrier")
    try:
        der = base64.b64decode(lines[1].encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise Reject("signature.malformed", "signature-carrier") from exc
    if len(der) != 44 or not der.startswith(SPKI_PREFIX):
        raise Reject("signature.malformed", "signature-carrier")
    return raw, der


def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt)).encode("ascii")
        + b" "
        + pt
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _valid_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"algorithm", "digest", "bytes"}
        and value.get("algorithm") == "sha256"
        and isinstance(value.get("digest"), str)
        and len(value["digest"]) == 64
        and all(char in "0123456789abcdef" for char in value["digest"])
        and isinstance(value.get("bytes"), int)
        and not isinstance(value.get("bytes"), bool)
        and value["bytes"] >= 0
    )


def _manifest_members(document: dict[str, Any]) -> list[dict[str, Any]]:
    manifest = document.get("manifest")
    if not isinstance(manifest, dict) or set(manifest) != {"members"}:
        raise Reject("manifest.invalid", "manifest")
    members = manifest.get("members")
    if not isinstance(members, list) or len(members) != len(MEMBER_ORDER):
        raise Reject("manifest.invalid", "manifest")
    normalized: list[dict[str, Any]] = []
    for index, expected_name in enumerate(MEMBER_ORDER):
        row = members[index]
        if not isinstance(row, dict) or set(row) != {"name", "identity"}:
            raise Reject("manifest.invalid", "manifest")
        if row.get("name") != expected_name or not _valid_identity(row.get("identity")):
            raise Reject("manifest.invalid", "manifest")
        normalized.append(row)
    return normalized


def _carrier_parts(document: Any) -> tuple[str, bytes, bytes, bytes, str, list[dict[str, Any]]]:
    if not isinstance(document, dict):
        raise Reject("manifest.invalid", "manifest")
    if set(document) != {
        "standard",
        "profile",
        "manifest",
        "dsseEnvelope",
        "publicKeyPem",
    }:
        raise Reject("manifest.invalid", "manifest")
    if document.get("standard") != CARRIER_STANDARD or document.get("profile") != PROFILE:
        raise Reject("manifest.invalid", "manifest")

    members = _manifest_members(document)
    envelope = document.get("dsseEnvelope")
    if not isinstance(envelope, dict) or set(envelope) != {
        "payload",
        "payloadType",
        "signatures",
    }:
        raise Reject("signature.malformed", "signature-carrier")
    payload = decode_canonical_b64(envelope.get("payload"))
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise Reject("signature.malformed", "signature-carrier")
    signature_row = signatures[0]
    if not isinstance(signature_row, dict) or set(signature_row) != {"keyid", "sig"}:
        raise Reject("signature.malformed", "signature-carrier")
    keyid = signature_row.get("keyid")
    if not isinstance(keyid, str) or not keyid:
        raise Reject("signature.malformed", "signature-carrier")
    signature = decode_canonical_b64(signature_row.get("sig"))
    _, der = parse_public_key_pem(document.get("publicKeyPem"))

    observed = [identity(payload), identity(signature), identity(der)]
    if any(members[index]["identity"] != observed[index] for index in range(3)):
        raise Reject("manifest.invalid", "manifest")

    payload_type = envelope.get("payloadType")
    if payload_type != PAYLOAD_TYPE:
        raise Reject("signature.malformed", "dsse")

    expected_keyid = "p1-a2-ed25519-spki-sha256:" + identity(der)["digest"]
    if keyid != expected_keyid or len(signature) != 64:
        raise Reject("signature.malformed", "signature-carrier")

    return document["publicKeyPem"], payload, signature, der, payload_type, members


def verify_ed25519(
    public_key_pem: str,
    message: bytes,
    signature: bytes,
    openssl: str = "openssl",
) -> bool:
    with tempfile.TemporaryDirectory(prefix="eigiib-p1-a7-4-") as temporary:
        temp = Path(temporary)
        key_path = temp / "public-key.pem"
        message_path = temp / "message.bin"
        signature_path = temp / "signature.bin"
        key_path.write_text(public_key_pem, encoding="utf-8", newline="\n")
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        completed = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return completed.returncode == 0


def evaluate(
    raw: bytes,
    vector_id: str,
    openssl: str = "openssl",
    route: str = ROUTE,
) -> Result:
    try:
        document = strict_json_loads(raw)
        public_key_pem, payload, signature, _, payload_type, _ = _carrier_parts(document)
        if not verify_ed25519(
            public_key_pem,
            pae(payload_type, payload),
            signature,
            openssl,
        ):
            raise Reject("signature.invalid", "signature")
    except Reject as exc:
        return Result(STANDARD, route, vector_id, False, exc.error_class, exc.boundary)
    except OSError as exc:
        raise RuntimeError(f"OpenSSL route unavailable: {exc}") from exc
    return Result(STANDARD, route, vector_id, True, None, "signature")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--vector-id", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        result = evaluate(args.input.read_bytes(), args.vector_id, args.openssl)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
