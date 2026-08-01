#!/usr/bin/env python3
"""Reference Python adapter for the closed P1-A7.3 structural boundaries."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A7.3-1.0"
ROUTE = "reference-python-openssl"
TOOL_VERSION = "0.1.0"
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_RESULT_FIELDS = {
    "manifest_binding_result",
    "p1a1_replay_result",
    "p1a2_replay_result",
    "p1a3_replay_result",
    "cross_capsule_binding_result",
    "end_to_end_result",
    "chain_identity",
}
_CHAIN_IDENTITY = {
    "algorithm": "sha256",
    "bytes": 2182,
    "digest": "8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d",
}


@dataclass(frozen=True)
class Result:
    standard: str
    route: str
    vector_id: str
    accepted: bool
    error_class: str | None
    boundary: str


class AdapterReject(Exception):
    def __init__(self, error_class: str, boundary: str) -> None:
        super().__init__(error_class)
        self.error_class = error_class
        self.boundary = boundary


def _strict_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AdapterReject("syntax.invalid-utf8", "utf8") from exc

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
        raise AdapterReject("syntax.invalid-json", "json") from exc


def _nested(document: Any, *keys: str) -> Any:
    current = document
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            raise AdapterReject("projection.invalid", "projection")
        current = current[key]
    return current


def _check_base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise AdapterReject("encoding.noncanonical-base64", "base64")
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise AdapterReject("encoding.noncanonical-base64", "base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise AdapterReject("encoding.noncanonical-base64", "base64")
    return decoded


def _check_path(value: Any) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise AdapterReject("path.unsafe", "path")
    if value.startswith(("/", "\\")) or _DRIVE_PREFIX.match(value) or "\\" in value:
        raise AdapterReject("path.unsafe", "path")
    if any(segment in {"", ".", ".."} for segment in value.split("/")):
        raise AdapterReject("path.unsafe", "path")


def _check_identity(value: Any, payload: bytes) -> None:
    if not isinstance(value, dict) or set(value) != {"algorithm", "bytes", "digest"}:
        raise AdapterReject("identity.length-mismatch", "identity.length")
    if value.get("algorithm") != "sha256":
        raise AdapterReject("identity.digest-mismatch", "identity.digest")
    observed_length = len(payload)
    declared_length = value.get("bytes")
    if not isinstance(declared_length, int) or isinstance(declared_length, bool) or declared_length != observed_length:
        raise AdapterReject("identity.length-mismatch", "identity.length")
    observed_digest = hashlib.sha256(payload).hexdigest()
    declared_digest = value.get("digest")
    if not isinstance(declared_digest, str) or declared_digest != observed_digest:
        raise AdapterReject("identity.digest-mismatch", "identity.digest")


def _check_projection(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != _RESULT_FIELDS:
        raise AdapterReject("projection.invalid", "projection")
    for key in _RESULT_FIELDS - {"chain_identity"}:
        if value.get(key) != "conformant":
            raise AdapterReject("projection.invalid", "projection")
    if value.get("chain_identity") != _CHAIN_IDENTITY:
        raise AdapterReject("projection.invalid", "projection")


def evaluate(raw: bytes, vector_id: str) -> Result:
    try:
        document = _strict_json(raw)
        payload = _check_base64(_nested(document, "payload", "base64"))
        _check_path(_nested(document, "payload", "path"))
        _check_identity(_nested(document, "payload", "identity"), payload)
        _check_projection(_nested(document, "projection"))
    except AdapterReject as exc:
        return Result(STANDARD, ROUTE, vector_id, False, exc.error_class, exc.boundary)
    return Result(STANDARD, ROUTE, vector_id, True, None, "projection")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--vector-id", required=True)
    args = parser.parse_args()
    try:
        result = evaluate(args.input.read_bytes(), args.vector_id)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
