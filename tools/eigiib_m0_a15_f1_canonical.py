#!/usr/bin/env python3
"""Canonical JSON, digest, time and path guards for M0-A15-F1."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


class CanonicalValueError(ValueError):
    pass


def _guard(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise CanonicalValueError(f"floating-point-value-forbidden:{path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _guard(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalValueError(f"non-string-key-forbidden:{path}")
            _guard(item, f"{path}.{key}")
        return
    raise CanonicalValueError(f"unsupported-canonical-type:{path}:{type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _guard(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def is_hex(value: Any, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value)
    )


def decode_b64(value: Any, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64-value-not-string")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # pragma: no cover - exact decoder error is provider-specific
        raise ValueError("base64-value-invalid") from exc
    if expected_length is not None and len(raw) != expected_length:
        raise ValueError("base64-value-length-invalid")
    return raw


def safe_repo_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if "\\" in value or any(char in value for char in "*?["):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)
