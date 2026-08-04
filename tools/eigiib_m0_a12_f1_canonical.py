#!/usr/bin/env python3
"""Canonical inventory and path helpers for M0-A12-F1."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_document(document: dict[str, Any], digest_field: str) -> str:
    payload = dict(document)
    payload.pop(digest_field, None)
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def safe_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("path must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("path must be normalized, relative and non-escaping")
    return path


def inventory_entry(path: str, data: bytes, role: str, media_type: str) -> dict[str, Any]:
    safe_relative_path(path)
    return {
        "path": path,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "role": role,
        "mediaType": media_type,
    }


def inventory_digest(entries: Iterable[dict[str, Any]]) -> str:
    normalized = [
        {
            "path": item["path"],
            "bytes": item["bytes"],
            "sha256": item["sha256"],
            "role": item["role"],
            "mediaType": item["mediaType"],
        }
        for item in entries
    ]
    normalized.sort(key=lambda item: item["path"])
    return hashlib.sha256(canonical_bytes(normalized)).hexdigest()
