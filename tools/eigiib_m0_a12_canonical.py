#!/usr/bin/env python3
"""Canonical JSON helpers for M0-A12 evidence digests."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_document(document: dict[str, Any], digest_field: str) -> str:
    payload = deepcopy(document)
    payload.pop(digest_field, None)
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value
