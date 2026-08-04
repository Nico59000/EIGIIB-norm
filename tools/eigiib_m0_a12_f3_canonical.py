#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

def digest_document(document: dict[str, Any], digest_field: str) -> str:
    payload = deepcopy(document)
    payload.pop(digest_field, None)
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()

def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value

def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)
