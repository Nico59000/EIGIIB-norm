#!/usr/bin/env python3
"""Reference Python adapter for the first P1-A7 route-bound boundaries."""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A7.2-1.0"
ROUTE = "reference-python-openssl"
TOOL_VERSION = "0.1.0"
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


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
            raise AdapterReject("internal.unmapped", "shape")
        current = current[key]
    return current


def _check_base64(value: Any) -> None:
    if not isinstance(value, str):
        raise AdapterReject("encoding.noncanonical-base64", "base64")
    try:
        ascii_value = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(ascii_value, validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise AdapterReject("encoding.noncanonical-base64", "base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise AdapterReject("encoding.noncanonical-base64", "base64")


def _check_path(value: Any) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise AdapterReject("path.unsafe", "path")
    if value.startswith(("/", "\\")) or _DRIVE_PREFIX.match(value):
        raise AdapterReject("path.unsafe", "path")
    if "\\" in value:
        raise AdapterReject("path.unsafe", "path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise AdapterReject("path.unsafe", "path")


def evaluate(raw: bytes, vector_id: str) -> Result:
    try:
        document = _strict_json(raw)
        _check_base64(_nested(document, "payload", "base64"))
        _check_path(_nested(document, "payload", "path"))
    except AdapterReject as exc:
        return Result(STANDARD, ROUTE, vector_id, False, exc.error_class, exc.boundary)
    return Result(STANDARD, ROUTE, vector_id, True, None, "path")


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
