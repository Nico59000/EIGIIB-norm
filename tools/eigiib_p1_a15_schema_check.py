#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def reject_unknown(value, schema, path="$" ):
    if schema.get("type") == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path}: expected object")
        required = set(schema.get("required", []))
        missing = required - set(value)
        if missing:
            raise ValueError(f"{path}: missing {sorted(missing)}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise ValueError(f"{path}: unexpected {sorted(extra)}")
        for key, child in value.items():
            if key in properties:
                reject_unknown(child, properties[key], f"{path}.{key}")
    elif schema.get("type") == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path}: expected array")
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ValueError(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ValueError(f"{path}: too many items")
        for index, child in enumerate(value):
            reject_unknown(child, schema.get("items", {}), f"{path}[{index}]")
    elif schema.get("type") == "string" and not isinstance(value, str):
        raise ValueError(f"{path}: expected string")
    elif schema.get("type") == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
        raise ValueError(f"{path}: expected integer")
    elif schema.get("type") == "boolean" and not isinstance(value, bool):
        raise ValueError(f"{path}: expected boolean")
    elif isinstance(schema.get("type"), list):
        allowed = schema["type"]
        ok = ("null" in allowed and value is None) or ("boolean" in allowed and isinstance(value, bool)) or ("string" in allowed and isinstance(value, str))
        if not ok:
            raise ValueError(f"{path}: invalid union type")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: enum mismatch")


def main() -> int:
    pairs = [
        (ROOT / "tests/fixtures/p1-a15/capsule.json", ROOT / "schemas/eigiib-p1-a15-capsule.schema.json"),
        (ROOT / "tests/fixtures/p1-a15/live-release-evidence.json", ROOT / "schemas/eigiib-p1-a15-evidence.schema.json"),
        (ROOT / "tests/fixtures/p1-a15/expected-replay.json", ROOT / "schemas/eigiib-p1-a15-route-result.schema.json"),
    ]
    try:
        for document_path, schema_path in pairs:
            document = json.loads(document_path.read_text(encoding="utf-8"))
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            reject_unknown(document, schema)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"P1-A15 schema validation failed: {exc}", file=sys.stderr)
        return 1
    print("P1-A15 closed schemas: conformant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
