#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def validate(value, schema, path="$"):
    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(value, dict):
            raise ValueError(f"{path}: expected object")
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        missing = required - set(value)
        if missing:
            raise ValueError(f"{path}: missing {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise ValueError(f"{path}: unexpected {sorted(extra)}")
        for key, child in value.items():
            if key in properties:
                validate(child, properties[key], f"{path}.{key}")
    elif schema_type == "array":
        if not isinstance(value, list):
            raise ValueError(f"{path}: expected array")
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ValueError(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ValueError(f"{path}: too many items")
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            raise ValueError(f"{path}: duplicate items")
        for index, child in enumerate(value):
            validate(child, schema.get("items", {}), f"{path}[{index}]")
    elif schema_type == "string":
        if not isinstance(value, str):
            raise ValueError(f"{path}: expected string")
        if "pattern" in schema:
            import re
            if re.fullmatch(schema["pattern"], value) is None:
                raise ValueError(f"{path}: pattern mismatch")
    elif schema_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{path}: expected integer")
        if "minimum" in schema and value < schema["minimum"]:
            raise ValueError(f"{path}: below minimum")
    elif schema_type == "boolean":
        if not isinstance(value, bool):
            raise ValueError(f"{path}: expected boolean")
    elif schema_type == "null":
        if value is not None:
            raise ValueError(f"{path}: expected null")
    elif isinstance(schema_type, list):
        valid = False
        for candidate in schema_type:
            try:
                validate(value, {"type": candidate}, path)
                valid = True
                break
            except ValueError:
                pass
        if not valid:
            raise ValueError(f"{path}: union type mismatch")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path}: const mismatch")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: enum mismatch")


def main() -> int:
    pairs = [
        ("tests/fixtures/p1-a16/capsule.json", "schemas/eigiib-p1-a16-capsule.schema.json"),
        ("tests/fixtures/p1-a16/live-registry-evidence.json", "schemas/eigiib-p1-a16-evidence.schema.json"),
        ("tests/fixtures/p1-a16/expected-replay.json", "schemas/eigiib-p1-a16-route-result.schema.json"),
    ]
    try:
        for document_path, schema_path in pairs:
            document = json.loads((ROOT / document_path).read_text(encoding="utf-8"))
            schema = json.loads((ROOT / schema_path).read_text(encoding="utf-8"))
            validate(document, schema)
    except Exception as exc:
        print(f"P1-A16 schema validation failed: {exc}", file=sys.stderr)
        return 1
    print("P1-A16 closed schemas: conformant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
