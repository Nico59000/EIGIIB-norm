#!/usr/bin/env python3
"""Closed JSON Schema subset validator for the registered P1-A12 schemas."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


def load(path: Path) -> Any:
    with path.open('r', encoding='utf-8') as handle:
        return json.load(handle)


def resolve(root: dict[str, Any], ref: str, base: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    if ref.startswith('#/'):
        node: Any = root
        for part in ref[2:].split('/'):
            node = node[part.replace('~1', '/').replace('~0', '~')]
        return node, root, base
    target, _, fragment = ref.partition('#')
    target_path = (base.parent / target).resolve()
    target_root = load(target_path)
    node: Any = target_root
    if fragment.startswith('/'):
        for part in fragment[1:].split('/'):
            node = node[part.replace('~1', '/').replace('~0', '~')]
    return node, target_root, target_path


def fail(path: str, message: str) -> None:
    raise ValueError(f'{path}: {message}')


def validate(value: Any, schema: dict[str, Any], root: dict[str, Any], base: Path, path: str = '$') -> None:
    if '$ref' in schema:
        node, next_root, next_base = resolve(root, schema['$ref'], base)
        validate(value, node, next_root, next_base, path)
        return
    for branch in schema.get('allOf', []):
        validate(value, branch, root, base, path)
    if 'const' in schema and value != schema['const']:
        fail(path, 'const')
    if 'enum' in schema and value not in schema['enum']:
        fail(path, 'enum')
    kind = schema.get('type')
    if isinstance(kind, list):
        errors = []
        for candidate in kind:
            try:
                validate(value, {**schema, 'type': candidate}, root, base, path)
                return
            except ValueError as exc:
                errors.append(str(exc))
        fail(path, 'type union')
    if kind == 'object':
        if not isinstance(value, dict):
            fail(path, 'object')
        required = schema.get('required', [])
        for key in required:
            if key not in value:
                fail(path, f'missing {key}')
        properties = schema.get('properties', {})
        if schema.get('additionalProperties') is False:
            extra = set(value) - set(properties)
            if extra:
                fail(path, f'additional {sorted(extra)}')
        for key, child in properties.items():
            if key in value:
                validate(value[key], child, root, base, f'{path}.{key}')
        if len(value) < schema.get('minProperties', 0):
            fail(path, 'minProperties')
    elif kind == 'array':
        if not isinstance(value, list):
            fail(path, 'array')
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', 10**9):
            fail(path, 'item count')
        if schema.get('uniqueItems'):
            seen = set()
            for item in value:
                marker = json.dumps(item, sort_keys=True, separators=(',', ':'))
                if marker in seen:
                    fail(path, 'uniqueItems')
                seen.add(marker)
        item_schema = schema.get('items')
        if item_schema:
            for index, item in enumerate(value):
                validate(item, item_schema, root, base, f'{path}[{index}]')
    elif kind == 'string':
        if not isinstance(value, str):
            fail(path, 'string')
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', 10**9):
            fail(path, 'string length')
        if 'pattern' in schema and re.fullmatch(schema['pattern'], value) is None:
            fail(path, 'pattern')
    elif kind == 'integer':
        if not isinstance(value, int) or isinstance(value, bool):
            fail(path, 'integer')
        if value < schema.get('minimum', -10**100) or value > schema.get('maximum', 10**100):
            fail(path, 'integer bounds')
    elif kind == 'boolean':
        if not isinstance(value, bool):
            fail(path, 'boolean')
    elif kind == 'null':
        if value is not None:
            fail(path, 'null')
    elif kind is not None:
        fail(path, f'unsupported type {kind}')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    pairs = [
        ('tests/fixtures/p1-a12/capsule.json', 'schemas/eigiib-p1-a12-capsule.schema.json'),
        ('tests/fixtures/p1-a12/expected-replay.json', 'schemas/eigiib-p1-a12-replay-report.schema.json'),
    ]
    try:
        for data_rel, schema_rel in pairs:
            data_path = root / data_rel
            schema_path = root / schema_rel
            schema = load(schema_path)
            validate(load(data_path), schema, schema, schema_path)
        replay = load(root / 'tests/fixtures/p1-a12/expected-replay.json')
        route_path = root / 'schemas/eigiib-p1-a12-route-result.schema.json'
        route_schema = load(route_path)
        for row in replay['observations']:
            validate(row, route_schema, route_schema, route_path)
    except Exception as exc:
        print(f'P1-A12 schema validation failed: {exc}', file=sys.stderr)
        return 1
    print('P1-A12 closed schema validation: conformant')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
