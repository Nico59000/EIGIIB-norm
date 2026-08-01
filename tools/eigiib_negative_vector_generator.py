#!/usr/bin/env python3
"""Generate and verify the closed P1-A7.1 structural negative-vector corpus."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A7.1-1.0"
PROFILE = "portable-negative-vector-v1"
TOOL_VERSION = "0.1.0"
CANONICAL_JSON = "utf8-sort-keys-indent-2-lf-v1"
POINTER_SYNTAX = "RFC6901"
ROUTES = [
    "reference-python-openssl",
    "independent-go-stdlib",
    "external-go-cose",
]
PLATFORMS = ["ubuntu-24.04", "macos-15", "windows-2025"]
OPERATORS = {
    "raw.insert-hex",
    "raw.append-utf8",
    "json.duplicate-root-member",
    "json.set",
    "json.delete",
    "json.append-string",
}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def strict_json_loads(raw: bytes, label: str) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member: {key}")
            out[key] = value
        return out

    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=hook,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except Exception as exc:
        raise ValueError(f"{label}: {exc}") from exc


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def identity(raw: bytes) -> dict[str, Any]:
    return {
        "algorithm": "sha256",
        "digest": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def confined_regular_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("path must be a non-empty repository-relative string")
    normalized = Path(os.path.normpath(relative))
    if normalized == Path("..") or (normalized.parts and normalized.parts[0] == ".."):
        raise ValueError("path escapes repository root")
    current = root
    for part in normalized.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("path contains a symlink")
    resolved = (root / normalized).resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("path escapes repository root") from exc
    if not resolved.is_file():
        raise ValueError("path is not a regular file")
    return resolved


def pointer_parts(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with '/'")
    return [
        token.replace("~1", "/").replace("~0", "~")
        for token in pointer[1:].split("/")
    ]


def pointer_parent(document: Any, pointer: str) -> tuple[Any, str]:
    parts = pointer_parts(pointer)
    if not parts:
        raise ValueError("mutation pointer may not select the document root")
    current = document
    for token in parts[:-1]:
        if isinstance(current, list):
            try:
                current = current[int(token)]
            except (ValueError, IndexError) as exc:
                raise ValueError(f"invalid array pointer token: {token}") from exc
        elif isinstance(current, dict):
            if token not in current:
                raise ValueError(f"missing pointer member: {token}")
            current = current[token]
        else:
            raise ValueError("pointer traverses a scalar")
    return current, parts[-1]


def _set_value(parent: Any, token: str, value: Any) -> None:
    if isinstance(parent, list):
        try:
            index = int(token)
            parent[index] = value
        except (ValueError, IndexError) as exc:
            raise ValueError(f"invalid array index: {token}") from exc
    elif isinstance(parent, dict):
        if token not in parent:
            raise ValueError(f"json.set may not create undeclared member: {token}")
        parent[token] = value
    else:
        raise ValueError("json.set parent is scalar")


def _delete_value(parent: Any, token: str) -> None:
    if isinstance(parent, list):
        try:
            del parent[int(token)]
        except (ValueError, IndexError) as exc:
            raise ValueError(f"invalid array index: {token}") from exc
    elif isinstance(parent, dict):
        if token not in parent:
            raise ValueError(f"missing member for deletion: {token}")
        del parent[token]
    else:
        raise ValueError("json.delete parent is scalar")


def _append_string(parent: Any, token: str, suffix: str) -> None:
    if not isinstance(suffix, str):
        raise ValueError("json.append-string suffix must be string")
    if isinstance(parent, list):
        try:
            index = int(token)
            value = parent[index]
        except (ValueError, IndexError) as exc:
            raise ValueError(f"invalid array index: {token}") from exc
        if not isinstance(value, str):
            raise ValueError("json.append-string target must be string")
        parent[index] = value + suffix
    elif isinstance(parent, dict):
        if token not in parent or not isinstance(parent[token], str):
            raise ValueError("json.append-string target must be existing string")
        parent[token] = parent[token] + suffix
    else:
        raise ValueError("json.append-string parent is scalar")


def apply_mutation(source: bytes, mutation: Any) -> bytes:
    if not isinstance(mutation, dict):
        raise ValueError("mutation must be object")
    operator = mutation.get("operator")
    if operator not in OPERATORS:
        raise ValueError(f"unsupported mutation operator: {operator!r}")

    if operator == "raw.insert-hex":
        offset = mutation.get("offset")
        encoded = mutation.get("hex")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("raw.insert-hex offset must be non-negative integer")
        if offset > len(source):
            raise ValueError("raw.insert-hex offset exceeds source length")
        if not isinstance(encoded, str) or not encoded or len(encoded) % 2:
            raise ValueError("raw.insert-hex hex must contain complete bytes")
        try:
            insertion = bytes.fromhex(encoded)
        except ValueError as exc:
            raise ValueError("raw.insert-hex contains non-hex data") from exc
        return source[:offset] + insertion + source[offset:]

    if operator == "raw.append-utf8":
        value = mutation.get("value")
        if not isinstance(value, str):
            raise ValueError("raw.append-utf8 value must be string")
        return source + value.encode("utf-8")

    document = strict_json_loads(source, "P1A7.SOURCE")

    if operator == "json.duplicate-root-member":
        member = mutation.get("member")
        if not isinstance(member, str) or member not in document:
            raise ValueError("duplicate member must name an existing root member")
        encoded = canonical_json(document)
        if not encoded.endswith(b"}\n"):
            raise AssertionError("canonical object terminator changed")
        duplicate_value = json.dumps(
            document[member],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ": "),
        ).encode("utf-8")
        duplicate_member = json.dumps(member, ensure_ascii=False).encode("utf-8")
        return (
            encoded[:-2]
            + b',\n  '
            + duplicate_member
            + b": "
            + duplicate_value
            + b"\n}\n"
        )

    pointer = mutation.get("pointer")
    if not isinstance(pointer, str):
        raise ValueError(f"{operator} requires JSON pointer")
    parent, token = pointer_parent(document, pointer)

    if operator == "json.set":
        if "value" not in mutation:
            raise ValueError("json.set requires value")
        _set_value(parent, token, copy.deepcopy(mutation["value"]))
    elif operator == "json.delete":
        _delete_value(parent, token)
    elif operator == "json.append-string":
        _append_string(parent, token, mutation.get("suffix"))
    else:
        raise AssertionError(operator)

    return canonical_json(document)


def validate_taxonomy(taxonomy: Any) -> dict[str, int]:
    if not isinstance(taxonomy, dict):
        raise ValueError("taxonomy root must be object")
    expected = {
        "standard",
        "profile",
        "precedence_rule",
        "classes",
        "claimBoundary",
    }
    if set(taxonomy) != expected:
        raise ValueError("taxonomy fields differ from contract")
    if taxonomy.get("standard") != "EIGIIB-P1-A7.1-TAXONOMY-1.0":
        raise ValueError("taxonomy standard mismatch")
    if taxonomy.get("profile") != "portable-error-taxonomy-v1":
        raise ValueError("taxonomy profile mismatch")
    if taxonomy.get("precedence_rule") != "lowest-rank-first-authoritative-boundary":
        raise ValueError("taxonomy precedence rule mismatch")
    classes = taxonomy.get("classes")
    if not isinstance(classes, list) or not classes:
        raise ValueError("taxonomy classes must be non-empty array")
    result: dict[str, int] = {}
    ranks: set[int] = set()
    for row in classes:
        if not isinstance(row, dict) or set(row) != {
            "id",
            "layer",
            "precedence",
            "description",
        }:
            raise ValueError("taxonomy class fields differ from contract")
        class_id = row.get("id")
        rank = row.get("precedence")
        if not isinstance(class_id, str) or class_id in result:
            raise ValueError("taxonomy class IDs must be unique strings")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1 or rank in ranks:
            raise ValueError("taxonomy precedence values must be unique positive integers")
        if not isinstance(row.get("description"), str) or not row["description"]:
            raise ValueError("taxonomy description must be non-empty")
        result[class_id] = rank
        ranks.add(rank)
    if ranks != set(range(1, len(classes) + 1)):
        raise ValueError("taxonomy precedence must be contiguous from one")
    boundary = taxonomy.get("claimBoundary")
    if not isinstance(boundary, dict) or boundary.get("authority") != "p1_negative_corpus_taxonomy":
        raise ValueError("taxonomy claim boundary authority mismatch")
    return result


def validate_manifest(root: Path, manifest: Any) -> tuple[dict[str, int], list[dict[str, Any]]]:
    if not isinstance(manifest, dict):
        raise ValueError("corpus manifest root must be object")
    expected = {
        "standard",
        "profile",
        "generator",
        "taxonomy",
        "requiredRoutes",
        "requiredPlatforms",
        "vectors",
        "claimBoundary",
    }
    if set(manifest) != expected:
        raise ValueError("corpus manifest fields differ from contract")
    if manifest.get("standard") != STANDARD or manifest.get("profile") != PROFILE:
        raise ValueError("corpus constants differ from contract")
    if manifest.get("generator") != {
        "tool": "tools/eigiib_negative_vector_generator.py",
        "version": TOOL_VERSION,
        "canonicalJson": CANONICAL_JSON,
        "pointerSyntax": POINTER_SYNTAX,
    }:
        raise ValueError("generator declaration differs from contract")
    if manifest.get("requiredRoutes") != ROUTES:
        raise ValueError("required route order differs from contract")
    if manifest.get("requiredPlatforms") != PLATFORMS:
        raise ValueError("required platform order differs from contract")

    taxonomy_ref = manifest.get("taxonomy")
    if not isinstance(taxonomy_ref, dict) or set(taxonomy_ref) != {"path", "identity"}:
        raise ValueError("taxonomy reference fields differ from contract")
    taxonomy_path = confined_regular_file(root, taxonomy_ref.get("path"))
    taxonomy_raw = taxonomy_path.read_bytes()
    if taxonomy_ref.get("identity") != identity(taxonomy_raw):
        raise ValueError("taxonomy identity mismatch")
    taxonomy = strict_json_loads(taxonomy_raw, "P1A7.TAXONOMY")
    class_ranks = validate_taxonomy(taxonomy)

    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("vectors must be non-empty array")
    identifiers: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for vector in vectors:
        if not isinstance(vector, dict) or set(vector) != {
            "id",
            "layer",
            "source",
            "mutation",
            "expect",
            "requiredRoutes",
            "requiredPlatforms",
            "claimBoundary",
            "generatedIdentity",
        }:
            raise ValueError("vector fields differ from contract")
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or vector_id in identifiers:
            raise ValueError("vector IDs must be unique strings")
        identifiers.add(vector_id)
        source_ref = vector.get("source")
        if not isinstance(source_ref, dict) or set(source_ref) != {"path", "identity"}:
            raise ValueError(f"{vector_id}: source fields differ from contract")
        source_path = confined_regular_file(root, source_ref.get("path"))
        source_raw = source_path.read_bytes()
        if source_ref.get("identity") != identity(source_raw):
            raise ValueError(f"{vector_id}: source identity mismatch")
        expect = vector.get("expect")
        if not isinstance(expect, dict) or set(expect) != {
            "accepted",
            "errorClass",
            "precedence",
        }:
            raise ValueError(f"{vector_id}: expectation fields differ from contract")
        if expect.get("accepted") is not False:
            raise ValueError(f"{vector_id}: P1-A7 negative vector must reject")
        error_class = expect.get("errorClass")
        precedence = expect.get("precedence")
        if error_class not in class_ranks:
            raise ValueError(f"{vector_id}: unknown portable error class")
        if not isinstance(precedence, list) or not precedence or len(precedence) != len(set(precedence)):
            raise ValueError(f"{vector_id}: precedence must be non-empty unique array")
        if any(item not in class_ranks for item in precedence):
            raise ValueError(f"{vector_id}: precedence references unknown class")
        if precedence != sorted(precedence, key=class_ranks.__getitem__):
            raise ValueError(f"{vector_id}: precedence order differs from taxonomy")
        if precedence[0] != error_class:
            raise ValueError(f"{vector_id}: expected class must be first precedence class")
        if vector.get("requiredRoutes") != ROUTES:
            raise ValueError(f"{vector_id}: required routes differ from corpus")
        if vector.get("requiredPlatforms") != PLATFORMS:
            raise ValueError(f"{vector_id}: required platforms differ from corpus")
        mutation = vector.get("mutation")
        generated = apply_mutation(source_raw, mutation)
        if vector.get("generatedIdentity") != identity(generated):
            raise ValueError(f"{vector_id}: generated identity mismatch")
        normalized.append(
            {
                "id": vector_id,
                "error_class": error_class,
                "identity": identity(generated),
                "bytes": generated,
            }
        )
    boundary = manifest.get("claimBoundary")
    if not isinstance(boundary, dict) or boundary.get("authority") != "p1_negative_corpus_contract":
        raise ValueError("corpus claim boundary authority mismatch")
    return class_ranks, normalized


def check_repository(root: Path, output_dir: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []
    manifest_result = "not-evaluated"
    taxonomy_result = "not-evaluated"
    generator_result = "not-evaluated"
    vector_count = 0
    manifest_path = root / "tests/fixtures/p1-a7/corpus.json"
    try:
        manifest = strict_json_loads(manifest_path.read_bytes(), "P1A7.MANIFEST")
        class_ranks, vectors = validate_manifest(root, manifest)
        manifest_result = "valid"
        taxonomy_result = "valid"
        generator_result = "deterministic"
        vector_count = len(vectors)
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            for row in vectors:
                (output_dir / f"{row['id']}.bin").write_bytes(row["bytes"])
            index = [
                {
                    "id": row["id"],
                    "error_class": row["error_class"],
                    "identity": row["identity"],
                }
                for row in vectors
            ]
            (output_dir / "index.json").write_bytes(canonical_json(index))
    except (OSError, ValueError) as exc:
        findings.append(
            Finding(
                "error",
                "P1A7.GENERATOR.CONTRACT",
                str(manifest_path),
                str(exc),
            )
        )
    return {
        "tool": "eigiib-negative-vector-generator",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if findings else "conformant",
        "manifest_result": manifest_result,
        "taxonomy_result": taxonomy_result,
        "generator_result": generator_result,
        "vector_count": vector_count,
        "route_replay_result": "not-evaluated-by-p1-a7.1",
        "error_class_equivalence_result": "not-evaluated-by-p1-a7.1",
        "findings": [asdict(item) for item in sorted(findings)],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = check_repository(args.root, args.output_dir)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["structural_result"])
        for finding in result["findings"]:
            print(
                f"{finding['severity']}: {finding['code']}: "
                f"{finding['path']}: {finding['message']}"
            )
    return 0 if result["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
