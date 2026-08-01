#!/usr/bin/env python3
"""Replay the complete P1-A7.3 structural negative corpus across three routes."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A7.3-1.0"
PROFILE = "identity-projection-precedence-closure-v1"
TOOL_VERSION = "0.1.0"
ROUTES = [
    "reference-python-openssl",
    "independent-go-stdlib",
    "external-go-cose",
]
RESULT_KEYS = {
    "standard",
    "route",
    "vector_id",
    "accepted",
    "error_class",
    "boundary",
}


def strict_json(raw: bytes, label: str) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label}: duplicate JSON member: {key}")
            result[key] = value
        return result

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=hook,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"{label}: non-finite JSON number: {value}")
        ),
    )


def load_generator(root: Path) -> Any:
    path = root / "tools/eigiib_negative_vector_generator.py"
    spec = importlib.util.spec_from_file_location("eigiib_negative_vector_generator_a73", path)
    if spec is None or spec.loader is None:
        raise ValueError("unable to load P1-A7 generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validate_identity(actual: dict[str, Any], expected: Any, label: str) -> None:
    if expected != actual:
        raise ValueError(f"{label}: identity mismatch")


def taxonomy_ranks(taxonomy: Any) -> dict[str, int]:
    if not isinstance(taxonomy, dict) or taxonomy.get("precedence_rule") != "lowest-rank-first-authoritative-boundary":
        raise ValueError("taxonomy precedence contract mismatch")
    classes = taxonomy.get("classes")
    if not isinstance(classes, list) or not classes:
        raise ValueError("taxonomy classes are missing")
    result: dict[str, int] = {}
    for row in classes:
        if not isinstance(row, dict):
            raise ValueError("taxonomy class is not an object")
        class_id = row.get("id")
        precedence = row.get("precedence")
        if not isinstance(class_id, str) or not isinstance(precedence, int) or isinstance(precedence, bool):
            raise ValueError("taxonomy class identity is invalid")
        if class_id in result or precedence in result.values():
            raise ValueError("taxonomy class or precedence is duplicated")
        result[class_id] = precedence
    if sorted(result.values()) != list(range(1, len(result) + 1)):
        raise ValueError("taxonomy precedence is not contiguous")
    return result


def load_structural_corpus(root: Path, generator: Any) -> tuple[bytes, list[dict[str, Any]]]:
    manifest_path = root / "tests/fixtures/p1-a7/a7.3-structural-corpus.json"
    manifest_raw = manifest_path.read_bytes()
    manifest = strict_json(manifest_raw, "P1A7.3.MANIFEST")
    expected_fields = {
        "standard",
        "profile",
        "generator",
        "taxonomy",
        "source",
        "requiredRoutes",
        "requiredPlatforms",
        "vectors",
        "claimBoundary",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields:
        raise ValueError("P1-A7.3 manifest fields differ from contract")
    if manifest.get("standard") != STANDARD or manifest.get("profile") != "structural-negative-replay-v1":
        raise ValueError("P1-A7.3 manifest identity differs from contract")
    if manifest.get("requiredRoutes") != ROUTES:
        raise ValueError("P1-A7.3 route order differs from contract")
    if manifest.get("requiredPlatforms") != ["ubuntu-24.04", "macos-15", "windows-2025"]:
        raise ValueError("P1-A7.3 platform order differs from contract")
    if manifest.get("generator") != {
        "tool": "tools/eigiib_negative_vector_generator.py",
        "version": "0.1.0",
        "sequenceMode": "ordered-application-v1",
    }:
        raise ValueError("P1-A7.3 generator declaration differs from contract")

    taxonomy_ref = manifest.get("taxonomy")
    source_ref = manifest.get("source")
    if not isinstance(taxonomy_ref, dict) or set(taxonomy_ref) != {"path", "identity"}:
        raise ValueError("taxonomy reference is invalid")
    if not isinstance(source_ref, dict) or set(source_ref) != {"path", "identity"}:
        raise ValueError("source reference is invalid")
    taxonomy_path = generator.confined_regular_file(root, taxonomy_ref["path"])
    source_path = generator.confined_regular_file(root, source_ref["path"])
    taxonomy_raw = taxonomy_path.read_bytes()
    source_raw = source_path.read_bytes()
    validate_identity(generator.identity(taxonomy_raw), taxonomy_ref["identity"], "taxonomy")
    validate_identity(generator.identity(source_raw), source_ref["identity"], "source")
    ranks = taxonomy_ranks(strict_json(taxonomy_raw, "P1A7.3.TAXONOMY"))

    vectors = manifest.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("P1-A7.3 vectors are missing")
    identifiers: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for vector in vectors:
        expected_vector_fields = {
            "id",
            "layer",
            "mutations",
            "expect",
            "requiredRoutes",
            "requiredPlatforms",
            "generatedIdentity",
            "claimBoundary",
        }
        if not isinstance(vector, dict) or set(vector) != expected_vector_fields:
            raise ValueError("P1-A7.3 vector fields differ from contract")
        vector_id = vector.get("id")
        if not isinstance(vector_id, str) or vector_id in identifiers:
            raise ValueError("P1-A7.3 vector IDs must be unique strings")
        identifiers.add(vector_id)
        mutations = vector.get("mutations")
        if not isinstance(mutations, list) or not mutations:
            raise ValueError(f"{vector_id}: mutation sequence is empty")
        raw = source_raw
        for mutation in mutations:
            raw = generator.apply_mutation(raw, mutation)
        validate_identity(generator.identity(raw), vector.get("generatedIdentity"), vector_id)
        expect = vector.get("expect")
        if not isinstance(expect, dict) or set(expect) != {"accepted", "errorClass", "precedence"}:
            raise ValueError(f"{vector_id}: expectation fields differ from contract")
        if expect.get("accepted") is not False:
            raise ValueError(f"{vector_id}: negative vector must reject")
        precedence = expect.get("precedence")
        error_class = expect.get("errorClass")
        if not isinstance(precedence, list) or not precedence or len(precedence) != len(set(precedence)):
            raise ValueError(f"{vector_id}: precedence must be non-empty and unique")
        if any(item not in ranks for item in precedence):
            raise ValueError(f"{vector_id}: precedence references unknown class")
        if precedence != sorted(precedence, key=ranks.__getitem__):
            raise ValueError(f"{vector_id}: precedence differs from taxonomy")
        if error_class != precedence[0]:
            raise ValueError(f"{vector_id}: expected class is not first in precedence")
        if vector.get("requiredRoutes") != ROUTES or vector.get("requiredPlatforms") != manifest["requiredPlatforms"]:
            raise ValueError(f"{vector_id}: route or platform set differs from corpus")
        normalized.append(
            {
                "id": vector_id,
                "bytes": raw,
                "error_class": error_class,
                "precedence": precedence,
                "mutation_count": len(mutations),
            }
        )
    return source_raw, normalized


def build_go_adapter(go: str, module_dir: Path, output: Path) -> None:
    completed = subprocess.run(
        [
            go,
            "build",
            "-mod=readonly",
            "-trimpath",
            "-o",
            str(output),
            "./cmd/eigiib-p1-structural-adapter",
        ],
        cwd=module_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"unable to build structural adapter in {module_dir.name}: {message}")


def run_adapter(command: list[str], input_path: Path, vector_id: str, route: str) -> dict[str, Any]:
    completed = subprocess.run(
        command + ["--input", str(input_path), "--vector-id", vector_id],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{route}: adapter unavailable: {message}")
    try:
        result = strict_json(completed.stdout, f"{route}.RESULT")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{route}: unmapped adapter output: {exc}") from exc
    if not isinstance(result, dict) or set(result) != RESULT_KEYS:
        raise ValueError(f"{route}: adapter result fields differ from contract")
    if result["standard"] != STANDARD or result["route"] != route or result["vector_id"] != vector_id:
        raise ValueError(f"{route}: adapter identity differs from invocation")
    if not isinstance(result["accepted"], bool):
        raise ValueError(f"{route}: accepted carrier is not boolean")
    if result["error_class"] is not None and not isinstance(result["error_class"], str):
        raise ValueError(f"{route}: error class carrier is invalid")
    if not isinstance(result["boundary"], str) or not result["boundary"]:
        raise ValueError(f"{route}: boundary carrier is invalid")
    return result


def check_repository(root: Path, go: str = "go", expected: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    findings: list[dict[str, str]] = []
    observations: list[dict[str, Any]] = []
    vector_ids: list[str] = []
    multi_ids: list[str] = []
    try:
        generator = load_generator(root)
        positive_raw, vectors = load_structural_corpus(root, generator)
        vector_ids = [row["id"] for row in vectors]
        multi_ids = [row["id"] for row in vectors if len(row["precedence"]) > 1]
        with tempfile.TemporaryDirectory(prefix="eigiib-p1-a7-3-") as temporary:
            temp = Path(temporary)
            independent_binary = temp / ("independent-structural.exe" if os.name == "nt" else "independent-structural")
            external_binary = temp / ("external-structural.exe" if os.name == "nt" else "external-structural")
            build_go_adapter(go, root / "independent", independent_binary)
            build_go_adapter(go, root / "external", external_binary)
            route_commands = {
                "reference-python-openssl": [
                    sys.executable,
                    str(root / "tools/eigiib_p1_a7_structural_adapter.py"),
                ],
                "independent-go-stdlib": [str(independent_binary)],
                "external-go-cose": [str(external_binary)],
            }
            inputs: list[tuple[str, bytes, bool, str | None, list[str]]] = [
                ("a7.3-positive-seed", positive_raw, True, None, []),
            ] + [
                (
                    row["id"],
                    row["bytes"],
                    False,
                    row["error_class"],
                    row["precedence"],
                )
                for row in vectors
            ]
            for vector_id, raw, expected_acceptance, expected_class, precedence in inputs:
                input_path = temp / f"{vector_id}.bin"
                input_path.write_bytes(raw)
                for route in ROUTES:
                    result = run_adapter(route_commands[route], input_path, vector_id, route)
                    observation = {
                        "route": route,
                        "vector_id": vector_id,
                        "accepted": result["accepted"],
                        "error_class": result["error_class"],
                        "boundary": result["boundary"],
                    }
                    observations.append(observation)
                    if result["accepted"] is not expected_acceptance or result["error_class"] != expected_class:
                        findings.append(
                            {
                                "code": "P1A7.3.ROUTE.DIVERGENCE",
                                "route": route,
                                "vector_id": vector_id,
                                "message": (
                                    f"expected accepted={expected_acceptance!r}, error_class={expected_class!r}; "
                                    f"observed accepted={result['accepted']!r}, error_class={result['error_class']!r}"
                                ),
                            }
                        )
                    if precedence and result["error_class"] != precedence[0]:
                        findings.append(
                            {
                                "code": "P1A7.3.PRECEDENCE.DIVERGENCE",
                                "route": route,
                                "vector_id": vector_id,
                                "message": "observed class differs from declared first authoritative boundary",
                            }
                        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        findings.append(
            {
                "code": "P1A7.3.REPLAY.UNAVAILABLE",
                "route": "all",
                "vector_id": "all",
                "message": str(exc),
            }
        )

    positive_rows = [row for row in observations if row["vector_id"] == "a7.3-positive-seed"]
    negative_rows = [row for row in observations if row["vector_id"] != "a7.3-positive-seed"]
    positive_ok = len(positive_rows) == len(ROUTES) and all(
        row["accepted"] is True and row["error_class"] is None for row in positive_rows
    )
    negative_ok = len(negative_rows) == len(ROUTES) * len(vector_ids) and all(
        row["accepted"] is False for row in negative_rows
    )
    class_ok = negative_ok and all(
        len({row["error_class"] for row in negative_rows if row["vector_id"] == vector_id}) == 1
        for vector_id in vector_ids
    )
    precedence_ok = bool(multi_ids) and all(
        len({row["error_class"] for row in negative_rows if row["vector_id"] == vector_id}) == 1
        for vector_id in multi_ids
    ) and not any(item["code"] == "P1A7.3.PRECEDENCE.DIVERGENCE" for item in findings)
    report = {
        "tool": "eigiib-structural-route-replay",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "profile": PROFILE,
        "routes": ROUTES,
        "vector_ids": vector_ids,
        "multi_defect_vector_ids": multi_ids,
        "positive_replay_result": "conformant" if positive_ok else "non-conformant",
        "negative_replay_result": "conformant" if negative_ok and not findings else "non-conformant",
        "error_class_equivalence_result": "conformant" if class_ok and not findings else "non-conformant",
        "multi_defect_precedence_result": "conformant" if precedence_ok and not findings else "non-conformant",
        "observation_count": len(observations),
        "observations": observations,
        "overall_result": (
            "conformant"
            if positive_ok and negative_ok and class_ok and precedence_ok and not findings
            else "non-conformant"
        ),
        "findings": findings,
        "claim_boundary": [
            "a7-3-structural-closure-does-not-imply-cryptographic-negative-corpus-closure",
            "multi-defect-precedence-equivalence-does-not-imply-identical-parser-control-flow",
            "fixture-identity-validation-does-not-imply-production-artifact-authenticity",
            "pre-cose-structural-rejection-does-not-imply-go-cose-invocation",
        ],
    }
    if expected is not None:
        expected_value = strict_json(expected.read_bytes(), "P1A7.3.EXPECTED")
        if report != expected_value:
            report["findings"].append(
                {
                    "code": "P1A7.3.CANONICAL.DIVERGENCE",
                    "route": "all",
                    "vector_id": "all",
                    "message": "structural route replay differs from checked-in canonical result",
                }
            )
            report["overall_result"] = "non-conformant"
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--go", default="go")
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = check_repository(args.root, args.go, args.expected)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["overall_result"])
        for finding in result["findings"]:
            print(f"{finding['code']}: {finding['route']}: {finding['vector_id']}: {finding['message']}")
    return 0 if result["overall_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
