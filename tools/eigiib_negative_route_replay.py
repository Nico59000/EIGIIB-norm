#!/usr/bin/env python3
"""Replay the first P1-A7.2 route-bound negative-vector slice."""
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

STANDARD = "EIGIIB-P1-A7.2-1.0"
PROFILE = "first-route-bound-json-utf8-base64-path-v1"
TOOL_VERSION = "0.1.0"
ROUTES = [
    "reference-python-openssl",
    "independent-go-stdlib",
    "external-go-cose",
]
VECTOR_IDS = [
    "a7-json-duplicate-standard",
    "a7-json-trailing-data",
    "a7-utf8-invalid-prefix",
    "a7-base64-extra-padding",
    "a7-path-parent-traversal",
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

    return json.loads(raw.decode("utf-8"), object_pairs_hook=hook)


def load_generator(root: Path) -> Any:
    path = root / "tools/eigiib_negative_vector_generator.py"
    spec = importlib.util.spec_from_file_location("eigiib_negative_vector_generator_a72", path)
    if spec is None or spec.loader is None:
        raise ValueError("unable to load P1-A7.1 generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_go_adapter(go: str, module_dir: Path, output: Path) -> None:
    completed = subprocess.run(
        [go, "build", "-mod=readonly", "-trimpath", "-o", str(output), "./cmd/eigiib-p1-negative-adapter"],
        cwd=module_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"unable to build route adapter in {module_dir.name}: {message}")


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
    try:
        generator = load_generator(root)
        manifest_path = root / "tests/fixtures/p1-a7/corpus.json"
        manifest = generator.strict_json_loads(manifest_path.read_bytes(), "P1A7.MANIFEST")
        _, generated = generator.validate_manifest(root, manifest)
        rows = {row["id"]: row for row in generated}
        if any(vector_id not in rows for vector_id in VECTOR_IDS):
            raise ValueError("P1-A7.2 vector set is incomplete")
        expected_classes = {
            vector["id"]: vector["expect"]["errorClass"]
            for vector in manifest["vectors"]
            if vector["id"] in VECTOR_IDS
        }
        positive_raw = (root / "tests/fixtures/p1-a7/source/generator-seed.json").read_bytes()

        with tempfile.TemporaryDirectory(prefix="eigiib-p1-a7-2-") as temporary:
            temp = Path(temporary)
            independent_binary = temp / ("independent-adapter.exe" if os.name == "nt" else "independent-adapter")
            external_binary = temp / ("external-adapter.exe" if os.name == "nt" else "external-adapter")
            build_go_adapter(go, root / "independent", independent_binary)
            build_go_adapter(go, root / "external", external_binary)
            route_commands = {
                "reference-python-openssl": [sys.executable, str(root / "tools/eigiib_p1_a7_reference_adapter.py")],
                "independent-go-stdlib": [str(independent_binary)],
                "external-go-cose": [str(external_binary)],
            }
            inputs: list[tuple[str, bytes, bool, str | None]] = [
                ("a7-positive-seed", positive_raw, True, None),
            ] + [
                (vector_id, rows[vector_id]["bytes"], False, expected_classes[vector_id])
                for vector_id in VECTOR_IDS
            ]
            for vector_id, raw, expected_acceptance, expected_class in inputs:
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
                                "code": "P1A7.2.ROUTE.DIVERGENCE",
                                "route": route,
                                "vector_id": vector_id,
                                "message": (
                                    f"expected accepted={expected_acceptance!r}, error_class={expected_class!r}; "
                                    f"observed accepted={result['accepted']!r}, error_class={result['error_class']!r}"
                                ),
                            }
                        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        findings.append(
            {
                "code": "P1A7.2.REPLAY.UNAVAILABLE",
                "route": "all",
                "vector_id": "all",
                "message": str(exc),
            }
        )

    positive_rows = [row for row in observations if row["vector_id"] == "a7-positive-seed"]
    negative_rows = [row for row in observations if row["vector_id"] != "a7-positive-seed"]
    positive_ok = len(positive_rows) == len(ROUTES) and all(
        row["accepted"] is True and row["error_class"] is None for row in positive_rows
    )
    negative_ok = len(negative_rows) == len(ROUTES) * len(VECTOR_IDS) and all(
        row["accepted"] is False for row in negative_rows
    )
    class_ok = negative_ok and all(
        len({row["error_class"] for row in negative_rows if row["vector_id"] == vector_id}) == 1
        for vector_id in VECTOR_IDS
    )
    report = {
        "tool": "eigiib-negative-route-replay",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "profile": PROFILE,
        "routes": ROUTES,
        "vector_ids": VECTOR_IDS,
        "positive_replay_result": "conformant" if positive_ok else "non-conformant",
        "negative_replay_result": "conformant" if negative_ok and not findings else "non-conformant",
        "error_class_equivalence_result": "conformant" if class_ok and not findings else "non-conformant",
        "multi_defect_precedence_result": "not-evaluated-by-p1-a7.2",
        "observation_count": len(observations),
        "observations": observations,
        "overall_result": "conformant" if positive_ok and negative_ok and class_ok and not findings else "non-conformant",
        "findings": findings,
        "claim_boundary": [
            "a7-2-first-slice-does-not-imply-full-negative-corpus-closure",
            "pre-cose-rejection-does-not-imply-external-cose-library-invocation",
            "portable-error-equivalence-does-not-imply-identical-parser-internals",
            "fixture-replay-does-not-imply-production-input-coverage",
        ],
    }
    if expected is not None:
        expected_value = strict_json(expected.read_bytes(), "P1A7.2.EXPECTED")
        if report != expected_value:
            report["findings"].append(
                {
                    "code": "P1A7.2.CANONICAL.DIVERGENCE",
                    "route": "all",
                    "vector_id": "all",
                    "message": "route replay differs from checked-in canonical result",
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
