"""Three-route execution and canonical comparison for P1-A7.4."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from eigiib_signature_replay_common import (
    CORPUS_PATH,
    PROFILE,
    RESULT_KEYS,
    ROUTES,
    STANDARD,
    TOOL_VERSION,
    load_adapter,
)
from eigiib_signature_replay_corpus import validate_corpus


def build_go_adapter(go: str, module_dir: Path, output: Path) -> None:
    completed = subprocess.run(
        [
            go,
            "build",
            "-mod=readonly",
            "-trimpath",
            "-o",
            str(output),
            "./cmd/eigiib-p1-signature-adapter",
        ],
        cwd=module_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"unable to build {module_dir.name} adapter: {message}")


def run_adapter(
    command: list[str],
    input_path: Path,
    vector_id: str,
    route: str,
) -> dict[str, Any]:
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
        result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{route}: invalid adapter output: {exc}") from exc
    if not isinstance(result, dict) or set(result) != RESULT_KEYS:
        raise ValueError(f"{route}: result fields differ from contract")
    if result.get("standard") != STANDARD or result.get("route") != route:
        raise ValueError(f"{route}: result identity mismatch")
    if result.get("vector_id") != vector_id:
        raise ValueError(f"{route}: result vector mismatch")
    if not isinstance(result.get("accepted"), bool):
        raise ValueError(f"{route}: accepted is not boolean")
    if result.get("error_class") is not None and not isinstance(result.get("error_class"), str):
        raise ValueError(f"{route}: error class carrier invalid")
    if not isinstance(result.get("boundary"), str) or not result["boundary"]:
        raise ValueError(f"{route}: boundary carrier invalid")
    return result


def check_repository(
    root: Path,
    go: str = "go",
    openssl: str = "openssl",
    expected: Path | None = None,
    corpus_path: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    adapter = load_adapter(root)
    findings: list[dict[str, str]] = []
    observations: list[dict[str, Any]] = []
    vector_ids: list[str] = []
    multi_ids: set[str] = set()
    try:
        selected_corpus = corpus_path or root / CORPUS_PATH
        seed, rows, _ = validate_corpus(root, selected_corpus, adapter, openssl)
        vector_ids = [row["id"] for row in rows]
        multi_ids = {row["id"] for row in rows if len(row["precedence"]) > 1}
        with tempfile.TemporaryDirectory(prefix="eigiib-p1-a7-4-") as temporary:
            temp = Path(temporary)
            independent = temp / ("independent-signature.exe" if os.name == "nt" else "independent-signature")
            external = temp / ("external-signature.exe" if os.name == "nt" else "external-signature")
            build_go_adapter(go, root / "independent", independent)
            build_go_adapter(go, root / "external", external)
            commands = {
                "reference-python-openssl": [
                    sys.executable,
                    str(root / "tools/eigiib_p1_a7_signature_adapter.py"),
                    "--openssl",
                    openssl,
                ],
                "independent-go-stdlib": [str(independent)],
                "external-go-cose": [str(external)],
            }
            inputs = [
                {
                    "id": "a7-positive-p1-a2-carrier",
                    "bytes": seed,
                    "expected_acceptance": True,
                    "expected_class": None,
                    "expected_boundary": "signature",
                }
            ] + [
                {
                    "id": row["id"],
                    "bytes": row["bytes"],
                    "expected_acceptance": False,
                    "expected_class": row["expected_class"],
                    "expected_boundary": row["expected_boundary"],
                }
                for row in rows
            ]
            for item in inputs:
                input_path = temp / f"{item['id']}.json"
                input_path.write_bytes(item["bytes"])
                for route in ROUTES:
                    result = run_adapter(commands[route], input_path, item["id"], route)
                    observation = {
                        "route": route,
                        "vector_id": item["id"],
                        "accepted": result["accepted"],
                        "error_class": result["error_class"],
                        "boundary": result["boundary"],
                    }
                    observations.append(observation)
                    if (
                        result["accepted"] is not item["expected_acceptance"]
                        or result["error_class"] != item["expected_class"]
                        or result["boundary"] != item["expected_boundary"]
                    ):
                        findings.append(
                            {
                                "code": "P1A7.4.ROUTE.DIVERGENCE",
                                "route": route,
                                "vector_id": item["id"],
                                "message": (
                                    f"expected accepted={item['expected_acceptance']!r}, "
                                    f"error_class={item['expected_class']!r}, "
                                    f"boundary={item['expected_boundary']!r}; observed "
                                    f"accepted={result['accepted']!r}, "
                                    f"error_class={result['error_class']!r}, "
                                    f"boundary={result['boundary']!r}"
                                ),
                            }
                        )
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
        findings.append(
            {
                "code": "P1A7.4.REPLAY.UNAVAILABLE",
                "route": "all",
                "vector_id": "all",
                "message": str(exc),
            }
        )

    positive_rows = [
        row for row in observations
        if row["vector_id"] == "a7-positive-p1-a2-carrier"
    ]
    negative_rows = [
        row for row in observations
        if row["vector_id"] != "a7-positive-p1-a2-carrier"
    ]
    positive_ok = len(positive_rows) == len(ROUTES) and all(
        row["accepted"] is True
        and row["error_class"] is None
        and row["boundary"] == "signature"
        for row in positive_rows
    )
    negative_ok = (
        len(negative_rows) == len(ROUTES) * len(vector_ids)
        and all(row["accepted"] is False for row in negative_rows)
    )
    class_ok = negative_ok and all(
        len({
            (
                row["error_class"],
                row["boundary"],
            )
            for row in negative_rows
            if row["vector_id"] == vector_id
        }) == 1
        for vector_id in vector_ids
    )
    precedence_ok = bool(multi_ids) and all(
        len({
            (
                row["error_class"],
                row["boundary"],
            )
            for row in negative_rows
            if row["vector_id"] == vector_id
        }) == 1
        for vector_id in multi_ids
    )
    report = {
        "tool": "eigiib-signature-route-replay",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "profile": PROFILE,
        "routes": ROUTES,
        "vector_ids": vector_ids,
        "positive_replay_result": "conformant" if positive_ok else "non-conformant",
        "negative_replay_result": (
            "conformant" if negative_ok and not findings else "non-conformant"
        ),
        "error_class_equivalence_result": (
            "conformant" if class_ok and not findings else "non-conformant"
        ),
        "multi_defect_precedence_result": (
            "conformant" if precedence_ok and not findings else "non-conformant"
        ),
        "observation_count": len(observations),
        "observations": observations,
        "overall_result": (
            "conformant"
            if positive_ok and negative_ok and class_ok and precedence_ok and not findings
            else "non-conformant"
        ),
        "findings": findings,
        "claim_boundary": [
            "valid-signature-does-not-imply-trusted-or-authorized-signer",
            "manifest-and-dsse-replay-does-not-imply-eigiib-claim-truth",
            "fixture-signature-replay-does-not-imply-production-key-custody",
            "external-route-pre-cose-dsse-check-does-not-imply-go-cose-invocation",
            "a7-4-closure-does-not-imply-cbor-cose-or-receipt-negative-closure",
        ],
    }
    if expected is not None:
        expected_value = json.loads(expected.read_text(encoding="utf-8"))
        if report != expected_value:
            report["findings"].append(
                {
                    "code": "P1A7.4.CANONICAL.DIVERGENCE",
                    "route": "all",
                    "vector_id": "all",
                    "message": "signature replay differs from checked-in canonical result",
                }
            )
            report["overall_result"] = "non-conformant"
    return report
