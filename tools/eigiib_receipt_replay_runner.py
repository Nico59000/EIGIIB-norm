"""Three-route execution and canonical comparison for P1-A7.6."""
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from eigiib_receipt_replay_common import CORPUS_PATH, POSITIVE_ID, PROFILE, RESULT_KEYS, ROUTES, STANDARD, TOOL_VERSION, load_adapter
from eigiib_receipt_replay_corpus import validate_corpus


def build_go_adapter(go: str, module_dir: Path, output: Path) -> None:
    completed = subprocess.run([go, "build", "-mod=readonly", "-trimpath", "-o", str(output), "./cmd/eigiib-p1-receipt-adapter"], cwd=module_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode != 0:
        raise ValueError(f"unable to build {module_dir.name} adapter: {completed.stderr.decode('utf-8', errors='replace').strip()}")


def run_adapter(command: list[str], input_path: Path, vector_id: str, route: str) -> dict[str, Any]:
    completed = subprocess.run(command + ["--input", str(input_path), "--vector-id", vector_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
    if completed.returncode != 0:
        raise ValueError(f"{route}: adapter unavailable: {completed.stderr.decode('utf-8', errors='replace').strip()}")
    try:
        result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{route}: invalid adapter output: {exc}") from exc
    if not isinstance(result, dict) or set(result) != RESULT_KEYS:
        raise ValueError(f"{route}: result fields differ from contract")
    if result.get("standard") != STANDARD or result.get("route") != route or result.get("vector_id") != vector_id:
        raise ValueError(f"{route}: result identity mismatch")
    if not isinstance(result.get("accepted"), bool):
        raise ValueError(f"{route}: accepted is not boolean")
    if result.get("error_class") is not None and not isinstance(result.get("error_class"), str):
        raise ValueError(f"{route}: error class carrier invalid")
    if not isinstance(result.get("boundary"), str) or not result["boundary"]:
        raise ValueError(f"{route}: boundary carrier invalid")
    return result


def check_repository(root: Path, go: str = "go", openssl: str = "openssl", expected: Path | None = None, corpus_path: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    adapter = load_adapter(root)
    findings: list[dict[str, str]] = []
    observations: list[dict[str, Any]] = []
    vector_ids: list[str] = []
    multi_ids: set[str] = set()
    try:
        seed, rows, _ = validate_corpus(root, corpus_path or root / CORPUS_PATH, adapter, openssl)
        vector_ids = [row["id"] for row in rows]
        multi_ids = {row["id"] for row in rows if len(row["precedence"]) > 1}
        with tempfile.TemporaryDirectory(prefix="eigiib-p1-a7-6-") as temporary:
            temp = Path(temporary)
            independent = temp / ("independent-receipt.exe" if os.name == "nt" else "independent-receipt")
            external = temp / ("external-receipt.exe" if os.name == "nt" else "external-receipt")
            build_go_adapter(go, root / "independent", independent)
            build_go_adapter(go, root / "external", external)
            commands = {
                "reference-python-openssl": [sys.executable, str(root / "tools/eigiib_p1_a7_receipt_adapter.py"), "--openssl", openssl],
                "independent-go-stdlib": [str(independent)],
                "external-go-cose": [str(external)],
            }
            inputs = [{"id": POSITIVE_ID, "bytes": seed, "expected_acceptance": True, "expected_class": None, "expected_boundary": "receipt-root"}] + [
                {"id": row["id"], "bytes": row["bytes"], "expected_acceptance": False, "expected_class": row["expected_class"], "expected_boundary": row["expected_boundary"]}
                for row in rows
            ]
            for item in inputs:
                input_path = temp / f"{item['id']}.json"
                input_path.write_bytes(item["bytes"])
                for route in ROUTES:
                    result = run_adapter(commands[route], input_path, item["id"], route)
                    observation = {"route": route, "vector_id": item["id"], "accepted": result["accepted"], "error_class": result["error_class"], "boundary": result["boundary"]}
                    observations.append(observation)
                    if result["accepted"] is not item["expected_acceptance"] or result["error_class"] != item["expected_class"] or result["boundary"] != item["expected_boundary"]:
                        findings.append({"code": "P1A7.6.ROUTE.DIVERGENCE", "route": route, "vector_id": item["id"], "message": f"expected accepted={item['expected_acceptance']!r}, error_class={item['expected_class']!r}, boundary={item['expected_boundary']!r}; observed accepted={result['accepted']!r}, error_class={result['error_class']!r}, boundary={result['boundary']!r}"})
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
        findings.append({"code": "P1A7.6.REPLAY.UNAVAILABLE", "route": "all", "vector_id": "all", "message": str(exc)})
    positive_rows = [row for row in observations if row["vector_id"] == POSITIVE_ID]
    negative_rows = [row for row in observations if row["vector_id"] != POSITIVE_ID]
    positive_ok = len(positive_rows) == len(ROUTES) and all(row["accepted"] is True and row["error_class"] is None and row["boundary"] == "receipt-root" for row in positive_rows)
    negative_ok = len(negative_rows) == len(ROUTES) * len(vector_ids) and all(row["accepted"] is False for row in negative_rows)
    class_ok = negative_ok and all(len({(row["error_class"], row["boundary"]) for row in negative_rows if row["vector_id"] == vector_id}) == 1 for vector_id in vector_ids)
    precedence_ok = bool(multi_ids) and all(len({(row["error_class"], row["boundary"]) for row in negative_rows if row["vector_id"] == vector_id}) == 1 for vector_id in multi_ids)
    report = {
        "tool": "eigiib-receipt-route-replay",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "profile": PROFILE,
        "routes": ROUTES,
        "vector_ids": vector_ids,
        "positive_replay_result": "conformant" if positive_ok else "non-conformant",
        "negative_replay_result": "conformant" if negative_ok and not findings else "non-conformant",
        "error_class_equivalence_result": "conformant" if class_ok and not findings else "non-conformant",
        "multi_defect_precedence_result": "conformant" if precedence_ok and not findings else "non-conformant",
        "observation_count": len(observations),
        "observations": observations,
        "overall_result": "conformant" if positive_ok and negative_ok and class_ok and precedence_ok and not findings else "non-conformant",
        "findings": findings,
        "claim_boundary": [
            "valid-receipt-signature-does-not-imply-trusted-transparency-service",
            "valid-inclusion-proof-does-not-imply-global-append-only-consistency",
            "closed-one-and-two-entry-proof-profile-does-not-imply-universal-receipt-interoperability",
            "external-route-invokes-go-cose-after-portable-receipt-gates",
            "a7-6-closure-does-not-imply-production-input-coverage-or-final-p1-a7-freeze",
        ],
    }
    if expected is not None:
        expected_value = json.loads(expected.read_text(encoding="utf-8"))
        if report != expected_value:
            report["findings"].append({"code": "P1A7.6.CANONICAL.DIVERGENCE", "route": "all", "vector_id": "all", "message": "Receipt replay differs from checked-in canonical result"})
            report["overall_result"] = "non-conformant"
    return report
