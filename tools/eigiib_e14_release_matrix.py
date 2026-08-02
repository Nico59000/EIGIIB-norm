#!/usr/bin/env python3
"""Cross-implementation E14-A5 release-decision matrix."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E14-A5-1.0"


def invoke(command: list[str]) -> dict[str, str]:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr or completed.stdout or f"command failed: {command}")
    return json.loads(completed.stdout)


def run_matrix(root: Path, catalog_path: Path) -> dict:
    catalog = json.loads((root / catalog_path).read_text(encoding="utf-8"))
    findings: list[dict[str, str]] = []
    outcomes: list[dict[str, str]] = []
    reference = root / "tools/eigiib_e14_release_check.py"
    independent = root / "tools/eigiib_e14_release_independent.py"
    cases = catalog.get("cases", []) if isinstance(catalog, dict) else []
    if catalog.get("standard") != STANDARD:
        findings.append({"severity": "error", "code": "E14A5.MATRIX.STANDARD", "path": str(catalog_path), "message": "unexpected matrix standard"})
    if not isinstance(cases, list) or not cases:
        findings.append({"severity": "error", "code": "E14A5.MATRIX.CASES", "path": str(catalog_path), "message": "cases must be a non-empty array"})
        cases = []
    seen: set[str] = set()
    for position, case in enumerate(cases):
        path = f"cases[{position}]"
        if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not case["id"]:
            findings.append({"severity": "error", "code": "E14A5.MATRIX.ID", "path": path, "message": "case id must be non-empty"})
            continue
        identifier = case["id"]
        if identifier in seen:
            findings.append({"severity": "error", "code": "E14A5.MATRIX.DUPLICATE", "path": path, "message": f"duplicate case {identifier}"})
            continue
        seen.add(identifier)
        inputs = case.get("inputs")
        expected = case.get("expected_state")
        if not isinstance(inputs, dict) or expected not in {"released", "rejected", "held", "unavailable"}:
            findings.append({"severity": "error", "code": "E14A5.MATRIX.CASE", "path": path, "message": "invalid case inputs or expected state"})
            continue
        with tempfile.TemporaryDirectory() as tmp:
            vector = Path(tmp) / "vector.json"
            vector.write_text(json.dumps({"id": identifier, "inputs": inputs}), encoding="utf-8")
            try:
                ref = invoke([sys.executable, str(reference), "--vector", str(vector)])
                alt = invoke([sys.executable, str(independent), str(vector)])
            except Exception as exc:
                findings.append({"severity": "error", "code": "E14A5.MATRIX.EXECUTION", "path": path, "message": str(exc)})
                continue
        ref_state, alt_state = ref.get("state"), alt.get("state")
        outcomes.append({"id": identifier, "reference": ref_state, "independent": alt_state, "expected": expected})
        if ref_state != alt_state:
            findings.append({"severity": "error", "code": "E14A5.MATRIX.DIFFERENTIAL", "path": path, "message": "verifiers disagree"})
        if ref_state != expected:
            findings.append({"severity": "error", "code": "E14A5.MATRIX.EXPECTED", "path": path, "message": f"derived {ref_state}, expected {expected}"})
    errors = any(item["severity"] == "error" for item in findings)
    return {
        "tool": "eigiib-e14-release-matrix",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "structural_result": "non-conformant" if errors else "conformant",
        "verifier_matrix_result": "non-conformant" if errors else "conformant",
        "verifier_count": 2,
        "case_count": len(cases),
        "matched_case_count": sum(1 for item in outcomes if item["reference"] == item["independent"] == item["expected"]),
        "outcomes": outcomes,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--catalog", default="conformance/e14-a5-verifier-matrix.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = run_matrix(Path(args.root).resolve(), Path(args.catalog))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
