#!/usr/bin/env python3
"""Run the frozen E16-A5 verifier matrix through two non-importing processes."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E16-A5-MATRIX-REPORT-1.0"
MATRIX_STANDARD = "EIGIIB-E16-A5-MATRIX-1.0"
VERIFIER_STANDARD = "EIGIIB-E16-A5-VERIFIER-1.0"
SOURCE_COMMIT = "b28fe74f829141232770155724620617bfb1241c"


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def confined(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("path must be non-empty and repository-relative")
    value = (root / relative).resolve()
    value.relative_to(root)
    if not value.is_file():
        raise FileNotFoundError(relative)
    return value


def invoke(tool: Path, case: dict[str, Any], root: Path) -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, str(tool)],
        cwd=root,
        input=json.dumps(case, sort_keys=True) + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    if proc.returncode:
        raise RuntimeError(
            f"{tool.name} exited {proc.returncode}: {proc.stderr or proc.stdout}"
        )
    value = json.loads(proc.stdout)
    if not isinstance(value, dict):
        raise RuntimeError(f"{tool.name} emitted a non-object")
    return value


def run_matrix(
    root: Path,
    matrix_path: Path = Path("conformance/e16-a5-verifier-matrix.json"),
) -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []
    case_reports: list[dict[str, Any]] = []
    state_counts = {
        "e16-preservation-closure-verified": 0,
        "rejected": 0,
        "held": 0,
        "unavailable": 0,
    }
    try:
        catalog_file = confined(root, matrix_path.as_posix())
        catalog = json.loads(catalog_file.read_text(encoding="utf-8"))
        if not isinstance(catalog, dict):
            raise ValueError("matrix root must be an object")
    except Exception as exc:
        return {
            "tool": "eigiib-e16-verifier-matrix",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "matrix_standard": MATRIX_STANDARD,
            "case_count": 0,
            "matched_case_count": 0,
            "verifier_count": 0,
            "verifier_source_distinct": False,
            "reports_byte_identical": False,
            "differential_restore_result": "non-conformant",
            "state_counts": state_counts,
            "case_reports": [],
            "findings": [
                asdict(Finding("error", "E16A5.MATRIX.LOAD", matrix_path.as_posix(), str(exc)))
            ],
            "overall_result": "non-conformant",
        }

    if (catalog.get("standard") != MATRIX_STANDARD or catalog.get("status") != "frozen-vectors" or catalog.get("source_e16_a4_commit") != SOURCE_COMMIT):
        findings.append(
            Finding("error", "E16A5.MATRIX.HEADER", matrix_path.as_posix(), "matrix header invalid")
        )
    reference_rel = catalog.get("reference_verifier")
    independent_rel = catalog.get("independent_verifier")
    try:
        reference = confined(root, str(reference_rel))
        independent = confined(root, str(independent_rel))
    except Exception as exc:
        findings.append(
            Finding("error", "E16A5.MATRIX.VERIFIER", matrix_path.as_posix(), str(exc))
        )
        reference = independent = catalog_file

    source_distinct = False
    if reference != independent:
        ref_raw = reference.read_bytes()
        ind_raw = independent.read_bytes()
        source_distinct = hashlib.sha256(ref_raw).digest() != hashlib.sha256(ind_raw).digest()
        if not source_distinct:
            findings.append(
                Finding("error", "E16A5.MATRIX.SOURCE.IDENTITY", "", "verifier sources are byte-identical")
            )
        ref_text = ref_raw.decode("utf-8", errors="replace")
        ind_text = ind_raw.decode("utf-8", errors="replace")
        if independent.stem in ref_text or reference.stem in ind_text:
            findings.append(
                Finding("error", "E16A5.MATRIX.SOURCE.IMPORT", "", "verifier source references the other implementation")
            )
    else:
        findings.append(
            Finding("error", "E16A5.MATRIX.SOURCE.PATH", "", "verifier paths must differ")
        )

    cases = catalog.get("cases")
    if not isinstance(cases, list):
        findings.append(
            Finding("error", "E16A5.MATRIX.CASES", matrix_path.as_posix(), "cases must be an array")
        )
        cases = []

    seen: set[str] = set()
    matched = 0
    byte_identical = True
    for index, case in enumerate(cases):
        path = f"cases[{index}]"
        if not isinstance(case, dict):
            findings.append(Finding("error", "E16A5.MATRIX.CASE", path, "case must be an object"))
            continue
        case_id = case.get("id")
        expected_state = case.get("expected_state")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            findings.append(Finding("error", "E16A5.MATRIX.CASE.ID", path, "case id invalid or duplicated"))
            continue
        seen.add(case_id)
        try:
            reference_report = invoke(reference, case, root)
            independent_report = invoke(independent, case, root)
        except Exception as exc:
            findings.append(Finding("error", "E16A5.MATRIX.EXECUTION", path, str(exc)))
            continue
        same = canonical(reference_report) == canonical(independent_report)
        byte_identical = byte_identical and same
        if not same:
            findings.append(
                Finding("error", "E16A5.MATRIX.DIFFERENTIAL", path, "verifier reports differ")
            )
        if (
            reference_report.get("standard") != VERIFIER_STANDARD
            or independent_report.get("standard") != VERIFIER_STANDARD
        ):
            findings.append(
                Finding("error", "E16A5.MATRIX.VERIFIER.STANDARD", path, "verifier standard invalid")
            )
        state = reference_report.get("state")
        expected_match = state == expected_state and independent_report.get("state") == expected_state
        if expected_match and same:
            matched += 1
        else:
            findings.append(
                Finding(
                    "error",
                    "E16A5.MATRIX.EXPECTED",
                    path,
                    f"expected {expected_state!r}, received {state!r}",
                )
            )
        if state in state_counts:
            state_counts[state] += 1
        else:
            findings.append(
                Finding("error", "E16A5.MATRIX.STATE", path, f"unexpected state {state!r}")
            )
        case_reports.append(
            {
                "id": case_id,
                "expected_state": expected_state,
                "state": state,
                "reports_byte_identical": same,
                "route_count": reference_report.get("route_count"),
                "verified_route_count": reference_report.get("verified_route_count"),
                "findings": reference_report.get("findings", []),
            }
        )

    overall = (
        "conformant"
        if not findings and matched == len(cases) and source_distinct and byte_identical
        else "non-conformant"
    )
    return {
        "tool": "eigiib-e16-verifier-matrix",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "matrix_standard": MATRIX_STANDARD,
        "case_count": len(cases),
        "matched_case_count": matched,
        "verifier_count": 2,
        "verifier_source_distinct": source_distinct,
        "reports_byte_identical": byte_identical,
        "differential_restore_result": overall,
        "state_counts": state_counts,
        "case_reports": case_reports,
        "findings": [asdict(item) for item in sorted(findings)],
        "overall_result": overall,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--matrix", default="conformance/e16-a5-verifier-matrix.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = run_matrix(Path(args.root), Path(args.matrix))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
