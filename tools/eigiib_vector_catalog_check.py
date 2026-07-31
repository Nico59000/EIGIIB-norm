#!/usr/bin/env python3
"""Static validator for the EIGIIB M0-A4 portable conformance vector corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.1"
STANDARD = "EIGIIB-M0-A4-1.0"
CANONICALIZATION = "m0-a4-json-sha256-v1"
CONTRACTS = {
    "M0-A2": {
        "result_field": "overall_result",
        "results": {"conformant", "conformant-with-documented-deviations", "incomplete", "non-conformant"},
    },
    "M0-A3": {
        "result_field": "structural_result",
        "results": {"conformant", "non-conformant"},
    },
}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def contains_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, list):
        return any(contains_float(x) for x in value)
    if isinstance(value, dict):
        return any(contains_float(x) for x in value.values())
    return False


class Checker:
    def __init__(self, root: Path, catalog: Path):
        self.root = root.resolve()
        self.catalog_path = catalog
        self.findings: list[Finding] = []
        self.vector_count = 0
        self.contract_counts = {key: 0 for key in CONTRACTS}

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def confined(self, rel: Path, code: str, *, must_exist: bool = False) -> Path | None:
        if rel.is_absolute():
            self.add("error", f"{code}.PATH", "path must be repository-relative", str(rel))
            return None
        p = (self.root / rel).resolve(strict=False)
        try:
            p.relative_to(self.root)
        except ValueError:
            self.add("error", f"{code}.PATH", "path escapes repository root", str(rel))
            return None
        if must_exist and (not p.exists() or not p.is_file()):
            self.add("error", f"{code}.MISSING", "file is missing", str(rel))
            return None
        return p

    def load(self) -> dict[str, Any] | None:
        p = self.confined(self.catalog_path, "M0A4.CATALOG", must_exist=True)
        if p is None:
            return None
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "M0A4.CATALOG.PARSE", str(exc), str(self.catalog_path))
            return None
        if not isinstance(obj, dict):
            self.add("error", "M0A4.CATALOG.TYPE", "catalog root must be an object", str(self.catalog_path))
            return None
        return obj

    def check_a2_fixture(self, fixture: dict[str, Any], loc: str) -> None:
        expected = {"graph", "component_reports"}
        if set(fixture) != expected:
            self.add("error", "M0A4.A2.FIELDS", "M0-A2 fixture must contain exactly graph and component_reports", loc)
        graph = fixture.get("graph")
        if not isinstance(graph, dict):
            self.add("error", "M0A4.A2.GRAPH", "graph must be an object", loc)
        reports = fixture.get("component_reports")
        if not isinstance(reports, dict):
            self.add("error", "M0A4.A2.REPORTS", "component_reports must be an object", loc)
            return
        for component_id, report in reports.items():
            if not isinstance(component_id, str) or not component_id or not isinstance(report, dict):
                self.add("error", "M0A4.A2.REPORT_ITEM", "component_reports must map non-empty ids to report objects", loc)

    def check_a3_fixture(self, fixture: dict[str, Any], loc: str) -> None:
        expected = {"authorities", "registry", "evidence_files"}
        if set(fixture) != expected:
            self.add("error", "M0A4.A3.FIELDS", "M0-A3 fixture must contain exactly authorities, registry and evidence_files", loc)
        authorities = fixture.get("authorities")
        if not isinstance(authorities, list) or any(not isinstance(x, str) or not x for x in authorities):
            self.add("error", "M0A4.A3.AUTHORITIES", "authorities must be an array of non-empty strings", loc)
        elif len(authorities) != len(set(authorities)):
            self.add("error", "M0A4.A3.AUTHORITY_DUPLICATE", "authorities must be unique", loc)
        if not isinstance(fixture.get("registry"), dict):
            self.add("error", "M0A4.A3.REGISTRY", "registry must be an object", loc)
        evidence = fixture.get("evidence_files")
        if not isinstance(evidence, dict):
            self.add("error", "M0A4.A3.EVIDENCE_FILES", "evidence_files must be an object", loc)
            return
        for rel, content in evidence.items():
            if not isinstance(rel, str) or not rel or not isinstance(content, str):
                self.add("error", "M0A4.A3.EVIDENCE_ITEM", "evidence_files must map non-empty paths to strings", loc)
                continue
            p = Path(rel)
            if p.is_absolute() or ".." in p.parts:
                self.add("error", "M0A4.A3.EVIDENCE_PATH", "materialized evidence file path must remain fixture-relative", loc)

    def check(self, obj: dict[str, Any]) -> None:
        if obj.get("standard") != STANDARD:
            self.add("error", "M0A4.STANDARD", f"standard must be {STANDARD}", str(self.catalog_path))
        if obj.get("canonicalization") != CANONICALIZATION:
            self.add("error", "M0A4.CANONICALIZATION", f"canonicalization must be {CANONICALIZATION}", str(self.catalog_path))

        supported = obj.get("supported_contracts")
        if not isinstance(supported, list) or set(supported) != set(CONTRACTS) or len(supported) != len(CONTRACTS):
            self.add("error", "M0A4.CONTRACTS", "supported_contracts must contain exactly the declared M0-A4 adapter set", str(self.catalog_path))
            supported_set = set()
        else:
            supported_set = set(supported)

        vectors = obj.get("vectors")
        if not isinstance(vectors, list) or not vectors:
            self.add("error", "M0A4.VECTORS", "vectors must be a non-empty array", str(self.catalog_path))
            return

        seen: set[str] = set()
        for i, vector in enumerate(vectors):
            loc = f"vectors[{i}]"
            if not isinstance(vector, dict):
                self.add("error", "M0A4.VECTOR.TYPE", "vector must be an object", loc)
                continue
            vid = vector.get("id")
            if not isinstance(vid, str) or not vid:
                self.add("error", "M0A4.VECTOR.ID", "vector id must be non-empty string", loc)
                continue
            if vid in seen:
                self.add("error", "M0A4.VECTOR.DUPLICATE", f"duplicate vector id: {vid}", loc)
                continue
            seen.add(vid)
            self.vector_count += 1

            contract = vector.get("contract")
            if contract not in CONTRACTS or contract not in supported_set:
                self.add("error", "M0A4.VECTOR.CONTRACT", f"unsupported vector contract: {contract}", loc)
                continue
            self.contract_counts[contract] += 1

            purpose = vector.get("purpose")
            if not isinstance(purpose, str) or not purpose.strip():
                self.add("error", "M0A4.VECTOR.PURPOSE", "purpose must be non-empty string", loc)

            fixture = vector.get("fixture")
            if not isinstance(fixture, dict):
                self.add("error", "M0A4.VECTOR.FIXTURE", "fixture must be an object", loc)
                continue
            if contains_float(fixture):
                self.add("error", "M0A4.VECTOR.FLOAT", "fixture must not contain floating-point values", loc)
            actual_digest = hashlib.sha256(canonical_bytes(fixture)).hexdigest()
            if vector.get("fixture_sha256") != actual_digest:
                self.add("error", "M0A4.VECTOR.DIGEST", "fixture_sha256 does not match canonical fixture bytes", loc)

            if contract == "M0-A2":
                self.check_a2_fixture(fixture, loc)
            elif contract == "M0-A3":
                self.check_a3_fixture(fixture, loc)

            expect = vector.get("expect")
            if not isinstance(expect, dict):
                self.add("error", "M0A4.VECTOR.EXPECT", "expect must be an object", loc)
                continue
            meta = CONTRACTS[contract]
            if expect.get("result_field") != meta["result_field"]:
                self.add("error", "M0A4.VECTOR.RESULT_FIELD", f"{contract} expects result field {meta['result_field']}", loc)
            if expect.get("result") not in meta["results"]:
                self.add("error", "M0A4.VECTOR.RESULT", "expected result is outside contract vocabulary", loc)
            codes = expect.get("error_codes")
            if not isinstance(codes, list) or any(not isinstance(code, str) or not code for code in codes):
                self.add("error", "M0A4.VECTOR.ERROR_CODES", "error_codes must be an array of non-empty strings", loc)
            elif codes != sorted(set(codes)):
                self.add("error", "M0A4.VECTOR.ERROR_CODES_ORDER", "error_codes must be sorted and unique", loc)

        for contract, count in self.contract_counts.items():
            if count == 0:
                self.add("error", "M0A4.CONTRACT.COVERAGE", f"no vector covers supported contract {contract}", str(self.catalog_path))

    def run(self) -> dict[str, Any]:
        obj = self.load()
        if obj is not None:
            self.check(obj)
        failed = any(f.severity == "error" for f in self.findings)
        return {
            "tool": "eigiib-vector-catalog-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if failed else "conformant",
            "vector_count": self.vector_count,
            "contract_counts": self.contract_counts,
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--catalog", default="conformance/conformance-vectors.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = Checker(Path(args.root), Path(args.catalog)).run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
