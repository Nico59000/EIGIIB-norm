#!/usr/bin/env python3
"""M0-A2 aggregate EIGIIB conformance reports without re-proving components."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.1"
STANDARD = "EIGIIB-M0-A2-1.0"

PASS_VALUES = {"conformant"}
QUALIFIED_VALUES = {"conformant-with-documented-deviations"}
INCOMPLETE_VALUES = {"partially-evaluated", "not-evaluated", "unavailable"}
FAIL_VALUES = {"non-conformant"}
RESULT_FIELDS = ("overall_result", "structural_result", "hardening_result", "result")


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Aggregator:
    def __init__(self, root: Path, results_dir: Path, graph: Path):
        self.root = root.resolve()
        self.results_dir = results_dir
        self.graph_path = graph
        self.findings: list[Finding] = []
        self.components: list[dict[str, Any]] = []

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def confined(self, rel: Path, code: str) -> Path | None:
        p = (self.root / rel).resolve(strict=False)
        try:
            p.relative_to(self.root)
        except ValueError:
            self.add("error", f"{code}.PATH", "path escapes repository root", str(rel))
            return None
        return p

    @staticmethod
    def filename(component_id: str) -> str:
        return component_id.lower() + ".json"

    def expected_ids(self, graph: dict[str, Any]) -> list[str]:
        expected = ["M0-A1"]
        nodes = graph.get("nodes")
        if not isinstance(nodes, list):
            self.add("error", "M0A2.GRAPH.NODES", "graph nodes must be an array", str(self.graph_path))
            return expected
        for item in nodes:
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("checker"):
                expected.append(item["id"])
        profiles = graph.get("hardening_profiles")
        if not isinstance(profiles, list):
            self.add("error", "M0A2.GRAPH.HARDENING", "hardening_profiles must be an array", str(self.graph_path))
            return expected
        for item in profiles:
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("checker"):
                expected.append(item["id"])
        if len(expected) != len(set(expected)):
            self.add("error", "M0A2.GRAPH.DUPLICATE", "derived component ids are not unique", str(self.graph_path))
        return expected

    @staticmethod
    def classify(report: dict[str, Any]) -> tuple[str | None, str | None]:
        field = next((candidate for candidate in RESULT_FIELDS if isinstance(report.get(candidate), str)), None)
        if field is None:
            return None, None
        value = report[field]
        if value in PASS_VALUES:
            return field, "pass"
        if value in QUALIFIED_VALUES:
            return field, "qualified"
        if value in INCOMPLETE_VALUES:
            return field, "incomplete"
        if value in FAIL_VALUES:
            return field, "fail"
        return field, "unsupported"

    @staticmethod
    def finding_counts(report: dict[str, Any]) -> dict[str, int]:
        out = {"error": 0, "warning": 0, "info": 0}
        findings = report.get("findings")
        if not isinstance(findings, list):
            return out
        for item in findings:
            if isinstance(item, dict) and item.get("severity") in out:
                out[item["severity"]] += 1
        return out

    def load_json(self, path: Path, code: str) -> dict[str, Any] | None:
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", f"{code}.PARSE", str(exc), str(path.relative_to(self.root)))
            return None
        if not isinstance(obj, dict):
            self.add("error", f"{code}.TYPE", "JSON root must be an object", str(path.relative_to(self.root)))
            return None
        return obj

    def run(self) -> dict[str, Any]:
        gp = self.confined(self.graph_path, "M0A2.GRAPH")
        rp = self.confined(self.results_dir, "M0A2.RESULTS")
        graph: dict[str, Any] | None = None
        if gp is None or not gp.is_file():
            self.add("error", "M0A2.GRAPH.MISSING", "extension graph is missing", str(self.graph_path))
        else:
            graph = self.load_json(gp, "M0A2.GRAPH")
        if rp is None or not rp.exists() or not rp.is_dir():
            self.add("error", "M0A2.RESULTS.MISSING", "results directory is missing", str(self.results_dir))

        expected = self.expected_ids(graph or {}) if graph is not None else ["M0-A1"]
        expected_names = {self.filename(cid) for cid in expected}

        if rp is not None and rp.is_dir():
            extras = sorted(p.name for p in rp.glob("*.json") if p.name not in expected_names)
            for name in extras:
                self.add("error", "M0A2.RESULTS.EXTRA", "unexpected component report", str(self.results_dir / name))

            for cid in expected:
                rel = self.results_dir / self.filename(cid)
                p = self.confined(rel, "M0A2.RESULT")
                if p is None or not p.is_file():
                    self.add("error", "M0A2.RESULT.MISSING", f"required component report missing: {cid}", str(rel))
                    continue
                raw = p.read_bytes()
                report = self.load_json(p, "M0A2.RESULT")
                if report is None:
                    continue
                tool = report.get("tool")
                standard = report.get("standard")
                if not isinstance(tool, str) or not tool:
                    self.add("error", "M0A2.RESULT.TOOL", f"{cid} has no non-empty tool id", str(rel))
                if not isinstance(standard, str) or not standard:
                    self.add("error", "M0A2.RESULT.STANDARD", f"{cid} has no non-empty standard id", str(rel))
                field, classification = self.classify(report)
                if field is None:
                    self.add("error", "M0A2.RESULT.FIELD", f"{cid} exposes no supported top-level conformance result", str(rel))
                    result_value = None
                else:
                    result_value = report[field]
                    if classification == "unsupported":
                        self.add("error", "M0A2.RESULT.VALUE", f"{cid} has unsupported {field} value {result_value!r}", str(rel))
                self.components.append({
                    "id": cid,
                    "path": str(rel),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                    "tool": tool if isinstance(tool, str) else "",
                    "standard": standard if isinstance(standard, str) else "",
                    "result_field": field or "",
                    "result": result_value,
                    "classification": classification or "unsupported",
                    "finding_counts": self.finding_counts(report),
                })

        classes = [c["classification"] for c in self.components]
        coverage_codes = {"M0A2.RESULT.MISSING", "M0A2.RESULT.PARSE", "M0A2.RESULT.TYPE", "M0A2.RESULTS.MISSING"}
        fatal_errors = any(
            f.severity == "error" and f.code not in coverage_codes
            for f in self.findings
        )
        coverage_incomplete = any(f.code in coverage_codes for f in self.findings)
        if fatal_errors or "fail" in classes or "unsupported" in classes:
            overall = "non-conformant"
        elif coverage_incomplete or len(self.components) != len(expected) or "incomplete" in classes:
            overall = "incomplete"
        elif "qualified" in classes:
            overall = "conformant-with-documented-deviations"
        else:
            overall = "conformant"

        summary = {
            "expected": len(expected),
            "present": len(self.components),
            "pass": classes.count("pass"),
            "qualified": classes.count("qualified"),
            "incomplete": classes.count("incomplete"),
            "fail": classes.count("fail"),
            "unsupported": classes.count("unsupported"),
        }
        return {
            "tool": "eigiib-aggregate",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "kind": "derived-conformance-report",
            "source_graph": str(self.graph_path),
            "results_dir": str(self.results_dir),
            "overall_result": overall,
            "summary": summary,
            "components": self.components,
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--results-dir", default=".eigiib-results/components")
    ap.add_argument("--graph", default="conformance/extension-graph.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = Aggregator(Path(args.root), Path(args.results_dir), Path(args.graph)).run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["overall_result"] in {"conformant", "conformant-with-documented-deviations"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
