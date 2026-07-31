#!/usr/bin/env python3
"""EIGIIB-E10 additive decision-boundary hardening checker."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.2.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0"


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Checker:
    def __init__(self, root: Path, registry: Path):
        self.root = root.resolve()
        self.registry_path = registry
        self.findings: list[Finding] = []
        self.obj: dict[str, Any] = {}
        self.checked = 0

    def add(self, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding("error", code, path, message))

    def safe_path(self, raw: str) -> Path | None:
        if not isinstance(raw, str) or not raw:
            self.add("E10H.PATH.INVALID", "path must be non-empty", str(raw))
            return None
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("E10H.PATH.ESCAPE", "path escapes repository", raw)
            return None
        candidate = (self.root / p).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("E10H.PATH.ESCAPE", "resolved path escapes repository", raw)
            return None
        if not candidate.exists() or not candidate.is_file():
            self.add("E10H.PATH.MISSING", "file does not exist", raw)
            return None
        try:
            candidate.resolve(strict=True).relative_to(self.root)
        except (OSError, ValueError):
            self.add("E10H.PATH.SYMLINK", "unsafe resolved path", raw)
            return None
        return candidate

    @staticmethod
    def item_map(items: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(items, list):
            return {}
        return {
            x["id"]: x
            for x in items
            if isinstance(x, dict) and isinstance(x.get("id"), str) and x.get("id")
        }

    def load(self) -> bool:
        safe = self.safe_path(str(self.registry_path))
        if safe is None:
            return False
        try:
            data = json.loads(safe.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.add("E10H.REGISTRY.PARSE", f"cannot parse JSON: {exc}", str(self.registry_path))
            return False
        if not isinstance(data, dict):
            self.add("E10H.REGISTRY.TYPE", "registry root must be object", str(self.registry_path))
            return False
        self.obj = data
        if data.get("standard") != STANDARD:
            self.add("E10H.STANDARD", "unsupported E10 standard identifier", str(self.registry_path))
        return True

    def check(self) -> None:
        proposals = self.item_map(self.obj.get("proposals"))
        policies = self.item_map(self.obj.get("policies"))
        contexts = self.item_map(self.obj.get("contexts"))
        decisions = self.obj.get("decisions", [])
        if not isinstance(decisions, list):
            self.add("E10H.DECISIONS.TYPE", "decisions must be array", str(self.registry_path))
            return

        for i, decision in enumerate(decisions):
            loc = f"{self.registry_path}#/decisions/{i}"
            if not isinstance(decision, dict):
                self.add("E10H.DECISION.TYPE", "decision must be object", loc)
                continue
            proposal = proposals.get(decision.get("proposal"))
            policy = policies.get(decision.get("policy"))
            context = contexts.get(decision.get("context"))
            if proposal is None or policy is None or context is None:
                self.add("E10H.DECISION.REF", "decision proposal/policy/context must resolve", loc)
                continue
            self.checked += 1
            if proposal.get("policy") != decision.get("policy") or proposal.get("context") != decision.get("context"):
                self.add("E10H.DECISION.BOUNDARY", "decision boundary differs from proposal boundary", loc)
            if decision.get("proposal_revision") != proposal.get("revision"):
                self.add("E10H.DECISION.PROPOSAL_REV", "decision proposal revision mismatch", loc)
            if decision.get("policy_revision") != policy.get("revision"):
                self.add("E10H.DECISION.POLICY_REV", "decision policy revision mismatch", loc)
            if decision.get("context_revision") != context.get("revision"):
                self.add("E10H.DECISION.CONTEXT_REV", "decision context revision mismatch", loc)

    def run(self) -> dict[str, Any]:
        if self.load():
            self.check()
        findings = sorted(self.findings, key=lambda x: (x.severity, x.code, x.path, x.message))
        errors = len(findings)
        return {
            "tool": "eigiib-automation-hardening-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "revision": self.obj.get("revision", "unknown"),
            "structural_result": "non-conformant" if errors else "conformant",
            "decision_boundary_result": "verified" if not errors and self.checked else "not-evaluated",
            "findings": [asdict(f) for f in findings],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--registry", default="conformance/automation.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    report = Checker(Path(args.root), Path(args.registry)).run()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["structural_result"])
        for finding in report["findings"]:
            print(f"{finding['severity']}: {finding['code']}: {finding['message']}")
    return 1 if report["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
