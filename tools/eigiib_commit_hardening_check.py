#!/usr/bin/env python3
"""EIGIIB-E12 hardening 0.2: fresh use observation and atomic commit-domain continuity."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

TOOL_VERSION = "0.2.0"
STANDARD = "EIGIIB-E12-hardening-0.2"


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Checker:
    def __init__(self, root: Path, registry: Path, automation: Path, temporal: Path):
        self.root = root.resolve()
        self.registry_path = registry
        self.automation_path = automation
        self.temporal_path = temporal
        self.findings: list[Finding] = []
        self.fresh_observation_count = 0
        self.atomic_domain_count = 0
        self.replay_domain_count = 0
        self.base = None

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def has_error(self, loc: str) -> bool:
        return any(f.severity == "error" and f.path == loc for f in self.findings)

    def baseline(self):
        path = self.root / "tools/eigiib_commit_check.py"
        spec = importlib.util.spec_from_file_location("e12baseline", path)
        if spec is None or spec.loader is None:
            self.add("error", "E12H.BASELINE.LOAD", "cannot load baseline E12 checker", str(path))
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        checker = mod.Checker(self.root, self.registry_path, self.automation_path, self.temporal_path)
        result = checker.run()
        if result.get("structural_result") != "conformant":
            self.add("error", "E12H.BASELINE", "baseline E12 checker is non-conformant", str(self.registry_path))
            return checker
        return checker

    def check_fresh_observation(self, decision_id: str, operation: dict, attempt: dict, loc: str) -> None:
        check_dec = self.base.e11_decisions.get(operation.get("check_temporal_decision"))
        commit_dec = self.base.e11_decisions.get(attempt.get("commit_temporal_decision"))
        if check_dec is None or commit_dec is None:
            self.add("error", "E12H.REVALIDATION.DECISION_REF", "check/commit E11 decision does not resolve", loc)
            return
        check_obs = check_dec.get("observation")
        commit_obs = commit_dec.get("observation")
        if not isinstance(check_obs, str) or check_obs not in self.base.e11_observations:
            self.add("error", "E12H.REVALIDATION.OBSERVATION_REF", "check-time E11 observation does not resolve", loc)
        if not isinstance(commit_obs, str) or commit_obs not in self.base.e11_observations:
            self.add("error", "E12H.REVALIDATION.OBSERVATION_REF", "commit-time E11 observation does not resolve", loc)
        if check_obs == commit_obs:
            self.add("error", "E12H.REVALIDATION.OBSERVATION_REUSE", "commit-time revalidation reuses the check-time E11 observation", loc)
        if not self.has_error(loc):
            self.fresh_observation_count += 1

    def usable_commit_store(self, commit: dict, loc: str) -> str | None:
        sid = commit.get("atomic_store")
        if not isinstance(sid, str) or not sid:
            self.add("error", "E12H.COMMIT.STORE", "positive commit requires explicit atomic_store", loc)
            return None
        if sid not in self.base.valid_stores:
            self.add("error", "E12H.COMMIT.STORE_UNUSABLE", "commit atomic_store is not a baseline-valid active atomic premise", loc)
            return None
        return sid

    def check_commit_safe_domain(self, decision: dict, operation: dict, attempt: dict, policy: dict, loc: str) -> None:
        commit = self.base.commits.get(decision.get("commit"))
        if commit is None:
            self.add("error", "E12H.COMMIT.REF", "commit-safe decision commit does not resolve", loc)
            return
        sid = self.usable_commit_store(commit, loc)
        if sid is None:
            return
        if policy.get("require_consumption"):
            consumption = self.base.consumptions.get(commit.get("consumption"))
            if consumption is None or consumption.get("store") != sid:
                self.add("error", "E12H.COMMIT.CONSUMPTION_STORE", "one-shot consumption is outside the commit atomic_store", loc)
        if policy.get("require_idempotency"):
            idem = self.base.idempotency.get(commit.get("idempotency_record"))
            if idem is None or idem.get("store") != sid:
                self.add("error", "E12H.COMMIT.IDEMPOTENCY_STORE", "idempotency binding is outside the commit atomic_store", loc)
        if not self.has_error(loc):
            self.atomic_domain_count += 1

    def check_replay_domain(self, decision: dict, attempt: dict, loc: str) -> None:
        commit = self.base.commits.get(decision.get("commit"))
        idem = self.base.idempotency.get(attempt.get("idempotency_record"))
        if commit is None or idem is None:
            self.add("error", "E12H.REPLAY.REF", "idempotent replay commit/idempotency record does not resolve", loc)
            return
        sid = self.usable_commit_store(commit, loc)
        if sid is None:
            return
        if idem.get("store") != sid:
            self.add("error", "E12H.REPLAY.STORE", "idempotency record and canonical commit use different atomic stores", loc)
        if not self.has_error(loc):
            self.replay_domain_count += 1

    def check(self) -> None:
        for did, decision in self.base.decisions.items():
            state = decision.get("state")
            if state not in {"commit-safe", "idempotent-replay"}:
                continue
            loc = f"decision:{did}"
            operation = self.base.operations.get(decision.get("operation"))
            attempt = self.base.attempts.get(decision.get("attempt"))
            policy = self.base.policies.get(decision.get("policy"))
            if operation is None or attempt is None or policy is None:
                self.add("error", "E12H.DECISION.REF", "positive decision boundary does not resolve", loc)
                continue
            self.check_fresh_observation(did, operation, attempt, loc)
            if state == "commit-safe":
                self.check_commit_safe_domain(decision, operation, attempt, policy, loc)
            else:
                self.check_replay_domain(decision, attempt, loc)

    def run(self) -> dict:
        self.base = self.baseline()
        if self.base is not None and not any(f.code == "E12H.BASELINE" for f in self.findings):
            self.check()
        failed = any(f.severity == "error" for f in self.findings)

        def cap(n: int) -> str:
            return "not-evaluated" if failed or n == 0 else "verified"

        return {
            "tool": "eigiib_commit_hardening_check.py",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "hardening_result": "non-conformant" if failed else "conformant",
            "fresh_commit_observation_result": cap(self.fresh_observation_count),
            "atomic_commit_domain_result": cap(self.atomic_domain_count),
            "idempotent_replay_domain_result": cap(self.replay_domain_count),
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--registry", default="conformance/commit.json")
    ap.add_argument("--automation", default="conformance/automation.json")
    ap.add_argument("--temporal", default="conformance/temporal.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = Checker(Path(args.root), Path(args.registry), Path(args.automation), Path(args.temporal)).run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["hardening_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
