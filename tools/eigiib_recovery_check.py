#!/usr/bin/env python3
"""EIGIIB-E7 recovery, remediation, and trust-state continuity checker.

Static by design: no network access, no remediation execution, no cryptographic
verification, and no mutation of trust state. E4/E5/E6 registries are consumed
only as typed external facts when explicitly supplied.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0"
MAX_OBJECTS = 100_000

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

class Checker:
    def __init__(self, root: Path, registry: Path, trust: Path | None = None, transparency: Path | None = None, gossip: Path | None = None):
        self.root = root.resolve()
        self.registry_path = registry
        self.trust_path = trust
        self.transparency_path = transparency
        self.gossip_path = gossip
        self.findings: list[Finding] = []
        self.obj: dict[str, Any] = {}
        self.incidents: dict[str, dict[str, Any]] = {}
        self.states: dict[str, dict[str, Any]] = {}
        self.actions: dict[str, dict[str, Any]] = {}
        self.plans: dict[str, dict[str, Any]] = {}
        self.transitions: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.evidence: dict[str, dict[str, Any]] = {}
        self.e4_authenticated: set[str] = set()
        self.e5_history_bound: set[str] = set()
        self.e6_evidence: set[str] = set()
        self.containment_verified = 0
        self.transition_verified = 0
        self.continuity_verified = 0
        self.closure_verified = 0

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def safe_path(self, raw: str, must_exist: bool = True) -> Path | None:
        if not isinstance(raw, str) or not raw:
            self.add("error", "E7.PATH.INVALID", "path must be non-empty", str(raw))
            return None
        p = Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error", "E7.PATH.ESCAPE", "path escapes repository", raw)
            return None
        candidate = (self.root / p).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("error", "E7.PATH.ESCAPE", "resolved path escapes repository", raw)
            return None
        if must_exist:
            if not candidate.exists() or not candidate.is_file():
                self.add("error", "E7.PATH.MISSING", "file does not exist", raw)
                return None
            try:
                candidate.resolve(strict=True).relative_to(self.root)
            except (OSError, ValueError):
                self.add("error", "E7.PATH.SYMLINK", "unsafe resolved path", raw)
                return None
        return candidate

    def load_json(self, rel: Path, code: str, required: bool = True) -> dict[str, Any] | None:
        p = (self.root / rel).resolve(strict=False)
        if not p.exists() and not required:
            return None
        safe = self.safe_path(str(rel))
        if safe is None:
            return None
        try:
            data = json.loads(safe.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.add("error", f"{code}.PARSE", f"cannot parse JSON: {exc}", str(rel))
            return None
        if not isinstance(data, dict):
            self.add("error", f"{code}.TYPE", "registry root must be object", str(rel))
            return None
        return data

    def load_external(self) -> None:
        if self.trust_path:
            t = self.load_json(self.trust_path, "E7.E4", required=False)
            if t:
                for d in t.get("decisions", []):
                    if isinstance(d, dict) and d.get("state") == "authenticated" and isinstance(d.get("id"), str):
                        self.e4_authenticated.add(d["id"])
        if self.transparency_path:
            t = self.load_json(self.transparency_path, "E7.E5", required=False)
            if t:
                for d in t.get("trust_history_decisions", []):
                    if isinstance(d, dict) and d.get("state") == "bound" and isinstance(d.get("id"), str):
                        self.e5_history_bound.add(d["id"])
        if self.gossip_path:
            g = self.load_json(self.gossip_path, "E7.E6", required=False)
            if g:
                for key in ("fork_evidence", "accountability_decisions"):
                    for item in g.get(key, []):
                        if isinstance(item, dict) and isinstance(item.get("id"), str):
                            self.e6_evidence.add(item["id"])

    def load(self) -> bool:
        data = self.load_json(self.registry_path, "E7.REGISTRY")
        if data is None:
            return False
        self.obj = data
        if data.get("standard") != STANDARD:
            self.add("error", "E7.STANDARD", "unsupported E7 standard identifier", str(self.registry_path))
        if not isinstance(data.get("revision"), str) or not data.get("revision"):
            self.add("error", "E7.REVISION", "revision must be non-empty string", str(self.registry_path))
        arrays = ["incidents", "trust_states", "evidence", "actions", "plans", "transitions", "rollback_records", "decisions"]
        total = 0
        for key in arrays:
            val = data.get(key)
            if not isinstance(val, list):
                self.add("error", "E7.COLLECTION", f"{key} must be an array", str(self.registry_path))
            else:
                total += len(val)
        if total > MAX_OBJECTS:
            self.add("error", "E7.RESOURCE", "object count exceeds checker limit")
        self.load_external()
        return True

    def map_items(self, key: str, code: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for i, item in enumerate(self.obj.get(key, [])):
            loc = f"{self.registry_path}#/{key}/{i}"
            if not isinstance(item, dict):
                self.add("error", f"{code}.TYPE", "item must be object", loc)
                continue
            iid = item.get("id")
            if not isinstance(iid, str) or not iid:
                self.add("error", f"{code}.ID", "item requires non-empty id", loc)
                continue
            if iid in out:
                self.add("error", f"{code}.DUPLICATE", f"duplicate id: {iid}", loc)
            out[iid] = item
        return out

    def check_incidents_states_evidence(self) -> None:
        self.incidents = self.map_items("incidents", "E7.INCIDENT")
        self.states = self.map_items("trust_states", "E7.STATE")
        self.evidence = self.map_items("evidence", "E7.EVIDENCE")
        for iid, inc in self.incidents.items():
            if inc.get("state") not in {"detected", "contained", "recovering", "continuity-established", "closed", "reopened"}:
                self.add("error", "E7.INCIDENT.STATE", "invalid incident state", f"incident:{iid}")
            if not isinstance(inc.get("sources", []), list):
                self.add("error", "E7.INCIDENT.SOURCES", "sources must be array", f"incident:{iid}")
        epochs: dict[int, str] = {}
        for sid, st in self.states.items():
            epoch = st.get("epoch")
            if not isinstance(epoch, int) or epoch < 0:
                self.add("error", "E7.STATE.EPOCH", "epoch must be non-negative integer", f"state:{sid}")
            elif epoch in epochs:
                self.add("error", "E7.STATE.EPOCH_DUP", f"epoch duplicates {epochs[epoch]}", f"state:{sid}")
            else:
                epochs[epoch] = sid
            if st.get("status") not in {"candidate", "active", "retired", "superseded", "quarantined"}:
                self.add("error", "E7.STATE.STATUS", "invalid trust-state status", f"state:{sid}")
        for eid, ev in self.evidence.items():
            if ev.get("path") is not None:
                self.safe_path(ev.get("path"))
            if ev.get("kind") not in {"observation", "test", "replay", "attestation", "checkpoint", "manual-review", "local"}:
                self.add("error", "E7.EVIDENCE.KIND", "invalid evidence kind", f"evidence:{eid}")

    def check_actions_plans(self) -> None:
        self.actions = self.map_items("actions", "E7.ACTION")
        self.plans = self.map_items("plans", "E7.PLAN")
        allowed = {"freeze", "quarantine", "revoke", "rotate", "replace-root", "replace-policy", "rebuild", "replay", "restore", "publish", "re-witness", "fork-resolution", "resume", "rollback", "verify"}
        for aid, action in self.actions.items():
            loc = f"action:{aid}"
            if action.get("kind") not in allowed:
                self.add("error", "E7.ACTION.KIND", "invalid recovery action kind", loc)
            if action.get("incident") not in self.incidents:
                self.add("error", "E7.ACTION.INCIDENT", "unresolved incident", loc)
            if action.get("status") not in {"planned", "in-progress", "completed", "failed", "reverted", "skipped"}:
                self.add("error", "E7.ACTION.STATUS", "invalid action status", loc)
            evs = action.get("evidence", [])
            if not isinstance(evs, list):
                self.add("error", "E7.ACTION.EVIDENCE", "evidence must be array", loc)
                evs = []
            for ref in evs:
                if ref not in self.evidence:
                    self.add("error", "E7.ACTION.EVIDENCE_REF", f"unresolved evidence: {ref}", loc)
            if action.get("status") == "completed" and not evs:
                self.add("error", "E7.ACTION.NO_EVIDENCE", "completed action requires evidence", loc)
        for pid, plan in self.plans.items():
            loc = f"plan:{pid}"
            if plan.get("incident") not in self.incidents:
                self.add("error", "E7.PLAN.INCIDENT", "unresolved incident", loc)
            refs = plan.get("actions")
            if not isinstance(refs, list):
                self.add("error", "E7.PLAN.ACTIONS", "actions must be array", loc)
                continue
            for ref in refs:
                if ref not in self.actions:
                    self.add("error", "E7.PLAN.ACTION_REF", f"unresolved action: {ref}", loc)
            deps = plan.get("dependencies", [])
            graph: dict[str, set[str]] = {r: set() for r in refs if r in self.actions}
            if not isinstance(deps, list):
                self.add("error", "E7.PLAN.DEPENDENCIES", "dependencies must be array", loc)
                continue
            for d in deps:
                if not isinstance(d, dict) or d.get("before") not in graph or d.get("after") not in graph:
                    self.add("error", "E7.PLAN.DEPENDENCY_REF", "invalid dependency reference", loc)
                    continue
                graph[d["before"]].add(d["after"])
            visiting: set[str] = set()
            visited: set[str] = set()
            def dfs(n: str) -> bool:
                if n in visiting:
                    return True
                if n in visited:
                    return False
                visiting.add(n)
                if any(dfs(m) for m in graph.get(n, ())):
                    return True
                visiting.remove(n)
                visited.add(n)
                return False
            if any(dfs(n) for n in list(graph)):
                self.add("error", "E7.PLAN.CYCLE", "recovery action dependency graph contains cycle", loc)

    def check_transitions_rollbacks(self) -> None:
        self.transitions = self.map_items("transitions", "E7.TRANSITION")
        rollbacks = self.map_items("rollback_records", "E7.ROLLBACK")
        for tid, tr in self.transitions.items():
            loc = f"transition:{tid}"
            old = self.states.get(tr.get("from_state"))
            new = self.states.get(tr.get("to_state"))
            if old is None or new is None:
                self.add("error", "E7.TRANSITION.STATE_REF", "unresolved trust state", loc)
                continue
            if not isinstance(old.get("epoch"), int) or not isinstance(new.get("epoch"), int) or new.get("epoch") <= old.get("epoch"):
                self.add("error", "E7.TRANSITION.EPOCH", "recovery transition must advance trust-state epoch", loc)
            refs = tr.get("actions", [])
            if not isinstance(refs, list) or not refs:
                self.add("error", "E7.TRANSITION.ACTIONS", "transition requires actions", loc)
            else:
                for ref in refs:
                    act = self.actions.get(ref)
                    if act is None or act.get("status") != "completed":
                        self.add("error", "E7.TRANSITION.ACTION_STATUS", f"transition action not completed: {ref}", loc)
            if tr.get("status") == "verified":
                self.transition_verified += 1
        for rid, rb in rollbacks.items():
            loc = f"rollback:{rid}"
            if rb.get("incident") not in self.incidents:
                self.add("error", "E7.ROLLBACK.INCIDENT", "unresolved incident", loc)
            if rb.get("superseded_transition") not in self.transitions:
                self.add("error", "E7.ROLLBACK.TRANSITION", "unresolved superseded transition", loc)
            refs = rb.get("compensating_actions")
            if not isinstance(refs, list) or not refs:
                self.add("error", "E7.ROLLBACK.COMPENSATION", "rollback requires explicit compensating actions", loc)
            else:
                for ref in refs:
                    if ref not in self.actions:
                        self.add("error", "E7.ROLLBACK.ACTION_REF", f"unresolved compensating action: {ref}", loc)

    def check_decisions(self) -> None:
        self.decisions = self.map_items("decisions", "E7.DECISION")
        for did, d in self.decisions.items():
            loc = f"decision:{did}"
            inc = self.incidents.get(d.get("incident"))
            if inc is None:
                self.add("error", "E7.DECISION.INCIDENT", "unresolved incident", loc)
                continue
            state = d.get("state")
            if state not in {"contained", "transition-verified", "continuity-established", "closed", "reopened", "unavailable"}:
                self.add("error", "E7.DECISION.STATE", "invalid recovery decision state", loc)
                continue
            action_refs = d.get("actions", []) if isinstance(d.get("actions", []), list) else []
            actions = [self.actions.get(x) for x in action_refs]
            if any(a is None for a in actions):
                self.add("error", "E7.DECISION.ACTION_REF", "unresolved action in decision", loc)
            if state == "contained":
                if not actions or any(a.get("status") != "completed" or a.get("kind") not in {"freeze", "quarantine", "revoke"} for a in actions if a):
                    self.add("error", "E7.DECISION.CONTAINMENT", "contained decision requires completed containment action(s)", loc)
                else:
                    self.containment_verified += 1
                continue
            if state in {"transition-verified", "continuity-established", "closed"}:
                tr = self.transitions.get(d.get("transition"))
                if tr is None or tr.get("status") != "verified":
                    self.add("error", "E7.DECISION.TRANSITION", "decision requires verified transition", loc)
                    continue
                if state == "transition-verified":
                    continue
                post = self.states.get(tr.get("to_state"))
                if post is None or post.get("status") != "active":
                    self.add("error", "E7.DECISION.CONTINUITY_STATE", "continuity requires active post-recovery trust state", loc)
                    continue
                if d.get("require_e4_authenticated") and d.get("e4_decision") not in self.e4_authenticated:
                    self.add("error", "E7.DECISION.E4", "required E4 authentication decision is absent", loc)
                    continue
                if d.get("require_e5_history_bound") and d.get("e5_decision") not in self.e5_history_bound:
                    self.add("error", "E7.DECISION.E5", "required E5 history-binding decision is absent", loc)
                    continue
                self.continuity_verified += 1
                if state == "closed":
                    blockers = d.get("open_blockers", [])
                    if not isinstance(blockers, list) or blockers:
                        self.add("error", "E7.DECISION.BLOCKERS", "closed decision requires empty open_blockers", loc)
                        continue
                    if inc.get("state") != "closed":
                        self.add("error", "E7.DECISION.INCIDENT_STATE", "closed decision requires incident state closed", loc)
                        continue
                    self.closure_verified += 1

    def run(self) -> dict[str, Any]:
        if self.load():
            self.check_incidents_states_evidence()
            self.check_actions_plans()
            self.check_transitions_rollbacks()
            self.check_decisions()
        findings = sorted(self.findings, key=lambda x: (x.severity, x.code, x.path, x.message))
        errors = sum(f.severity == "error" for f in findings)
        return {
            "tool": "eigiib-recovery-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "revision": self.obj.get("revision", "unknown"),
            "structural_result": "non-conformant" if errors else "conformant",
            "containment_result": "verified" if self.containment_verified else "not-evaluated",
            "transition_result": "verified" if self.transition_verified else "not-evaluated",
            "continuity_result": "verified" if self.continuity_verified else "not-evaluated",
            "closure_result": "verified" if self.closure_verified else "not-evaluated",
            "findings": [asdict(f) for f in findings],
        }

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--registry", default="conformance/recovery.json")
    ap.add_argument("--trust", default="conformance/trust.json")
    ap.add_argument("--transparency", default="conformance/transparency.json")
    ap.add_argument("--gossip", default="conformance/gossip.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    checker = Checker(Path(args.root), Path(args.registry), Path(args.trust), Path(args.transparency), Path(args.gossip))
    report = checker.run()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["structural_result"])
        for f in report["findings"]:
            print(f"{f['severity']}: {f['code']}: {f['message']}")
    return 1 if report["structural_result"] == "non-conformant" else 0

if __name__ == "__main__":
    raise SystemExit(main())
