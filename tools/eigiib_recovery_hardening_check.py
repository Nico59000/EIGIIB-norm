#!/usr/bin/env python3
"""EIGIIB-E7 hardening overlay for incident-bound recovery semantics.

This checker is supplementary to eigiib_recovery_check.py. It does not execute
remediation, perform network access, or duplicate E4/E5/E6 cryptography. It
closes mechanically decidable gaps around incident boundaries, rollback
continuity, lower-layer bindings, reopening provenance, and capability labels.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.2.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0"


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Checker:
    def __init__(self, root: Path, registry: Path, trust: Path | None = None,
                 transparency: Path | None = None, gossip: Path | None = None):
        self.root = root.resolve()
        self.registry = registry
        self.trust = trust
        self.transparency = transparency
        self.gossip = gossip
        self.findings: list[Finding] = []
        self.obj: dict[str, Any] = {}
        self.incidents: dict[str, dict[str, Any]] = {}
        self.states: dict[str, dict[str, Any]] = {}
        self.evidence: dict[str, dict[str, Any]] = {}
        self.actions: dict[str, dict[str, Any]] = {}
        self.transitions: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.e4: set[str] = set()
        self.e5: set[str] = set()
        self.e6: set[str] = set()
        self.verified_transitions = 0

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def error_at(self, path: str) -> bool:
        return any(f.severity == "error" and f.path == path for f in self.findings)

    def safe(self, rel: Path) -> Path | None:
        if rel.is_absolute() or ".." in rel.parts:
            self.add("error", "E7H.PATH.ESCAPE", "path escapes repository", str(rel))
            return None
        p = (self.root / rel).resolve(strict=False)
        try:
            p.relative_to(self.root)
        except ValueError:
            self.add("error", "E7H.PATH.ESCAPE", "resolved path escapes repository", str(rel))
            return None
        if not p.is_file():
            self.add("error", "E7H.PATH.MISSING", "file does not exist", str(rel))
            return None
        return p

    def load_json(self, rel: Path | None, required: bool = False) -> dict[str, Any] | None:
        if rel is None:
            return None
        p = self.safe(rel)
        if p is None:
            if not required:
                self.findings = [f for f in self.findings if not (f.path == str(rel) and f.code == "E7H.PATH.MISSING")]
            return None
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.add("error", "E7H.JSON", f"cannot parse JSON: {exc}", str(rel))
            return None
        return obj if isinstance(obj, dict) else None

    @staticmethod
    def index(items: Any) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        if not isinstance(items, list):
            return out
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                out[item["id"]] = item
        return out

    def load(self) -> bool:
        obj = self.load_json(self.registry, required=True)
        if obj is None:
            return False
        self.obj = obj
        if obj.get("standard") != STANDARD:
            self.add("error", "E7H.STANDARD", "unsupported E7 standard identifier", str(self.registry))
        self.incidents = self.index(obj.get("incidents"))
        self.states = self.index(obj.get("trust_states"))
        self.evidence = self.index(obj.get("evidence"))
        self.actions = self.index(obj.get("actions"))
        self.transitions = self.index(obj.get("transitions"))
        self.decisions = self.index(obj.get("decisions"))

        t = self.load_json(self.trust)
        if t:
            self.e4 = {d["id"] for d in t.get("decisions", []) if isinstance(d, dict) and d.get("state") == "authenticated" and isinstance(d.get("id"), str)}
        t = self.load_json(self.transparency)
        if t:
            self.e5 = {d["id"] for d in t.get("trust_history_decisions", []) if isinstance(d, dict) and d.get("state") == "bound" and isinstance(d.get("id"), str)}
        g = self.load_json(self.gossip)
        if g:
            for key in ("fork_evidence", "accountability_decisions"):
                self.e6.update(i["id"] for i in g.get(key, []) if isinstance(i, dict) and isinstance(i.get("id"), str))
        return True

    def check_evidence(self) -> None:
        for eid, ev in self.evidence.items():
            loc = f"evidence:{eid}"
            if ev.get("e4_decision") is not None and ev.get("e4_decision") not in self.e4:
                self.add("error", "E7H.EVIDENCE.E4", "referenced authenticated E4 decision is absent", loc)
            if ev.get("e5_decision") is not None and ev.get("e5_decision") not in self.e5:
                self.add("error", "E7H.EVIDENCE.E5", "referenced bound E5 decision is absent", loc)
            if ev.get("e6_evidence") is not None and ev.get("e6_evidence") not in self.e6:
                self.add("error", "E7H.EVIDENCE.E6", "referenced E6 evidence is absent", loc)

    def check_plans(self) -> None:
        for plan in self.obj.get("plans", []):
            if not isinstance(plan, dict) or not isinstance(plan.get("id"), str):
                continue
            loc = f"plan:{plan['id']}"
            incident = plan.get("incident")
            for ref in plan.get("actions", []) if isinstance(plan.get("actions"), list) else []:
                action = self.actions.get(ref)
                if action is not None and action.get("incident") != incident:
                    self.add("error", "E7H.PLAN.ACTION_INCIDENT", f"plan action belongs to another incident: {ref}", loc)

    def check_transitions(self) -> None:
        allowed = {"proposed", "verified", "rejected", "superseded"}
        for tid, tr in self.transitions.items():
            loc = f"transition:{tid}"
            incident = tr.get("incident")
            if incident not in self.incidents:
                self.add("error", "E7H.TRANSITION.INCIDENT", "transition requires resolvable incident", loc)
            status = tr.get("status")
            if status not in allowed:
                self.add("error", "E7H.TRANSITION.STATUS", "invalid transition status", loc)
            for ref in tr.get("actions", []) if isinstance(tr.get("actions"), list) else []:
                action = self.actions.get(ref)
                if action is not None and action.get("incident") != incident:
                    self.add("error", "E7H.TRANSITION.ACTION_INCIDENT", f"transition action belongs to another incident: {ref}", loc)
                if status == "verified" and action is not None and action.get("status") != "completed":
                    self.add("error", "E7H.TRANSITION.ACTION_STATUS", f"verified transition action not completed: {ref}", loc)
            if status == "verified":
                if tr.get("require_e4_authenticated") and tr.get("e4_decision") not in self.e4:
                    self.add("error", "E7H.TRANSITION.E4", "required E4 decision is absent", loc)
                if tr.get("require_e5_history_bound") and tr.get("e5_decision") not in self.e5:
                    self.add("error", "E7H.TRANSITION.E5", "required E5 decision is absent", loc)
                if tr.get("require_e6_evidence") and tr.get("e6_evidence") not in self.e6:
                    self.add("error", "E7H.TRANSITION.E6", "required E6 evidence is absent", loc)
                if not self.error_at(loc):
                    self.verified_transitions += 1

    def check_rollbacks(self) -> None:
        for rb in self.obj.get("rollback_records", []):
            if not isinstance(rb, dict) or not isinstance(rb.get("id"), str):
                continue
            loc = f"rollback:{rb['id']}"
            incident = rb.get("incident")
            if not isinstance(rb.get("reason"), str) or not rb.get("reason", "").strip():
                self.add("error", "E7H.ROLLBACK.REASON", "rollback requires non-empty reason", loc)
            sup = self.transitions.get(rb.get("superseded_transition"))
            if sup is not None and sup.get("incident") != incident:
                self.add("error", "E7H.ROLLBACK.TRANSITION_INCIDENT", "superseded transition belongs to another incident", loc)
            for ref in rb.get("compensating_actions", []) if isinstance(rb.get("compensating_actions"), list) else []:
                action = self.actions.get(ref)
                if action is not None and action.get("incident") != incident:
                    self.add("error", "E7H.ROLLBACK.ACTION_INCIDENT", f"compensating action belongs to another incident: {ref}", loc)
            rep = self.transitions.get(rb.get("replacement_transition")) if rb.get("replacement_transition") is not None else None
            if rb.get("replacement_transition") is not None and rep is None:
                self.add("error", "E7H.ROLLBACK.REPLACEMENT_REF", "replacement transition is unresolved", loc)
            if rep is not None:
                if rep.get("incident") != incident:
                    self.add("error", "E7H.ROLLBACK.REPLACEMENT_INCIDENT", "replacement transition belongs to another incident", loc)
                if sup is not None:
                    s0 = self.states.get(sup.get("to_state")); s1 = self.states.get(rep.get("to_state"))
                    if s0 and s1 and isinstance(s0.get("epoch"), int) and isinstance(s1.get("epoch"), int) and s1["epoch"] <= s0["epoch"]:
                        self.add("error", "E7H.ROLLBACK.REPLACEMENT_EPOCH", "replacement transition must end after superseded destination epoch", loc)

    def check_decisions(self) -> None:
        for did, d in self.decisions.items():
            loc = f"decision:{did}"
            incident = d.get("incident")
            for ref in d.get("actions", []) if isinstance(d.get("actions"), list) else []:
                action = self.actions.get(ref)
                if action is not None and action.get("incident") != incident:
                    self.add("error", "E7H.DECISION.ACTION_INCIDENT", f"decision action belongs to another incident: {ref}", loc)
            if d.get("transition") is not None:
                tr = self.transitions.get(d.get("transition"))
                if tr is not None and tr.get("incident") != incident:
                    self.add("error", "E7H.DECISION.TRANSITION_INCIDENT", "decision transition belongs to another incident", loc)
            if d.get("state") == "reopened":
                inc = self.incidents.get(incident)
                if inc is not None and inc.get("state") != "reopened":
                    self.add("error", "E7H.DECISION.REOPEN_STATE", "reopened decision requires reopened incident state", loc)
                prior = d.get("prior_closure")
                if prior is None:
                    self.add("warning", "E7H.DECISION.REOPEN_PRIOR", "reopen decision should preserve prior closure", loc)
                else:
                    pd = self.decisions.get(prior)
                    if pd is None or pd.get("state") != "closed" or pd.get("incident") != incident:
                        self.add("error", "E7H.DECISION.REOPEN_PRIOR", "prior closure is invalid for this incident", loc)
                refs = d.get("evidence", [])
                if not isinstance(refs, list) or not refs:
                    self.add("warning", "E7H.DECISION.REOPEN_EVIDENCE", "reopen decision should preserve new evidence", loc)
                elif any(ref not in self.evidence for ref in refs):
                    self.add("error", "E7H.DECISION.REOPEN_EVIDENCE_REF", "reopen evidence reference is unresolved", loc)

    def run(self) -> dict[str, Any]:
        if self.load():
            self.check_evidence(); self.check_plans(); self.check_transitions(); self.check_rollbacks(); self.check_decisions()
        fs = sorted(self.findings, key=lambda f: (f.severity, f.code, f.path, f.message))
        errors = sum(f.severity == "error" for f in fs)
        return {
            "tool": "eigiib-recovery-hardening-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "hardening_result": "non-conformant" if errors else "conformant",
            "verified_transition_count": self.verified_transitions,
            "findings": [asdict(f) for f in fs],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--registry", default="conformance/recovery.json")
    ap.add_argument("--trust", default="conformance/trust.json")
    ap.add_argument("--transparency", default="conformance/transparency.json")
    ap.add_argument("--gossip", default="conformance/gossip.json")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = Checker(Path(a.root), Path(a.registry), Path(a.trust), Path(a.transparency), Path(a.gossip)).run()
    print(json.dumps(r, indent=2, sort_keys=True) if a.json else r["hardening_result"])
    return 1 if r["hardening_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
