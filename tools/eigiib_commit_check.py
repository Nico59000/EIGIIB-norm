#!/usr/bin/env python3
"""Static EIGIIB-E12 checker for commit-time revalidation and bounded consumption/idempotency relations."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0"
BOUNDARY_KEYS = ("proposal_revision", "policy_revision", "context_revision")


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
        self.valid_stores: set[str] = set()
        self.valid_operations: set[str] = set()
        self.revalidated_attempts: set[str] = set()
        self.valid_consumptions: set[str] = set()
        self.valid_idempotency: set[str] = set()
        self.valid_commits: set[str] = set()
        self.commit_safe_count = 0
        self.replay_count = 0

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def has_error(self, loc: str) -> bool:
        return any(f.severity == "error" and f.path == loc for f in self.findings)

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
            self.add("error", f"{code}.MISSING", "referenced file is missing", str(rel))
            return None
        return p

    def load_json(self, rel: Path, code: str) -> dict[str, Any] | None:
        p = self.confined(rel, code, must_exist=True)
        if p is None:
            return None
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", f"{code}.PARSE", str(exc), str(rel))
            return None
        if not isinstance(obj, dict):
            self.add("error", f"{code}.TYPE", "JSON root must be an object", str(rel))
            return None
        return obj

    def map_items(self, obj: dict[str, Any], key: str, code: str) -> dict[str, dict[str, Any]]:
        items = obj.get(key, [])
        if not isinstance(items, list):
            self.add("error", f"{code}.TYPE", f"{key} must be an array", key)
            return {}
        out: dict[str, dict[str, Any]] = {}
        for i, item in enumerate(items):
            loc = f"{key}[{i}]"
            if not isinstance(item, dict):
                self.add("error", f"{code}.ITEM", "item must be an object", loc)
                continue
            ident = item.get("id")
            if not isinstance(ident, str) or not ident:
                self.add("error", f"{code}.ID", "item id must be non-empty string", loc)
                continue
            if ident in out:
                self.add("error", f"{code}.DUPLICATE", f"duplicate id: {ident}", loc)
                continue
            out[ident] = item
        return out

    @staticmethod
    def identity_valid(value: Any) -> bool:
        if not isinstance(value, dict) or set(value) != {"algorithm", "digest", "bytes"}:
            return False
        digest = value.get("digest")
        size = value.get("bytes")
        return (
            value.get("algorithm") == "sha256"
            and isinstance(digest, str)
            and len(digest) == 64
            and all(ch in "0123456789abcdef" for ch in digest)
            and isinstance(size, int)
            and not isinstance(size, bool)
            and size > 0
        )

    @staticmethod
    def boundary(value: Any) -> tuple[str, str, str] | None:
        if not isinstance(value, dict) or set(value) != set(BOUNDARY_KEYS):
            return None
        values = tuple(value.get(k) for k in BOUNDARY_KEYS)
        if any(not isinstance(v, str) or not v for v in values):
            return None
        return values  # type: ignore[return-value]

    @staticmethod
    def e10_boundary(decision: dict[str, Any]) -> tuple[Any, Any, Any]:
        return tuple(decision.get(k) for k in BOUNDARY_KEYS)

    def evidence_valid(self, evidence: Any, loc: str, code: str) -> bool:
        if not isinstance(evidence, list) or not evidence:
            self.add("error", code, "material evidence array is required", loc)
            return False
        ok = True
        for item in evidence:
            if isinstance(item, str):
                if not item:
                    self.add("error", code, "evidence id must be non-empty", loc)
                    ok = False
            elif isinstance(item, dict) and set(item) == {"path"} and isinstance(item.get("path"), str) and item["path"]:
                if self.confined(Path(item["path"]), code, must_exist=True) is None:
                    ok = False
            else:
                self.add("error", code, "evidence item must be non-empty id or confined path object", loc)
                ok = False
        return ok

    def store_usable(self, store_id: Any, loc: str) -> bool:
        if not isinstance(store_id, str):
            self.add("error", "E12.STORE.REF", "store reference must be string", loc)
            return False
        if store_id not in self.stores:
            self.add("error", "E12.STORE.REF", f"store does not resolve: {store_id}", loc)
            return False
        if store_id not in self.valid_stores:
            self.add("error", "E12.STORE.UNUSABLE", "store is not an evidence-backed active atomic premise", loc)
            return False
        return True

    def temporal_view(self, decision_id: str, expected_subject: str, expected_boundary: tuple[str, str, str], loc: str) -> tuple[str, int, int, str] | None:
        decision = self.e11_decisions.get(decision_id)
        if decision is None:
            self.add("error", "E12.TIME.DECISION_REF", f"E11 temporal decision does not resolve: {decision_id}", loc)
            return None
        if decision.get("subject") != expected_subject:
            self.add("error", "E12.TIME.SUBJECT", "E11 temporal decision subject differs from E10 decision", loc)
        if self.boundary(decision.get("e10_boundary")) != expected_boundary:
            self.add("error", "E12.TIME.BOUNDARY", "E11 temporal decision E10 boundary mismatch", loc)
        policy = self.e11_policies.get(decision.get("policy"))
        obs = self.e11_observations.get(decision.get("observation"))
        if policy is None or obs is None:
            self.add("error", "E12.TIME.REF", "E11 policy/observation does not resolve", loc)
            return None
        source = self.e11_sources.get(obs.get("source"))
        if source is None:
            self.add("error", "E12.TIME.SOURCE", "E11 observation source does not resolve", loc)
            return None
        domain = policy.get("domain")
        if source.get("domain") != domain or not isinstance(domain, str):
            self.add("error", "E12.TIME.DOMAIN", "E11 policy/source do not provide one common time domain", loc)
            return None
        tick = obs.get("tick")
        uncertainty = obs.get("uncertainty")
        if not isinstance(tick, int) or isinstance(tick, bool) or not isinstance(uncertainty, int) or isinstance(uncertainty, bool) or uncertainty < 0:
            self.add("error", "E12.TIME.OBSERVATION", "E11 observation tick/uncertainty are not usable integers", loc)
            return None
        return domain, tick, uncertainty, str(decision.get("state"))

    def check_stores(self) -> None:
        modes = {"atomic-compare-and-set", "transactional-unique-key", "external-serialized", "unknown"}
        statuses = {"active", "suspended", "unavailable", "unknown"}
        for sid, store in self.stores.items():
            loc = f"store:{sid}"
            if store.get("mode") not in modes:
                self.add("error", "E12.STORE.MODE", "invalid atomic store mode", loc)
            if store.get("status") not in statuses:
                self.add("error", "E12.STORE.STATUS", "invalid atomic store status", loc)
            if store.get("status") == "active" and store.get("mode") != "unknown":
                if self.evidence_valid(store.get("evidence"), loc, "E12.STORE.EVIDENCE") and not self.has_error(loc):
                    self.valid_stores.add(sid)

    def check_policies(self) -> None:
        allowed = {"valid", "grace-valid"}
        for pid, policy in self.policies.items():
            loc = f"policy:{pid}"
            for key in ("allowed_check_temporal_states", "allowed_commit_temporal_states"):
                value = policy.get(key)
                if not isinstance(value, list) or not value or len(value) != len(set(value)) or any(x not in allowed for x in value):
                    self.add("error", "E12.POLICY.TEMPORAL_STATES", f"{key} must be a non-empty unique valid/grace-valid set", loc)
            for key in ("require_consumption", "require_idempotency"):
                if not isinstance(policy.get(key), bool):
                    self.add("error", "E12.POLICY.FLAG", f"{key} must be boolean", loc)
            if not isinstance(policy.get("revision"), str) or not policy.get("revision"):
                self.add("error", "E12.POLICY.REVISION", "policy revision must be non-empty string", loc)

    def check_operations(self) -> None:
        for oid, operation in self.operations.items():
            loc = f"operation:{oid}"
            policy = self.policies.get(operation.get("policy"))
            if policy is None:
                self.add("error", "E12.OP.POLICY", "operation policy does not resolve", loc)
                continue
            e10 = self.e10_decisions.get(operation.get("e10_decision"))
            if e10 is None:
                self.add("error", "E12.OP.E10_REF", "E10 decision does not resolve", loc)
                continue
            if e10.get("state") != "authorized":
                self.add("error", "E12.OP.E10_STATE", "operation requires E10 authorized decision", loc)
            proposal = self.e10_proposals.get(e10.get("proposal"))
            if proposal is None:
                self.add("error", "E12.OP.PROPOSAL", "E10 proposal does not resolve", loc)
                continue
            for key in ("action", "scope", "target"):
                if operation.get(key) != proposal.get(key):
                    self.add("error", "E12.OP.BINDING", f"operation {key} differs from E10 proposal", loc)
            if not self.identity_valid(operation.get("operation_identity")):
                self.add("error", "E12.OP.IDENTITY", "operation_identity is invalid", loc)
            if not self.identity_valid(proposal.get("operation_identity")) or proposal.get("operation_identity") != operation.get("operation_identity"):
                self.add("error", "E12.OP.PROPOSAL_IDENTITY", "E10 proposal must carry the same operation_identity", loc)
            boundary = self.boundary(operation.get("e10_boundary"))
            if boundary is None:
                self.add("error", "E12.OP.BOUNDARY", "operation E10 boundary is invalid", loc)
                continue
            if boundary != self.e10_boundary(e10):
                self.add("error", "E12.OP.BOUNDARY", "operation E10 boundary differs from E10 decision revisions", loc)
            check_id = operation.get("check_temporal_decision")
            if not isinstance(check_id, str):
                self.add("error", "E12.OP.CHECK_TIME", "check_temporal_decision must be string", loc)
                continue
            view = self.temporal_view(check_id, operation.get("e10_decision"), boundary, loc)
            if view is not None and view[3] not in policy.get("allowed_check_temporal_states", []):
                self.add("error", "E12.OP.CHECK_STATE", "check-time E11 decision state not allowed by E12 policy", loc)
            if not self.has_error(loc):
                self.valid_operations.add(oid)

    def check_attempts(self) -> None:
        allowed_states = {"prepared", "committed", "reused", "aborted", "failed", "unavailable"}
        for aid, attempt in self.attempts.items():
            loc = f"attempt:{aid}"
            if attempt.get("state") not in allowed_states:
                self.add("error", "E12.ATTEMPT.STATE", "invalid attempt state", loc)
                continue
            operation = self.operations.get(attempt.get("operation"))
            if operation is None:
                self.add("error", "E12.ATTEMPT.OPERATION", "attempt operation does not resolve", loc)
                continue
            execution = self.e10_executions.get(attempt.get("e10_execution"))
            if execution is None:
                self.add("error", "E12.ATTEMPT.EXECUTION", "E10 execution does not resolve", loc)
            elif execution.get("decision") != operation.get("e10_decision"):
                self.add("error", "E12.ATTEMPT.EXECUTION_BINDING", "E10 execution belongs to another decision", loc)
            if attempt.get("state") not in {"committed", "reused"}:
                continue
            if attempt.get("operation") not in self.valid_operations:
                self.add("error", "E12.ATTEMPT.OPERATION_INVALID", "positive attempt requires valid operation binding", loc)
                continue
            if execution is None or execution.get("state") not in {"attempted", "succeeded"}:
                self.add("error", "E12.ATTEMPT.EXECUTION_STATE", "committed/reused attempt requires attempted or succeeded E10 execution", loc)
            policy = self.policies[operation["policy"]]
            boundary = self.boundary(operation.get("e10_boundary"))
            assert boundary is not None
            check_id = operation.get("check_temporal_decision")
            commit_id = attempt.get("commit_temporal_decision")
            if not isinstance(commit_id, str) or commit_id == check_id:
                self.add("error", "E12.REVALIDATION.DISTINCT", "commit-time E11 decision must be distinct from check-time decision", loc)
                continue
            check_view = self.temporal_view(check_id, operation.get("e10_decision"), boundary, loc)
            commit_view = self.temporal_view(commit_id, operation.get("e10_decision"), boundary, loc)
            if check_view is None or commit_view is None:
                continue
            if commit_view[3] not in policy.get("allowed_commit_temporal_states", []):
                self.add("error", "E12.REVALIDATION.STATE", "commit-time E11 decision state not allowed by E12 policy", loc)
            if check_view[0] != commit_view[0]:
                self.add("error", "E12.REVALIDATION.DOMAIN", "check and commit observations use different time domains", loc)
            elif commit_view[1] - commit_view[2] < check_view[1] + check_view[2]:
                self.add("error", "E12.REVALIDATION.ORDER", "commit-time uncertainty interval is not definitely after check-time interval", loc)
            if not self.has_error(loc):
                self.revalidated_attempts.add(aid)

    def check_consumptions(self) -> None:
        states = {"reserved", "consumed", "released", "contested", "unavailable"}
        seen_keys: dict[tuple[str, str, str], str] = {}
        for cid, consumption in self.consumptions.items():
            loc = f"consumption:{cid}"
            state = consumption.get("state")
            if state not in states:
                self.add("error", "E12.CONSUMPTION.STATE", "invalid consumption state", loc)
            key = (str(consumption.get("store")), str(consumption.get("namespace")), str(consumption.get("token")))
            if key in seen_keys:
                self.add("error", "E12.CONSUMPTION.DUPLICATE_KEY", f"one-shot key already owned by {seen_keys[key]}", loc)
            else:
                seen_keys[key] = cid
            operation = self.operations.get(consumption.get("operation"))
            attempt = self.attempts.get(consumption.get("attempt"))
            if operation is None or attempt is None:
                self.add("error", "E12.CONSUMPTION.REF", "operation/attempt does not resolve", loc)
                continue
            if attempt.get("operation") != consumption.get("operation"):
                self.add("error", "E12.CONSUMPTION.OPERATION", "consumption attempt belongs to another operation", loc)
            if state == "consumed":
                if attempt.get("consumption") != cid:
                    self.add("error", "E12.CONSUMPTION.ATTEMPT_BINDING", "consumed record is not selected by its attempt", loc)
                self.store_usable(consumption.get("store"), loc)
                self.evidence_valid(consumption.get("evidence"), loc, "E12.CONSUMPTION.EVIDENCE")
                if not self.has_error(loc):
                    self.valid_consumptions.add(cid)

    def check_idempotency(self) -> None:
        states = {"open", "committed", "retired", "contested", "unavailable"}
        seen_keys: dict[tuple[str, str, str], str] = {}
        for iid, record in self.idempotency.items():
            loc = f"idempotency:{iid}"
            state = record.get("state")
            if state not in states:
                self.add("error", "E12.IDEMPOTENCY.STATE", "invalid idempotency state", loc)
            key = (str(record.get("store")), str(record.get("namespace")), str(record.get("key")))
            if key in seen_keys:
                self.add("error", "E12.IDEMPOTENCY.DUPLICATE_KEY", f"idempotency key already owned by {seen_keys[key]}", loc)
            else:
                seen_keys[key] = iid
            if record.get("operation") not in self.operations:
                self.add("error", "E12.IDEMPOTENCY.OPERATION", "idempotency operation does not resolve", loc)
            if state == "committed":
                self.store_usable(record.get("store"), loc)
                self.evidence_valid(record.get("evidence"), loc, "E12.IDEMPOTENCY.EVIDENCE")
                commit = self.commits.get(record.get("canonical_commit"))
                if commit is None:
                    self.add("error", "E12.IDEMPOTENCY.COMMIT", "canonical commit does not resolve", loc)
                else:
                    if commit.get("state") != "committed" or commit.get("operation") != record.get("operation") or commit.get("idempotency_record") != iid:
                        self.add("error", "E12.IDEMPOTENCY.COMMIT_BINDING", "canonical commit does not bind this idempotency record/operation", loc)
                if not self.has_error(loc):
                    self.valid_idempotency.add(iid)

    def check_commits(self) -> None:
        states = {"committed", "compensated", "disputed", "unavailable"}
        historical: dict[str, list[str]] = {}
        for cid, commit in self.commits.items():
            if commit.get("state") in {"committed", "compensated"}:
                historical.setdefault(str(commit.get("operation")), []).append(cid)
        for operation, ids in historical.items():
            if len(ids) > 1:
                self.add("error", "E12.COMMIT.MULTIPLE", f"operation has multiple committed/compensated commit records: {ids}", f"operation:{operation}")

        for cid, commit in self.commits.items():
            loc = f"commit:{cid}"
            state = commit.get("state")
            if state not in states:
                self.add("error", "E12.COMMIT.STATE", "invalid commit state", loc)
            operation = self.operations.get(commit.get("operation"))
            attempt = self.attempts.get(commit.get("attempt"))
            if operation is None or attempt is None:
                self.add("error", "E12.COMMIT.REF", "operation/attempt does not resolve", loc)
                continue
            if attempt.get("operation") != commit.get("operation"):
                self.add("error", "E12.COMMIT.OPERATION", "commit attempt belongs to another operation", loc)
            if state not in {"committed", "compensated"}:
                continue
            self.evidence_valid(commit.get("evidence"), loc, "E12.COMMIT.EVIDENCE")
            if state == "compensated":
                continue
            if attempt.get("state") != "committed" or commit.get("attempt") not in self.revalidated_attempts:
                self.add("error", "E12.COMMIT.ATTEMPT", "commit requires revalidated committed attempt", loc)
            policy = self.policies.get(operation.get("policy"))
            if policy is None:
                self.add("error", "E12.COMMIT.POLICY", "operation policy does not resolve", loc)
                continue
            if policy.get("require_consumption"):
                ref = commit.get("consumption")
                if ref != attempt.get("consumption") or ref not in self.valid_consumptions:
                    self.add("error", "E12.COMMIT.CONSUMPTION", "commit lacks the attempt's valid consumed one-shot record", loc)
            elif commit.get("consumption") is not None:
                ref = commit.get("consumption")
                record = self.consumptions.get(ref)
                if record is None or record.get("operation") != commit.get("operation") or record.get("attempt") != commit.get("attempt"):
                    self.add("error", "E12.COMMIT.CONSUMPTION_REF", "optional consumption reference is incoherent", loc)
            if policy.get("require_idempotency"):
                ref = commit.get("idempotency_record")
                if ref != attempt.get("idempotency_record") or ref not in self.valid_idempotency:
                    self.add("error", "E12.COMMIT.IDEMPOTENCY", "commit lacks the attempt's valid committed idempotency record", loc)
                else:
                    record = self.idempotency[ref]
                    if record.get("canonical_commit") != cid:
                        self.add("error", "E12.COMMIT.CANONICAL", "commit is not the idempotency record's canonical commit", loc)
            elif commit.get("idempotency_record") is not None:
                ref = commit.get("idempotency_record")
                record = self.idempotency.get(ref)
                if record is None or record.get("operation") != commit.get("operation"):
                    self.add("error", "E12.COMMIT.IDEMPOTENCY_REF", "optional idempotency reference is incoherent", loc)
            if not self.has_error(loc):
                self.valid_commits.add(cid)

    def check_decisions(self) -> None:
        states = {"commit-safe", "idempotent-replay", "held", "rejected", "indeterminate", "unavailable"}
        for did, decision in self.decisions.items():
            loc = f"decision:{did}"
            state = decision.get("state")
            if state not in states:
                self.add("error", "E12.DECISION.STATE", "invalid E12 decision state", loc)
                continue
            operation = self.operations.get(decision.get("operation"))
            attempt = self.attempts.get(decision.get("attempt"))
            policy = self.policies.get(decision.get("policy"))
            if operation is None or attempt is None or policy is None:
                self.add("error", "E12.DECISION.REF", "decision operation/attempt/policy does not resolve", loc)
                continue
            if operation.get("policy") != decision.get("policy") or attempt.get("operation") != decision.get("operation"):
                self.add("error", "E12.DECISION.BOUNDARY", "decision crosses operation/attempt/policy boundary", loc)
            if state not in {"commit-safe", "idempotent-replay"}:
                if decision.get("commit") is not None and decision.get("commit") not in self.commits:
                    self.add("error", "E12.DECISION.COMMIT_REF", "optional decision commit does not resolve", loc)
                continue
            if decision.get("operation") not in self.valid_operations or decision.get("attempt") not in self.revalidated_attempts:
                self.add("error", "E12.DECISION.REVALIDATION", "positive decision requires valid operation and commit-time revalidation", loc)
                continue
            if state == "commit-safe":
                commit_id = decision.get("commit")
                if attempt.get("state") != "committed" or commit_id not in self.valid_commits:
                    self.add("error", "E12.DECISION.COMMIT_SAFE", "commit-safe requires valid committed record and committed attempt", loc)
                else:
                    commit = self.commits[commit_id]
                    if commit.get("operation") != decision.get("operation") or commit.get("attempt") != decision.get("attempt"):
                        self.add("error", "E12.DECISION.COMMIT_BINDING", "decision commit belongs to another operation/attempt", loc)
                if not self.has_error(loc):
                    self.commit_safe_count += 1
            else:
                if not policy.get("require_idempotency") or attempt.get("state") != "reused":
                    self.add("error", "E12.DECISION.REPLAY_POLICY", "idempotent-replay requires idempotency policy and reused attempt", loc)
                    continue
                iid = attempt.get("idempotency_record")
                record = self.idempotency.get(iid)
                if iid not in self.valid_idempotency or record is None:
                    self.add("error", "E12.DECISION.REPLAY_IDEMPOTENCY", "reused attempt lacks valid committed idempotency record", loc)
                    continue
                canonical = record.get("canonical_commit")
                commit = self.commits.get(canonical)
                if canonical not in self.valid_commits or commit is None or decision.get("commit") != canonical:
                    self.add("error", "E12.DECISION.REPLAY_COMMIT", "idempotent replay must return the valid canonical commit", loc)
                elif commit.get("attempt") == decision.get("attempt"):
                    self.add("error", "E12.DECISION.REPLAY_ATTEMPT", "idempotent replay must reuse a commit from a different original attempt", loc)
                if attempt.get("consumption") is not None:
                    self.add("error", "E12.DECISION.REPLAY_CONSUMPTION", "reused attempt must not perform a new consumption", loc)
                if any(c.get("attempt") == decision.get("attempt") and c.get("state") in {"committed", "compensated"} for c in self.commits.values()):
                    self.add("error", "E12.DECISION.REPLAY_NEW_COMMIT", "reused attempt must not create a new commit record", loc)
                if not self.has_error(loc):
                    self.replay_count += 1

    def run(self) -> dict[str, Any]:
        obj = self.load_json(self.registry_path, "E12.REGISTRY") or {}
        automation = self.load_json(self.automation_path, "E12.E10") or {}
        temporal = self.load_json(self.temporal_path, "E12.E11") or {}
        if obj.get("standard") not in {None, STANDARD}:
            self.add("error", "E12.STANDARD", f"standard must be {STANDARD}", str(self.registry_path))

        self.stores = self.map_items(obj, "atomic_stores", "E12.STORE")
        self.policies = self.map_items(obj, "policies", "E12.POLICY")
        self.operations = self.map_items(obj, "operations", "E12.OP")
        self.idempotency = self.map_items(obj, "idempotency_records", "E12.IDEMPOTENCY")
        self.attempts = self.map_items(obj, "attempts", "E12.ATTEMPT")
        self.consumptions = self.map_items(obj, "consumptions", "E12.CONSUMPTION")
        self.commits = self.map_items(obj, "commits", "E12.COMMIT")
        self.decisions = self.map_items(obj, "decisions", "E12.DECISION")

        self.e10_decisions = self.map_items(automation, "decisions", "E12.UPSTREAM.E10_DECISION")
        self.e10_proposals = self.map_items(automation, "proposals", "E12.UPSTREAM.E10_PROPOSAL")
        self.e10_executions = self.map_items(automation, "executions", "E12.UPSTREAM.E10_EXECUTION")
        self.e11_decisions = self.map_items(temporal, "temporal_decisions", "E12.UPSTREAM.E11_DECISION")
        self.e11_policies = self.map_items(temporal, "policies", "E12.UPSTREAM.E11_POLICY")
        self.e11_observations = self.map_items(temporal, "observations", "E12.UPSTREAM.E11_OBSERVATION")
        self.e11_sources = self.map_items(temporal, "time_sources", "E12.UPSTREAM.E11_SOURCE")

        self.check_stores()
        self.check_policies()
        self.check_operations()
        self.check_attempts()
        self.check_consumptions()
        self.check_idempotency()
        self.check_commits()
        self.check_decisions()

        failed = any(f.severity == "error" for f in self.findings)
        def cap(count: int) -> str:
            return "not-evaluated" if failed or count == 0 else "verified"

        return {
            "tool": "eigiib-commit-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if failed else "conformant",
            "operation_binding_result": cap(len(self.valid_operations)),
            "commit_revalidation_result": cap(len(self.revalidated_attempts)),
            "consumption_binding_result": cap(len(self.valid_consumptions)),
            "idempotency_binding_result": cap(len(self.valid_idempotency)),
            "commit_safety_result": cap(self.commit_safe_count),
            "idempotent_replay_result": cap(self.replay_count),
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
    return 1 if result["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
