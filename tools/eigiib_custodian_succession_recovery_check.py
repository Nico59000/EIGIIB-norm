#!/usr/bin/env python3
"""Check E16-A4 custodian succession and anti-rollback recovery authorities."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E16-A4-1.0"
PROFILE_REVISION = "EIGIIB-E16-draft-1.0"
SOURCE_E16_A3_HEAD = "74cb64ebcb1b51b0a035e755be413dbd2a7e9e3e"
HISTORY_STANDARD = "EIGIIB-E16-A4-HISTORICAL-E16-A3-REPLAY-1.0"
MANIFEST_STANDARD = "EIGIIB-E16-A4-AUTHORITY-MANIFEST-1.0"
TRANSITION_STANDARD = "EIGIIB-E16-A4-TRANSITION-1.0"
FREEZE_STANDARD = "EIGIIB-E16-A4-FREEZE-1.0"

REGISTRY_PATH = "conformance/custodian-succession-recovery.json"
MANIFEST_PATH = "conformance/e16-a4-authority-manifest.json"
TRANSITION_PATH = "conformance/e16-a4-adoption-transition.json"
FREEZE_PATH = "conformance/e16-a4-authority-freeze.json"
UPSTREAM_REGISTRY_PATH = "conformance/retention-readback-restore.json"
UPSTREAM_FREEZE_PATH = "conformance/e16-a3-authority-freeze.json"

EXPECTED_AUTHORITIES = {
    "contract": "extensions/E16-A4-CUSTODIAN-SUCCESSION-REPLICA-MIGRATION-LOSS-QUARANTINE-ANTI-ROLLBACK-RECOVERY.md",
    "authority_manifest": MANIFEST_PATH,
    "registry": REGISTRY_PATH,
    "transition": TRANSITION_PATH,
    "authority_freeze": FREEZE_PATH,
    "human_mastery": "docs/E16-A4-HUMAN-MASTERY-GUIDE.md",
    "manual_review": "conformance/E16-A4-MANUAL-REVIEW.md",
    "registry_schema": "schemas/eigiib-e16-a4-custodian-succession-recovery.schema.json",
    "manifest_schema": "schemas/eigiib-e16-a4-authority-manifest.schema.json",
    "transition_schema": "schemas/eigiib-e16-a4-adoption-transition.schema.json",
    "freeze_schema": "schemas/eigiib-e16-a4-authority-freeze.schema.json",
    "checker": "tools/eigiib_custodian_succession_recovery_check.py",
    "historical_replay": "tools/eigiib_historical_e16_a3_replay.py",
    "tests": "tests/test_eigiib_custodian_succession_recovery.py",
    "expected_report": "tests/fixtures/e16-a4/expected-report.json",
    "workflow": ".github/workflows/e16-a4-custodian-succession-recovery.yml",
}
EXPECTED_REQUIRED = list(EXPECTED_AUTHORITIES)
EXPECTED_FREEZE_PATHS = set(EXPECTED_AUTHORITIES.values()) - {FREEZE_PATH}

GATE_ORDER = ("deny", "unavailable", "held", "permit")
POSITIVE_STATE = "successor-replica-recovered"
DECISION_STATES = (POSITIVE_STATE, "rejected", "held", "unavailable")
ARRAYS = (
    "succession_authorizations",
    "migration_plans",
    "migration_observations",
    "loss_reports",
    "quarantine_records",
    "recovery_replays",
    "recovery_decisions",
)


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def commitment_for(value: dict[str, Any]) -> str:
    clean = {key: val for key, val in value.items() if key != "commitment"}
    return hashlib.sha256(canonical(clean)).hexdigest()


def load_json(root: Path, rel: str) -> Any:
    return json.loads((root / rel).read_text(encoding="utf-8"))


def gate_state(states: list[str]) -> str:
    for state in GATE_ORDER:
        if state in states:
            return state
    return "deny"


def decision_state(gates: dict[str, str]) -> str:
    state = gate_state(list(gates.values()))
    return {
        "deny": "rejected",
        "unavailable": "unavailable",
        "held": "held",
        "permit": POSITIVE_STATE,
    }[state]


class Checker:
    def __init__(self, root: Path, history_report: Path):
        self.root = root.resolve()
        self.history_report = history_report
        self.findings: list[Finding] = []
        self.registry: dict[str, Any] = {}
        self.upstream: dict[str, Any] = {}
        self.indexes: dict[str, dict[tuple[str, str], dict[str, Any]]] = {}

    def add(self, code: str, path: str, message: str) -> None:
        self.findings.append(Finding("error", code, path, message))

    def read(self, rel: str, code: str) -> Any:
        try:
            return load_json(self.root, rel)
        except Exception as exc:
            self.add(code, rel, str(exc))
            return {}

    def validate_history(self) -> str:
        try:
            path = self.history_report
            if not path.is_absolute():
                path = self.root / path
            report = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("E16A4.HISTORY.READ", str(self.history_report), str(exc))
            return "non-conformant"
        expected = {
            "standard": HISTORY_STANDARD,
            "source_commit": SOURCE_E16_A3_HEAD,
            "overall_result": "conformant",
            "e16_a2_history_result": "conformant",
            "e16_a3_result": "conformant",
            "e16_a3_tests_result": "conformant",
        }
        for key, value in expected.items():
            if report.get(key) != value:
                self.add("E16A4.HISTORY.VALUE", str(self.history_report), f"{key} must be {value!r}")
        return "conformant" if not any(f.code.startswith("E16A4.HISTORY") for f in self.findings) else "non-conformant"

    def validate_manifest_transition(self) -> None:
        manifest = self.read(MANIFEST_PATH, "E16A4.MANIFEST.READ")
        expected_manifest = {
            "standard": MANIFEST_STANDARD,
            "status": "authoritative-slice-overlay",
            "profile_revision": PROFILE_REVISION,
            "source_e16_a3_commit": SOURCE_E16_A3_HEAD,
            "required_authorities": EXPECTED_REQUIRED,
            "authorities": EXPECTED_AUTHORITIES,
        }
        for key, value in expected_manifest.items():
            if manifest.get(key) != value:
                self.add("E16A4.MANIFEST.VALUE", MANIFEST_PATH, f"{key} mismatch")

        transition = self.read(TRANSITION_PATH, "E16A4.TRANSITION.READ")
        if transition.get("standard") != TRANSITION_STANDARD:
            self.add("E16A4.TRANSITION.STANDARD", TRANSITION_PATH, "unexpected standard")
        if transition.get("status") != "adopted-e16-a4":
            self.add("E16A4.TRANSITION.STATUS", TRANSITION_PATH, "unexpected status")
        source = transition.get("source", {})
        target = transition.get("target", {})
        hist = transition.get("historical_preservation", {})
        if source != {
            "slice": "E16-A3",
            "head_commit": SOURCE_E16_A3_HEAD,
            "profile_revision": PROFILE_REVISION,
            "authority_freeze": UPSTREAM_FREEZE_PATH,
        }:
            self.add("E16A4.TRANSITION.SOURCE", TRANSITION_PATH, "source boundary mismatch")
        if target != {
            "extension": "E16-1.0",
            "slice": "E16-A4",
            "profile_revision": PROFILE_REVISION,
            "authority_manifest": MANIFEST_PATH,
            "registry": REGISTRY_PATH,
        }:
            self.add("E16A4.TRANSITION.TARGET", TRANSITION_PATH, "target boundary mismatch")
        expected_hist = {
            "e16_a3_claims_rewritten": False,
            "e16_a3_source_freeze_mutated": False,
            "transition_is_additive": True,
            "descendant_authority_frozen_separately": True,
        }
        if hist != expected_hist:
            self.add("E16A4.TRANSITION.HISTORY", TRANSITION_PATH, "historical preservation mismatch")

    def validate_freeze(self) -> str:
        freeze = self.read(FREEZE_PATH, "E16A4.FREEZE.READ")
        if freeze.get("standard") != FREEZE_STANDARD:
            self.add("E16A4.FREEZE.STANDARD", FREEZE_PATH, "unexpected standard")
        if freeze.get("status") != "frozen":
            self.add("E16A4.FREEZE.STATUS", FREEZE_PATH, "unexpected status")
        if freeze.get("profile_revision") != PROFILE_REVISION:
            self.add("E16A4.FREEZE.PROFILE", FREEZE_PATH, "unexpected profile")
        if freeze.get("source_e16_a3_commit") != SOURCE_E16_A3_HEAD:
            self.add("E16A4.FREEZE.SOURCE", FREEZE_PATH, "unexpected source commit")
        entries = freeze.get("authorities")
        if not isinstance(entries, list):
            self.add("E16A4.FREEZE.ENTRIES", FREEZE_PATH, "authorities must be an array")
            return "non-conformant"
        by_path: dict[str, dict[str, Any]] = {}
        for item in entries:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                self.add("E16A4.FREEZE.ENTRY", FREEZE_PATH, "invalid authority entry")
                continue
            path = item["path"]
            if path in by_path:
                self.add("E16A4.FREEZE.DUPLICATE", FREEZE_PATH, path)
            by_path[path] = item
        if set(by_path) != EXPECTED_FREEZE_PATHS:
            self.add("E16A4.FREEZE.SURFACE", FREEZE_PATH, "frozen path set mismatch")
        for rel in sorted(EXPECTED_FREEZE_PATHS):
            path = self.root / rel
            if not path.is_file():
                self.add("E16A4.FREEZE.MISSING", rel, "frozen authority missing")
                continue
            raw = path.read_bytes()
            item = by_path.get(rel, {})
            if item.get("bytes") != len(raw):
                self.add("E16A4.FREEZE.BYTES", rel, "byte count mismatch")
            if item.get("sha256") != hashlib.sha256(raw).hexdigest():
                self.add("E16A4.FREEZE.DIGEST", rel, "SHA-256 mismatch")
        return "conformant" if not any(f.code.startswith("E16A4.FREEZE") for f in self.findings) else "non-conformant"

    def verify_record(self, family: str, record: Any, index: int) -> None:
        path = f"{REGISTRY_PATH}#{family}/{index}"
        if not isinstance(record, dict):
            self.add("E16A4.RECORD.TYPE", path, "record must be an object")
            return
        for field in ("id", "revision", "commitment"):
            if field not in record:
                self.add("E16A4.RECORD.FIELD", path, f"missing {field}")
        commitment = record.get("commitment")
        if not isinstance(commitment, dict) or commitment.get("algorithm") != "sha256":
            self.add("E16A4.COMMITMENT.FORMAT", path, "invalid commitment")
        elif commitment.get("digest") != commitment_for(record):
            self.add("E16A4.COMMITMENT.MISMATCH", path, "commitment mismatch")

    def build_indexes(self) -> None:
        for family in ARRAYS:
            values = self.registry.get(family)
            if not isinstance(values, list):
                self.add("E16A4.REGISTRY.ARRAY", REGISTRY_PATH, f"{family} must be an array")
                values = []
                self.registry[family] = values
            index: dict[tuple[str, str], dict[str, Any]] = {}
            for pos, record in enumerate(values):
                self.verify_record(family, record, pos)
                if not isinstance(record, dict):
                    continue
                key = (record.get("id"), record.get("revision"))
                if not all(isinstance(part, str) and part for part in key):
                    self.add("E16A4.RECORD.IDENTITY", f"{REGISTRY_PATH}#{family}/{pos}", "invalid identity")
                    continue
                if key in index:
                    self.add("E16A4.RECORD.DUPLICATE", f"{REGISTRY_PATH}#{family}/{pos}", repr(key))
                index[key] = record
            self.indexes[family] = index

    def ref(self, family: str, record: dict[str, Any], prefix: str, path: str) -> dict[str, Any] | None:
        key = (record.get(prefix), record.get(f"{prefix}_revision"))
        target = self.indexes.get(family, {}).get(key)
        if target is None:
            self.add("E16A4.REFERENCE.MISSING", path, f"{prefix} {key!r} missing")
            return None
        expected = target.get("commitment", {}).get("digest")
        if record.get(f"{prefix}_commitment") != expected:
            self.add("E16A4.REFERENCE.COMMITMENT", path, f"{prefix} commitment mismatch")
            return None
        return target

    def upstream_decision(self, auth: dict[str, Any], path: str) -> dict[str, Any] | None:
        values = self.upstream.get("preservation_verification_decisions", [])
        if not isinstance(values, list):
            self.add("E16A4.UPSTREAM.ARRAY", UPSTREAM_REGISTRY_PATH, "decisions must be an array")
            return None
        key = (auth.get("source_decision"), auth.get("source_decision_revision"))
        for item in values:
            if isinstance(item, dict) and (item.get("id"), item.get("revision")) == key:
                digest = item.get("commitment", {}).get("digest")
                if auth.get("source_decision_commitment") != digest:
                    self.add("E16A4.UPSTREAM.COMMITMENT", path, "source decision commitment mismatch")
                    return None
                if item.get("state") != "bounded-preservation-and-restore-verified":
                    self.add("E16A4.UPSTREAM.STATE", path, "source decision is not positive")
                    return None
                return item
        self.add("E16A4.UPSTREAM.MISSING", path, f"source decision {key!r} missing")
        return None

    @staticmethod
    def map_state(value: str, positive: str, negative: str) -> str:
        if value == positive:
            return "permit"
        if value == negative:
            return "deny"
        if value == "unavailable":
            return "unavailable"
        return "held"

    def derive(self, decision: dict[str, Any], pos: int) -> dict[str, str]:
        path = f"{REGISTRY_PATH}#recovery_decisions/{pos}"
        succession = self.ref("succession_authorizations", decision, "succession", path)
        plan = self.ref("migration_plans", decision, "migration_plan", path)
        observation = self.ref("migration_observations", decision, "migration_observation", path)
        replay = self.ref("recovery_replays", decision, "recovery_replay", path)
        gates = {
            "e16_a3_continuity": "deny",
            "succession": "deny",
            "migration_plan": "deny",
            "migration_observation": "deny",
            "loss": "permit",
            "quarantine": "permit",
            "anti_rollback_recovery": "deny",
        }
        source = None
        if succession:
            source = self.upstream_decision(succession, path)
            if source:
                repeated = (
                    succession.get("content_sha256"),
                    succession.get("content_bytes"),
                    succession.get("predecessor_custodian"),
                    succession.get("predecessor_replica"),
                )
                source_values = (
                    source.get("content_sha256"),
                    source.get("content_bytes"),
                    source.get("custodian"),
                    source.get("replica"),
                )
                if all(value is not None for value in source_values) and repeated != source_values:
                    self.add("E16A4.SUCCESSION.SOURCE_BINDING", path, "source identity mismatch")
                else:
                    gates["e16_a3_continuity"] = "permit"
            gates["succession"] = self.map_state(
                succession.get("authorization_state"), "authorized", "withdrawn"
            )
            if succession.get("predecessor_custodian") == succession.get("successor_custodian"):
                gates["succession"] = "deny"
                self.add("E16A4.SUCCESSION.DISTINCT", path, "predecessor and successor custodians must differ")

        if plan and succession:
            if plan.get("succession") != succession.get("id") or plan.get("succession_revision") != succession.get("revision"):
                self.add("E16A4.PLAN.SUCCESSION", path, "plan succession mismatch")
            aligned = (
                plan.get("predecessor_custodian") == succession.get("predecessor_custodian")
                and plan.get("successor_custodian") == succession.get("successor_custodian")
                and plan.get("source_replica") == succession.get("predecessor_replica")
                and plan.get("content_sha256") == succession.get("content_sha256")
                and plan.get("content_bytes") == succession.get("content_bytes")
                and plan.get("source_generation") == succession.get("source_generation")
            )
            if not aligned or plan.get("target_replica") == plan.get("source_replica"):
                self.add("E16A4.PLAN.BINDING", path, "plan identity binding mismatch")
                gates["migration_plan"] = "deny"
            elif not isinstance(plan.get("target_generation"), int) or plan.get("target_generation") <= plan.get("source_generation", -1):
                self.add("E16A4.PLAN.GENERATION", path, "target generation must be newer")
                gates["migration_plan"] = "deny"
            else:
                gates["migration_plan"] = self.map_state(plan.get("state"), "planned", "cancelled")

        if observation and plan:
            aligned = (
                observation.get("migration_plan") == plan.get("id")
                and observation.get("source_replica") == plan.get("source_replica")
                and observation.get("target_replica") == plan.get("target_replica")
                and observation.get("observed_content_sha256") == plan.get("content_sha256")
                and observation.get("observed_content_bytes") == plan.get("content_bytes")
                and observation.get("target_generation") == plan.get("target_generation")
            )
            if not aligned:
                self.add("E16A4.OBSERVATION.BINDING", path, "migration observation mismatch")
                gates["migration_observation"] = "deny"
            else:
                gates["migration_observation"] = self.map_state(
                    observation.get("observation_state"), "positive", "negative"
                )

        target_id = plan.get("target_replica") if plan else None
        target_rev = plan.get("target_replica_revision") if plan else None
        for report in self.registry.get("loss_reports", []):
            if not isinstance(report, dict) or not plan:
                continue
            if report.get("migration_plan") != plan.get("id") or report.get("migration_plan_revision") != plan.get("revision"):
                continue
            role = report.get("affected_role")
            state = report.get("loss_state")
            if role in ("target", "both"):
                if report.get("affected_replica") not in (target_id, "*"):
                    self.add("E16A4.LOSS.TARGET", path, "target loss report identifies another replica")
                    gates["loss"] = "deny"
                elif state == "confirmed":
                    gates["loss"] = "deny"
                elif state == "unavailable" and gates["loss"] != "deny":
                    gates["loss"] = "unavailable"
                elif state == "suspected" and gates["loss"] not in ("deny", "unavailable"):
                    gates["loss"] = "held"

        replay_key = (replay.get("id"), replay.get("revision")) if replay else (None, None)
        for quarantine in self.registry.get("quarantine_records", []):
            if not isinstance(quarantine, dict):
                continue
            state = quarantine.get("quarantine_state")
            kind = quarantine.get("subject_kind")
            target_subject = (
                kind == "target-replica"
                and quarantine.get("subject") == target_id
                and quarantine.get("subject_revision") == target_rev
            )
            observation_subject = observation and kind == "migration-observation" and (
                quarantine.get("subject"), quarantine.get("subject_revision")
            ) == (observation.get("id"), observation.get("revision"))
            replay_subject = replay and kind == "recovery-replay" and (
                quarantine.get("subject"), quarantine.get("subject_revision")
            ) == replay_key
            if target_subject or observation_subject or replay_subject:
                if state == "active":
                    gates["quarantine"] = "deny"
                elif state == "unavailable" and gates["quarantine"] != "deny":
                    gates["quarantine"] = "unavailable"
                elif state == "held" and gates["quarantine"] not in ("deny", "unavailable"):
                    gates["quarantine"] = "held"

        if replay and plan and observation:
            aligned = (
                replay.get("migration_plan") == plan.get("id")
                and replay.get("migration_observation") == observation.get("id")
                and replay.get("candidate_replica") == plan.get("target_replica")
                and replay.get("candidate_replica_revision") == plan.get("target_replica_revision")
                and replay.get("content_sha256") == plan.get("content_sha256")
                and replay.get("content_bytes") == plan.get("content_bytes")
                and replay.get("candidate_generation") == plan.get("target_generation")
            )
            generations = (
                isinstance(replay.get("accepted_generation"), int)
                and isinstance(replay.get("minimum_generation"), int)
                and isinstance(replay.get("candidate_generation"), int)
                and replay["candidate_generation"] > replay["accepted_generation"]
                and replay["candidate_generation"] >= replay["minimum_generation"]
            )
            sequence = replay.get("replay_sequence")
            sequence_ok = isinstance(sequence, list) and bool(sequence)
            if sequence_ok:
                positions = [item.get("position") for item in sequence if isinstance(item, dict)]
                commitments = [item.get("commitment") for item in sequence if isinstance(item, dict)]
                sequence_ok = (
                    len(positions) == len(sequence)
                    and positions == list(range(len(sequence)))
                    and len(commitments) == len(sequence)
                    and all(isinstance(item, str) and len(item) == 64 for item in commitments)
                    and len(set(commitments)) == len(commitments)
                )
            superseded = replay.get("superseded_commitments")
            source_commitment = succession.get("source_decision_commitment") if succession else None
            superseded_ok = (
                isinstance(superseded, list)
                and source_commitment in superseded
                and len(superseded) == len(set(superseded))
            )
            if not aligned:
                self.add("E16A4.REPLAY.BINDING", path, "recovery replay binding mismatch")
            if not generations:
                self.add("E16A4.REPLAY.ROLLBACK", path, "candidate generation violates anti-rollback floor")
            if not sequence_ok:
                self.add("E16A4.REPLAY.SEQUENCE", path, "replay sequence is not strict and duplicate-free")
            if not superseded_ok:
                self.add("E16A4.REPLAY.SUPERSEDED", path, "source commitment is not explicitly superseded")
            if aligned and generations and sequence_ok and superseded_ok:
                gates["anti_rollback_recovery"] = self.map_state(
                    replay.get("replay_state"), "positive", "negative"
                )
            else:
                gates["anti_rollback_recovery"] = "deny"
        return gates

    def validate_registry(self) -> tuple[str, str, dict[str, int]]:
        self.registry = self.read(REGISTRY_PATH, "E16A4.REGISTRY.READ")
        self.upstream = self.read(UPSTREAM_REGISTRY_PATH, "E16A4.UPSTREAM.READ")
        expected_header = {
            "standard": STANDARD,
            "status": "structural-only",
            "source_e16_a3_commit": SOURCE_E16_A3_HEAD,
            "upstream_retention_registry": UPSTREAM_REGISTRY_PATH,
            "upstream_e16_a3_freeze": UPSTREAM_FREEZE_PATH,
            "authority_manifest": MANIFEST_PATH,
        }
        for key, value in expected_header.items():
            if self.registry.get(key) != value:
                self.add("E16A4.REGISTRY.HEADER", REGISTRY_PATH, f"{key} mismatch")
        self.build_indexes()

        for family in ("migration_plans", "recovery_replays"):
            seen: set[str] = set()
            for pos, record in enumerate(self.registry.get(family, [])):
                if not isinstance(record, dict):
                    continue
                key = record.get("idempotency_key")
                if not isinstance(key, str) or not key:
                    self.add("E16A4.IDEMPOTENCY.MISSING", f"{REGISTRY_PATH}#{family}/{pos}", "missing idempotency key")
                elif key in seen:
                    self.add("E16A4.IDEMPOTENCY.DUPLICATE", f"{REGISTRY_PATH}#{family}/{pos}", key)
                seen.add(key)

        counts = {state: 0 for state in DECISION_STATES}
        for pos, decision in enumerate(self.registry.get("recovery_decisions", [])):
            if not isinstance(decision, dict):
                continue
            gates = self.derive(decision, pos)
            state = decision_state(gates)
            if decision.get("gates") != gates or decision.get("state") != state:
                self.add("E16A4.DECISION.DERIVATION", f"{REGISTRY_PATH}#recovery_decisions/{pos}", "stored decision differs from derivation")
            if state in counts:
                counts[state] += 1

        structural = "non-conformant" if self.findings else "conformant"
        decisions = self.registry.get("recovery_decisions", [])
        recovery = "not-evaluated" if not decisions else structural
        return structural, recovery, counts

    def run(self) -> dict[str, Any]:
        history = self.validate_history()
        self.validate_manifest_transition()
        freeze = self.validate_freeze()
        structural, recovery, counts = self.validate_registry()
        if history != "conformant" or freeze != "conformant":
            structural = "non-conformant"
            if self.registry.get("recovery_decisions"):
                recovery = "non-conformant"
        return {
            "tool": "eigiib-custodian-succession-recovery-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "historical_continuity_result": history,
            "authority_freeze_result": freeze,
            "structural_result": structural,
            "recovery_result": recovery,
            "succession_authorization_count": len(self.registry.get("succession_authorizations", [])),
            "migration_plan_count": len(self.registry.get("migration_plans", [])),
            "migration_observation_count": len(self.registry.get("migration_observations", [])),
            "loss_report_count": len(self.registry.get("loss_reports", [])),
            "quarantine_record_count": len(self.registry.get("quarantine_records", [])),
            "recovery_replay_count": len(self.registry.get("recovery_replays", [])),
            "recovery_decision_count": len(self.registry.get("recovery_decisions", [])),
            "decision_state_counts": counts,
            "findings": [asdict(item) for item in sorted(self.findings)],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--history-report", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = Checker(Path(args.root), Path(args.history_report)).run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
