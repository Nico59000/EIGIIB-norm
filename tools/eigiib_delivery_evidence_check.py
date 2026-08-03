#!/usr/bin/env python3
"""Static EIGIIB-E15-A2 transfer-attempt and external-evidence checker."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tomllib
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E15-A2-1.0"
TRANSITION_STANDARD = "EIGIIB-E15-A2-TRANSITION-1.0"
FREEZE_STANDARD = "EIGIIB-E15-A2-FREEZE-1.0"
HISTORY_STANDARD = "EIGIIB-E15-A2-HISTORICAL-E15-A1-REPLAY-1.0"
PROFILE_REVISION = "EIGIIB-E15-draft-1.1"
FINAL_PROFILE_REVISION = "EIGIIB-E15-1.0"
SOURCE_E15_A1_HEAD = "ca0dfde0efcee975ef4957f604d4954b6de07e01"
SOURCE_E14_HEAD = "472e14fbb3d92205eabf10438e90295e19125ea4"
DELIVERY_ACTION = "eigiib:e15:deliver"

GATE_STATES = {"permit", "deny", "held", "unavailable"}
EVIDENCE_STATES = {"positive", "negative", "contested", "unavailable"}
LIFECYCLE_STATES = {
    "not-started", "in-progress", "externally-attested", "rejected",
    "held", "contested", "unavailable",
}
ATTESTER_STATES = {"verified", "rejected", "contested", "unavailable"}
POLICY_STATES = {"active", "retired", "contested", "unavailable"}
LOCAL_RESULTS = {"prepared", "submitted", "locally-completed", "failed", "contested", "unavailable"}
EVIDENCE_TYPES = {
    "service-acceptance", "delivery-receipt", "recipient-interface-acceptance",
    "non-delivery", "transport-failure",
}
ACK_TYPES = {"service-generated", "recipient-interface-generated", "recipient-principal-signed"}

EXPECTED_FREEZE_PATHS = {
    ".github/workflows/e15-a1-delivery-intent.yml",
    ".github/workflows/e15-a2-delivery-evidence.yml",
    ".github/workflows/eigiib.yml",
    "EIGIIB.toml",
    "conformance/E15-A2-MANUAL-REVIEW.md",
    "conformance/delivery-intent.json",
    "conformance/delivery-evidence.json",
    "conformance/e15-a1-adoption-transition.json",
    "conformance/e15-a1-authority-freeze.json",
    "conformance/e15-a2-adoption-transition.json",
    "conformance/extension-graph.json",
    "docs/E15-A2-HUMAN-MASTERY-GUIDE.md",
    "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
    "schemas/eigiib-e15-a2-adoption-transition.schema.json",
    "schemas/eigiib-e15-a2-authority-freeze.schema.json",
    "schemas/eigiib-e15-a2-delivery-evidence.schema.json",
    "tests/fixtures/e15-a2/expected-report.json",
    "tests/test_eigiib_delivery_evidence.py",
    "tools/eigiib_delivery_evidence_check.py",
    "tools/eigiib_historical_e15_a1_replay.py",
}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def commitment_for(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes({k: v for k, v in value.items() if k != "commitment"})).hexdigest()


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def combine_gates(values: list[str]) -> str:
    if "deny" in values:
        return "deny"
    if "unavailable" in values:
        return "unavailable"
    if "held" in values:
        return "held"
    return "permit"


def state_gate(state: str, positive: str, negative: str) -> str:
    if state == positive:
        return "permit"
    if state == negative:
        return "deny"
    if state == "unavailable":
        return "unavailable"
    return "held"


class Checker:
    def __init__(
        self,
        root: Path,
        registry: Path = Path("conformance/delivery-evidence.json"),
        transition: Path = Path("conformance/e15-a2-adoption-transition.json"),
        freeze: Path = Path("conformance/e15-a2-authority-freeze.json"),
        parent_registry: Path = Path("conformance/delivery-intent.json"),
        history_report: Path | None = None,
    ):
        self.root = root.resolve()
        self.registry_path = registry
        self.transition_path = transition
        self.freeze_path = freeze
        self.parent_registry_path = parent_registry
        self.history_report_path = history_report
        self.findings: list[Finding] = []
        self.parent_intents: dict[str, dict[str, Any]] = {}
        self.parent_decisions: dict[str, dict[str, Any]] = {}
        self.attesters: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.attempts: dict[str, dict[str, Any]] = {}
        self.delivery_evidence: dict[str, dict[str, Any]] = {}
        self.acknowledgements: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.valid_decisions: set[str] = set()
        self.derived_states: dict[str, str] = {}
        self.attempt_binding: dict[str, str] = {}
        self.evidence_binding: dict[str, str] = {}
        self.evidence_attester: dict[str, str] = {}
        self.ack_binding: dict[str, str] = {}
        self.ack_attester: dict[str, str] = {}

    @staticmethod
    def nonempty(value: Any) -> bool:
        return isinstance(value, str) and bool(value)

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def confined(self, rel: str, code: str, must_exist: bool = False) -> Path | None:
        if not self.nonempty(rel) or Path(rel).is_absolute():
            self.add("error", f"{code}.PATH", "path must be non-empty and repository-relative", str(rel))
            return None
        candidate = (self.root / rel).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add("error", f"{code}.PATH", "path escapes repository root", rel)
            return None
        if must_exist and not candidate.is_file():
            self.add("error", f"{code}.MISSING", "referenced file is missing", rel)
            return None
        return candidate

    def load_json(self, rel: Path, code: str) -> dict[str, Any] | None:
        path = self.confined(rel.as_posix(), code, True)
        if path is None:
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
        except Exception as exc:
            self.add("error", f"{code}.PARSE", str(exc), rel.as_posix())
            return None
        if not isinstance(value, dict):
            self.add("error", f"{code}.TYPE", "JSON root must be an object", rel.as_posix())
            return None
        return value

    def index(self, obj: dict[str, Any], field: str, code: str) -> dict[str, dict[str, Any]]:
        values = obj.get(field)
        if not isinstance(values, list):
            self.add("error", f"{code}.TYPE", f"{field} must be an array", field)
            return {}
        out: dict[str, dict[str, Any]] = {}
        for pos, value in enumerate(values):
            path = f"{field}[{pos}]"
            if not isinstance(value, dict):
                self.add("error", f"{code}.ITEM", "item must be an object", path)
                continue
            identifier = value.get("id")
            if not self.nonempty(identifier):
                self.add("error", f"{code}.ID", "id must be a non-empty string", path)
                continue
            if identifier in out:
                self.add("error", f"{code}.DUPLICATE", f"duplicate id {identifier}", path)
                continue
            out[identifier] = value
        return out

    def string_list(self, value: Any, path: str, code: str, allow_empty: bool = False) -> list[str]:
        if (
            not isinstance(value, list)
            or (not allow_empty and not value)
            or any(not self.nonempty(item) for item in value)
            or len(value) != len(set(value))
        ):
            self.add("error", code, "must be a unique array of non-empty strings", path)
            return []
        return value

    def check_commitment(self, value: dict[str, Any], path: str, code: str) -> None:
        commitment = value.get("commitment")
        if not isinstance(commitment, dict) or commitment.get("algorithm") != "sha256" or commitment.get("digest") != commitment_for(value):
            self.add("error", code, "canonical SHA-256 commitment mismatch", path)

    def check_profile(self) -> None:
        try:
            profile = tomllib.loads((self.root / "EIGIIB.toml").read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "E15A2.PROFILE.PARSE", str(exc), "EIGIIB.toml")
            return
        if "E15-1.0" not in profile.get("extensions", []):
            self.add("error", "E15A2.PROFILE.ADOPTION", "E15-1.0 must remain adopted", "EIGIIB.toml")
        if profile.get("revision") not in {PROFILE_REVISION, FINAL_PROFILE_REVISION}:
            self.add("error", "E15A2.PROFILE.REVISION", f"revision must be {PROFILE_REVISION} or {FINAL_PROFILE_REVISION}", "EIGIIB.toml")
        expected = {
            "e15": "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
            "delivery_intent": self.parent_registry_path.as_posix(),
            "e15_a1_transition": "conformance/e15-a1-adoption-transition.json",
            "e15_a1_authority_freeze": "conformance/e15-a1-authority-freeze.json",
            "delivery_evidence": self.registry_path.as_posix(),
            "e15_a2_transition": self.transition_path.as_posix(),
            "e15_a2_authority_freeze": self.freeze_path.as_posix(),
            "e15_a2_human_mastery": "docs/E15-A2-HUMAN-MASTERY-GUIDE.md",
        }
        authorities = profile.get("authorities", {})
        required = profile.get("required_authorities", [])
        for key, value in expected.items():
            if not isinstance(authorities, dict) or authorities.get(key) != value:
                self.add("error", "E15A2.PROFILE.AUTHORITY", f"authority {key} must bind {value}", "EIGIIB.toml")
            else:
                self.confined(value, "E15A2.PROFILE", True)
            if not isinstance(required, list) or key not in required:
                self.add("error", "E15A2.PROFILE.REQUIRED", f"required authority missing: {key}", "EIGIIB.toml")
        gates = profile.get("manual_gates", [])
        exact = ("complete", "e15", "conformance/E15-A2-MANUAL-REVIEW.md")
        matches = [g for g in gates if isinstance(g, dict) and g.get("id") == "e15-a2-transfer-evidence-acknowledgement-review"] if isinstance(gates, list) else []
        if len(matches) != 1 or (matches[0].get("status"), matches[0].get("authority"), matches[0].get("attestation")) != exact:
            self.add("error", "E15A2.PROFILE.GATE", "E15-A2 manual gate is missing or inexact", "EIGIIB.toml")
        else:
            self.confined(exact[2], "E15A2.PROFILE", True)

    def check_history_report(self) -> str:
        if self.history_report_path is None:
            self.add("error", "E15A2.HISTORY.REPORT", "historical E15-A1 replay report is required", "")
            return "non-conformant"
        report = self.load_json(self.history_report_path, "E15A2.HISTORY")
        if report is None:
            return "non-conformant"
        if report.get("standard") != HISTORY_STANDARD or report.get("source_commit") != SOURCE_E15_A1_HEAD:
            self.add("error", "E15A2.HISTORY.HEADER", "historical E15-A1 replay header mismatch", self.history_report_path.as_posix())
        if report.get("historical_e14_result") != "conformant" or report.get("e15_a1_result") != "conformant":
            self.add("error", "E15A2.HISTORY.COMPONENT", "historical E15-A1 coverage is incomplete", self.history_report_path.as_posix())
        if report.get("overall_result") != "conformant":
            self.add("error", "E15A2.HISTORY.RESULT", "historical E15-A1 replay is not conformant", self.history_report_path.as_posix())
        return "non-conformant" if any(f.code.startswith("E15A2.HISTORY") for f in self.findings) else "conformant"

    def check_transition(self, transition: dict[str, Any] | None) -> None:
        if transition is None:
            return
        path = self.transition_path.as_posix()
        if transition.get("standard") != TRANSITION_STANDARD or transition.get("status") != "adopted-e15-a2":
            self.add("error", "E15A2.TRANSITION.HEADER", "unexpected transition header", path)
        source = transition.get("source")
        exact_source = {
            "head_commit": SOURCE_E15_A1_HEAD,
            "profile_revision": "EIGIIB-E15-draft-1.0",
            "authority_freeze": "conformance/e15-a1-authority-freeze.json",
            "registry_authority": "conformance/delivery-intent.json",
            "checker": "tools/eigiib_delivery_intent_check.py",
        }
        if not isinstance(source, dict) or any(source.get(k) != v for k, v in exact_source.items()):
            self.add("error", "E15A2.TRANSITION.SOURCE", "source E15-A1 authority mismatch", path)
        replay = transition.get("historical_replay")
        if not isinstance(replay, dict) or replay.get("mode") != "materialize-and-replay-exact-source-commit" or replay.get("tool") != "tools/eigiib_historical_e15_a1_replay.py":
            self.add("error", "E15A2.TRANSITION.REPLAY", "historical replay contract mismatch", path)
        target = transition.get("target")
        exact_target = {
            "slice": "E15-A2",
            "registry_authority": self.registry_path.as_posix(),
            "checker": "tools/eigiib_delivery_evidence_check.py",
            "authority_freeze": self.freeze_path.as_posix(),
            "profile_revision": PROFILE_REVISION,
        }
        if not isinstance(target, dict) or any(target.get(k) != v for k, v in exact_target.items()):
            self.add("error", "E15A2.TRANSITION.TARGET", "target E15-A2 authority mismatch", path)
        preservation = transition.get("historical_preservation")
        if not isinstance(preservation, dict) or preservation.get("e15_a1_claims_rewritten") is not False or preservation.get("source_freeze_mutated") is not False or preservation.get("transition_is_additive") is not True:
            self.add("error", "E15A2.TRANSITION.PRESERVATION", "historical preservation contract mismatch", path)

    def load_parent(self) -> None:
        parent = self.load_json(self.parent_registry_path, "E15A2.PARENT")
        if parent is None:
            return
        if parent.get("standard") != "EIGIIB-E15-A1-1.0" or parent.get("source_e14_commit") != SOURCE_E14_HEAD:
            self.add("error", "E15A2.PARENT.HEADER", "unexpected E15-A1 parent registry", self.parent_registry_path.as_posix())
        self.parent_intents = self.index(parent, "delivery_intents", "E15A2.PARENT.INTENT")
        decisions = self.index(parent, "delivery_decisions", "E15A2.PARENT.DECISION")
        for decision in decisions.values():
            intent = decision.get("intent")
            if self.nonempty(intent) and decision.get("state") == "admissible":
                self.parent_decisions[intent] = decision

    def validate_attesters(self) -> None:
        for identifier, value in self.attesters.items():
            path = f"attester_profiles[{identifier}]"
            self.check_commitment(value, path, "E15A2.ATTESTER.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("kind") not in {"service", "recipient-interface", "independent-observer"}:
                self.add("error", "E15A2.ATTESTER.SHAPE", "attester revision or kind is invalid", path)
            if value.get("identity_state") not in ATTESTER_STATES:
                self.add("error", "E15A2.ATTESTER.STATE", "invalid attester identity state", path)
            for field in ("accepted_evidence_types", "accepted_endpoints", "authentication_algorithms"):
                self.string_list(value.get(field), f"{path}.{field}", "E15A2.ATTESTER.LIST")
            if not self.nonempty(value.get("identity_authority")):
                self.add("error", "E15A2.ATTESTER.AUTHORITY", "identity authority is required", path)

    def validate_policies(self) -> None:
        for identifier, value in self.policies.items():
            path = f"external_attestation_policies[{identifier}]"
            self.check_commitment(value, path, "E15A2.POLICY.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("state") not in POLICY_STATES:
                self.add("error", "E15A2.POLICY.SHAPE", "policy revision or state is invalid", path)
            for field in ("allowed_attesters", "allowed_evidence_types", "required_authentication_algorithms", "allowed_acknowledgement_types"):
                self.string_list(value.get(field), f"{path}.{field}", "E15A2.POLICY.LIST", allow_empty=(field == "allowed_acknowledgement_types"))
            if value.get("acknowledgement_requirement") not in {"required", "optional"}:
                self.add("error", "E15A2.POLICY.ACK", "acknowledgement requirement must be required or optional", path)
            for field in ("max_evidence_age_seconds", "max_acknowledgement_age_seconds"):
                if not isinstance(value.get(field), int) or value[field] < 0:
                    self.add("error", "E15A2.POLICY.AGE", f"{field} must be a non-negative integer", path)

    def validate_attempts(self) -> None:
        seen_keys: dict[str, str] = {}
        seen_sequence: set[tuple[str, int]] = set()
        for identifier, value in self.attempts.items():
            path = f"transfer_attempts[{identifier}]"
            self.check_commitment(value, path, "E15A2.ATTEMPT.COMMITMENT")
            required_strings = (
                "revision", "intent", "intent_revision", "attempt_idempotency_key", "endpoint", "endpoint_revision",
                "carrier", "carrier_revision", "recipient_scope", "payload_sha256", "attestation_policy", "attestation_policy_revision", "started_at",
            )
            if any(not self.nonempty(value.get(field)) for field in required_strings):
                self.add("error", "E15A2.ATTEMPT.SHAPE", "attempt string fields are incomplete", path)
            if value.get("local_result") not in LOCAL_RESULTS:
                self.add("error", "E15A2.ATTEMPT.LOCAL", "invalid local result", path)
            if not isinstance(value.get("attempt_sequence"), int) or value["attempt_sequence"] < 1:
                self.add("error", "E15A2.ATTEMPT.SEQUENCE", "attempt sequence must be a positive integer", path)
            if not isinstance(value.get("payload_bytes"), int) or value["payload_bytes"] < 0:
                self.add("error", "E15A2.ATTEMPT.PAYLOAD", "payload_bytes must be non-negative", path)
            if parse_time(value.get("started_at")) is None:
                self.add("error", "E15A2.ATTEMPT.TIME", "started_at must be UTC RFC3339", path)
            key = value.get("attempt_idempotency_key")
            if self.nonempty(key):
                if key in seen_keys:
                    self.add("error", "E15A2.ATTEMPT.IDEMPOTENCY", f"attempt idempotency key already used by {seen_keys[key]}", path)
                seen_keys[key] = identifier
            seq = (str(value.get("intent")), value.get("attempt_sequence"))
            if isinstance(seq[1], int):
                if seq in seen_sequence:
                    self.add("error", "E15A2.ATTEMPT.SEQUENCE", "attempt sequence is duplicated for intent", path)
                seen_sequence.add(seq)
            parent = self.parent_intents.get(str(value.get("intent")))
            parent_decision = self.parent_decisions.get(str(value.get("intent")))
            policy = self.policies.get(str(value.get("attestation_policy")))
            binding = "permit"
            if parent is None or parent_decision is None or parent.get("revision") != value.get("intent_revision"):
                binding = "deny"
            elif any(parent.get(k) != value.get(k) for k in ("endpoint", "endpoint_revision", "carrier", "carrier_revision", "recipient_scope")):
                binding = "deny"
            elif parent.get("payload_sha256") != value.get("payload_sha256") or parent.get("payload_bytes") != value.get("payload_bytes"):
                binding = "deny"
            if policy is None or policy.get("revision") != value.get("attestation_policy_revision"):
                binding = "deny"
            self.attempt_binding[identifier] = binding

    def authentication_gate(self, value: dict[str, Any], attester: dict[str, Any], policy: dict[str, Any]) -> str:
        gates = [state_gate(str(attester.get("identity_state")), "verified", "rejected"), state_gate(str(policy.get("state")), "active", "retired")]
        auth = value.get("authentication")
        if not isinstance(auth, dict):
            return "deny"
        algorithm = auth.get("algorithm")
        if algorithm not in attester.get("authentication_algorithms", []) or algorithm not in policy.get("required_authentication_algorithms", []):
            gates.append("deny")
        if value.get("attester") not in policy.get("allowed_attesters", []):
            gates.append("deny")
        if value.get("type") not in policy.get("allowed_evidence_types", []) and value.get("type") not in policy.get("allowed_acknowledgement_types", []):
            gates.append("deny")
        return combine_gates(gates)

    def validate_delivery_evidence(self) -> None:
        for identifier, value in self.delivery_evidence.items():
            path = f"external_delivery_evidence[{identifier}]"
            self.check_commitment(value, path, "E15A2.EVIDENCE.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("type") not in EVIDENCE_TYPES or value.get("evidence_state") not in EVIDENCE_STATES:
                self.add("error", "E15A2.EVIDENCE.SHAPE", "evidence revision, type or state is invalid", path)
            attempt = self.attempts.get(str(value.get("attempt")))
            attester = self.attesters.get(str(value.get("attester")))
            policy = self.policies.get(str(value.get("policy")))
            if attempt is None or attester is None or policy is None:
                self.add("error", "E15A2.EVIDENCE.REF", "attempt, attester and policy must resolve", path)
                continue
            if value.get("attempt_revision") != attempt.get("revision") or value.get("attester_revision") != attester.get("revision") or value.get("policy_revision") != policy.get("revision"):
                self.add("error", "E15A2.EVIDENCE.REVISION", "referenced revision mismatch", path)
            for field in ("issued_at", "valid_until"):
                if parse_time(value.get(field)) is None:
                    self.add("error", "E15A2.EVIDENCE.TIME", f"{field} must be UTC RFC3339", path)
            auth = value.get("authentication")
            if not isinstance(auth, dict) or any(not self.nonempty(auth.get(k)) for k in ("algorithm", "key_id", "signature_sha256")):
                self.add("error", "E15A2.EVIDENCE.AUTH", "authentication binding is incomplete", path)
            event = value.get("observed_event")
            state = value.get("evidence_state")
            if state == "positive" and event not in {"accepted", "delivered"}:
                self.add("error", "E15A2.EVIDENCE.COHERENCE", "positive evidence requires accepted or delivered event", path)
            if state == "negative" and event not in {"rejected", "failed"}:
                self.add("error", "E15A2.EVIDENCE.COHERENCE", "negative evidence requires rejected or failed event", path)
            binding = "permit"
            for field in ("endpoint", "carrier", "recipient_scope", "payload_sha256"):
                if value.get(field) != attempt.get(field):
                    binding = "deny"
            if value.get("type") not in attester.get("accepted_evidence_types", []) or value.get("endpoint") not in attester.get("accepted_endpoints", []):
                binding = "deny"
            self.evidence_binding[identifier] = binding
            self.evidence_attester[identifier] = self.authentication_gate(value, attester, policy)

    def validate_acknowledgements(self) -> None:
        for identifier, value in self.acknowledgements.items():
            path = f"recipient_acknowledgements[{identifier}]"
            self.check_commitment(value, path, "E15A2.ACK.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("type") not in ACK_TYPES or value.get("evidence_state") not in EVIDENCE_STATES:
                self.add("error", "E15A2.ACK.SHAPE", "acknowledgement revision, type or state is invalid", path)
            attempt = self.attempts.get(str(value.get("attempt")))
            delivery = self.delivery_evidence.get(str(value.get("delivery_evidence")))
            attester = self.attesters.get(str(value.get("attester")))
            policy = self.policies.get(str(value.get("policy")))
            if attempt is None or delivery is None or attester is None or policy is None:
                self.add("error", "E15A2.ACK.REF", "attempt, delivery evidence, attester and policy must resolve", path)
                continue
            if value.get("attempt_revision") != attempt.get("revision") or value.get("delivery_evidence_revision") != delivery.get("revision") or value.get("attester_revision") != attester.get("revision") or value.get("policy_revision") != policy.get("revision"):
                self.add("error", "E15A2.ACK.REVISION", "referenced revision mismatch", path)
            for field in ("issued_at", "valid_until"):
                if parse_time(value.get(field)) is None:
                    self.add("error", "E15A2.ACK.TIME", f"{field} must be UTC RFC3339", path)
            auth = value.get("authentication")
            if not isinstance(auth, dict) or any(not self.nonempty(auth.get(k)) for k in ("algorithm", "key_id", "signature_sha256")):
                self.add("error", "E15A2.ACK.AUTH", "authentication binding is incomplete", path)
            event = value.get("acknowledged_event")
            state = value.get("evidence_state")
            if state == "positive" and event not in {"received", "accepted", "processed"}:
                self.add("error", "E15A2.ACK.COHERENCE", "positive acknowledgement event mismatch", path)
            if state == "negative" and event != "rejected":
                self.add("error", "E15A2.ACK.COHERENCE", "negative acknowledgement requires rejected event", path)
            binding = "permit"
            if delivery.get("attempt") != value.get("attempt"):
                binding = "deny"
            for field in ("endpoint", "recipient_scope", "payload_sha256"):
                if value.get(field) != attempt.get(field):
                    binding = "deny"
            if value.get("type") not in policy.get("allowed_acknowledgement_types", []):
                binding = "deny"
            self.ack_binding[identifier] = binding
            self.ack_attester[identifier] = self.authentication_gate(value, attester, policy)

    def freshness_gate(self, items: list[dict[str, Any]], evaluated: datetime, policy: dict[str, Any], acknowledgement: bool = False) -> str:
        max_age = policy.get("max_acknowledgement_age_seconds" if acknowledgement else "max_evidence_age_seconds")
        gates: list[str] = []
        for item in items:
            issued = parse_time(item.get("issued_at"))
            valid_until = parse_time(item.get("valid_until"))
            if issued is None or valid_until is None or not isinstance(max_age, int):
                gates.append("deny")
                continue
            if issued > evaluated or evaluated > valid_until or (evaluated - issued).total_seconds() > max_age:
                gates.append("deny")
            else:
                gates.append("permit")
        return combine_gates(gates) if gates else "permit"

    def evidence_gate(self, states: list[str], required: bool = True) -> str:
        if not states:
            return "held" if required else "permit"
        if "negative" in states:
            return "deny"
        if "unavailable" in states:
            return "unavailable"
        if "contested" in states:
            return "held"
        return "permit"

    def derive_lifecycle(self, attempt: dict[str, Any], gates: dict[str, str], evidence_states: list[str], ack_states: list[str]) -> str:
        values = list(gates.values())
        if "deny" in values or attempt.get("local_result") == "failed":
            return "rejected"
        if "contested" in evidence_states or "contested" in ack_states or attempt.get("local_result") == "contested":
            return "contested"
        if "unavailable" in values or "unavailable" in evidence_states or "unavailable" in ack_states or attempt.get("local_result") == "unavailable":
            return "unavailable"
        if not evidence_states and attempt.get("local_result") == "prepared":
            return "not-started"
        if not evidence_states and attempt.get("local_result") in {"submitted", "locally-completed"}:
            return "in-progress"
        if "held" in values:
            return "held"
        return "externally-attested"

    def validate_decisions(self) -> None:
        used_evidence: set[str] = set()
        used_acks: set[str] = set()
        attempts_seen: set[str] = set()
        for identifier, value in self.decisions.items():
            path = f"delivery_evidence_decisions[{identifier}]"
            self.check_commitment(value, path, "E15A2.DECISION.COMMITMENT")
            attempt_id = value.get("attempt")
            attempt = self.attempts.get(str(attempt_id))
            if attempt is None or value.get("attempt_revision") != attempt.get("revision"):
                self.add("error", "E15A2.DECISION.ATTEMPT", "decision attempt does not resolve exactly", path)
                continue
            if attempt_id in attempts_seen:
                self.add("error", "E15A2.DECISION.DUPLICATE", "attempt has more than one decision", path)
            attempts_seen.add(str(attempt_id))
            if not isinstance(value.get("sequence"), int) or value["sequence"] < 1:
                self.add("error", "E15A2.DECISION.SEQUENCE", "sequence must be positive", path)
            evidence_ids = self.string_list(value.get("delivery_evidence"), f"{path}.delivery_evidence", "E15A2.DECISION.EVIDENCE", allow_empty=True)
            ack_ids = self.string_list(value.get("acknowledgements"), f"{path}.acknowledgements", "E15A2.DECISION.ACK", allow_empty=True)
            evidence_items = [self.delivery_evidence[eid] for eid in evidence_ids if eid in self.delivery_evidence]
            ack_items = [self.acknowledgements[aid] for aid in ack_ids if aid in self.acknowledgements]
            if len(evidence_items) != len(evidence_ids) or len(ack_items) != len(ack_ids):
                self.add("error", "E15A2.DECISION.REF", "decision evidence or acknowledgement reference is unresolved", path)
                continue
            if any(item.get("attempt") != attempt_id for item in evidence_items + ack_items):
                self.add("error", "E15A2.DECISION.BINDING", "decision includes evidence from another attempt", path)
            used_evidence.update(evidence_ids)
            used_acks.update(ack_ids)
            policy = self.policies.get(str(attempt.get("attestation_policy")))
            if policy is None:
                self.add("error", "E15A2.DECISION.POLICY", "attempt policy does not resolve", path)
                continue
            evaluated = parse_time(value.get("evaluated_at"))
            if evaluated is None:
                self.add("error", "E15A2.DECISION.TIME", "evaluated_at must be UTC RFC3339", path)
                continue
            binding_gate = combine_gates(
                [self.attempt_binding.get(str(attempt_id), "deny")]
                + [self.evidence_binding.get(eid, "deny") for eid in evidence_ids]
                + [self.ack_binding.get(aid, "deny") for aid in ack_ids]
            )
            attester_gate = combine_gates(
                [self.evidence_attester.get(eid, "deny") for eid in evidence_ids]
                + [self.ack_attester.get(aid, "deny") for aid in ack_ids]
                or ["permit"]
            )
            freshness_gate = combine_gates([
                self.freshness_gate(evidence_items, evaluated, policy, False),
                self.freshness_gate(ack_items, evaluated, policy, True),
            ])
            evidence_states = [str(item.get("evidence_state")) for item in evidence_items]
            ack_states = [str(item.get("evidence_state")) for item in ack_items]
            delivery_gate = self.evidence_gate(evidence_states, required=True)
            ack_required = policy.get("acknowledgement_requirement") == "required"
            acknowledgement_gate = self.evidence_gate(ack_states, required=ack_required)
            gates = {
                "binding_result": binding_gate,
                "attester_result": attester_gate,
                "freshness_result": freshness_gate,
                "delivery_evidence_result": delivery_gate,
                "acknowledgement_result": acknowledgement_gate,
            }
            expected_state = self.derive_lifecycle(attempt, gates, evidence_states, ack_states)
            for field, expected in gates.items():
                if value.get(field) not in GATE_STATES or value.get(field) != expected:
                    self.add("error", "E15A2.DECISION.GATE", f"{field} must be {expected}", path)
            if value.get("lifecycle_state") not in LIFECYCLE_STATES or value.get("lifecycle_state") != expected_state:
                self.add("error", "E15A2.DECISION.STATE", f"lifecycle_state must be {expected_state}", path)
            self.string_list(value.get("reasons"), f"{path}.reasons", "E15A2.DECISION.REASONS")
            self.string_list(value.get("evidence_refs"), f"{path}.evidence_refs", "E15A2.DECISION.REFS")
            if not any(f.severity == "error" and f.path == path for f in self.findings):
                self.valid_decisions.add(identifier)
                self.derived_states[identifier] = expected_state
        for identifier in sorted(set(self.delivery_evidence) - used_evidence):
            self.add("error", "E15A2.EVIDENCE.ORPHAN", "delivery evidence is not consumed by a decision", identifier)
        for identifier in sorted(set(self.acknowledgements) - used_acks):
            self.add("error", "E15A2.ACK.ORPHAN", "acknowledgement is not consumed by a decision", identifier)
        for identifier in sorted(set(self.attempts) - attempts_seen):
            self.add("error", "E15A2.ATTEMPT.UNDECIDED", "attempt has no delivery-evidence decision", identifier)

    def validate_freeze(self, freeze: dict[str, Any] | None) -> str:
        if freeze is None:
            return "non-conformant"
        path = self.freeze_path.as_posix()
        if freeze.get("standard") != FREEZE_STANDARD or freeze.get("status") != "frozen" or freeze.get("profile_revision") != PROFILE_REVISION:
            self.add("error", "E15A2.FREEZE.HEADER", "unexpected authority freeze header", path)
        source = freeze.get("source")
        if not isinstance(source, dict) or source.get("e15_a1_head_commit") != SOURCE_E15_A1_HEAD:
            self.add("error", "E15A2.FREEZE.SOURCE", "authority freeze source mismatch", path)
        authorities = freeze.get("authorities")
        if not isinstance(authorities, list):
            self.add("error", "E15A2.FREEZE.TYPE", "authorities must be an array", path)
            return "non-conformant"
        indexed: dict[str, dict[str, Any]] = {}
        for pos, entry in enumerate(authorities):
            if not isinstance(entry, dict) or not self.nonempty(entry.get("path")):
                self.add("error", "E15A2.FREEZE.ITEM", "invalid authority entry", f"{path}[{pos}]")
                continue
            rel = entry["path"]
            if rel in indexed:
                self.add("error", "E15A2.FREEZE.DUPLICATE", "duplicate frozen path", rel)
                continue
            indexed[rel] = entry
            file_path = self.confined(rel, "E15A2.FREEZE", True)
            if file_path is None:
                continue
            raw = file_path.read_bytes()
            if entry.get("bytes") != len(raw):
                self.add("error", "E15A2.FREEZE.BYTES", "frozen byte length mismatch", rel)
            if entry.get("sha256") != hashlib.sha256(raw).hexdigest():
                self.add("error", "E15A2.FREEZE.DIGEST", "frozen SHA-256 mismatch", rel)
        for rel in sorted(EXPECTED_FREEZE_PATHS - set(indexed)):
            self.add("error", "E15A2.FREEZE.MISSING", "required E15-A2 authority is not frozen", rel)
        for rel in sorted(set(indexed) - EXPECTED_FREEZE_PATHS):
            self.add("error", "E15A2.FREEZE.EXTRA", "unexpected authority is frozen", rel)
        return "non-conformant" if any(f.code.startswith("E15A2.FREEZE") for f in self.findings) else "conformant"

    def run(self) -> dict[str, Any]:
        self.check_profile()
        history_result = self.check_history_report()
        self.check_transition(self.load_json(self.transition_path, "E15A2.TRANSITION"))
        self.load_parent()
        registry = self.load_json(self.registry_path, "E15A2.REGISTRY")
        freeze = self.load_json(self.freeze_path, "E15A2.FREEZE")
        if registry is not None:
            if registry.get("standard") != STANDARD or registry.get("status") != "structural-only" or registry.get("source_e15_a1_commit") != SOURCE_E15_A1_HEAD:
                self.add("error", "E15A2.REGISTRY.HEADER", "unexpected registry header", self.registry_path.as_posix())
            self.attesters = self.index(registry, "attester_profiles", "E15A2.ATTESTER")
            self.policies = self.index(registry, "external_attestation_policies", "E15A2.POLICY")
            self.attempts = self.index(registry, "transfer_attempts", "E15A2.ATTEMPT")
            self.delivery_evidence = self.index(registry, "external_delivery_evidence", "E15A2.EVIDENCE")
            self.acknowledgements = self.index(registry, "recipient_acknowledgements", "E15A2.ACK")
            self.decisions = self.index(registry, "delivery_evidence_decisions", "E15A2.DECISION")
            self.validate_attesters()
            self.validate_policies()
            self.validate_attempts()
            self.validate_delivery_evidence()
            self.validate_acknowledgements()
            self.validate_decisions()
        freeze_result = self.validate_freeze(freeze)
        errors = any(f.severity == "error" for f in self.findings)
        result = "not-evaluated" if not self.attempts else (
            "conformant" if len(self.valid_decisions) == len(self.decisions) == len(self.attempts) and not errors else "non-conformant"
        )
        states = list(self.derived_states.values())
        return {
            "tool": "eigiib-delivery-evidence-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if errors else "conformant",
            "historical_continuity_result": history_result,
            "authority_freeze_result": freeze_result,
            "transfer_evidence_result": result,
            "attester_profile_count": len(self.attesters),
            "attestation_policy_count": len(self.policies),
            "transfer_attempt_count": len(self.attempts),
            "external_delivery_evidence_count": len(self.delivery_evidence),
            "recipient_acknowledgement_count": len(self.acknowledgements),
            "delivery_evidence_decision_count": len(self.decisions),
            "lifecycle_state_counts": {state: states.count(state) for state in sorted(LIFECYCLE_STATES)},
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--registry", default="conformance/delivery-evidence.json")
    parser.add_argument("--transition", default="conformance/e15-a2-adoption-transition.json")
    parser.add_argument("--freeze", default="conformance/e15-a2-authority-freeze.json")
    parser.add_argument("--parent-registry", default="conformance/delivery-intent.json")
    parser.add_argument("--history-report", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = Checker(
        Path(args.root), Path(args.registry), Path(args.transition), Path(args.freeze),
        Path(args.parent_registry), Path(args.history_report),
    ).run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
