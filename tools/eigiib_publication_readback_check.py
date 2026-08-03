#!/usr/bin/env python3
"""Static EIGIIB-E15-A3 publication, persistence and readback checker."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E15-A3-1.0"
TRANSITION_STANDARD = "EIGIIB-E15-A3-TRANSITION-1.0"
FREEZE_STANDARD = "EIGIIB-E15-A3-FREEZE-1.0"
HISTORY_STANDARD = "EIGIIB-E15-A3-HISTORICAL-E15-A2-REPLAY-1.0"
PROFILE_REVISION = "EIGIIB-E15-draft-1.2"
SOURCE_E15_A2_HEAD = "25988d80571f0f8d3587d976810a2dd8e0ce2328"
SOURCE_E15_A1_HEAD = "ca0dfde0efcee975ef4957f604d4954b6de07e01"
SOURCE_E14_HEAD = "472e14fbb3d92205eabf10438e90295e19125ea4"
PUBLICATION_ACTION = "eigiib:e15:publish"

GATE_STATES = {"permit", "deny", "held", "unavailable"}
EVIDENCE_STATES = {"positive", "negative", "contested", "unavailable"}
IDENTITY_STATES = {"verified", "rejected", "contested", "unavailable"}
POLICY_STATES = {"active", "retired", "contested", "unavailable"}
PUBLISHER_KINDS = {"registry", "object-store", "release-service", "content-addressed-store"}
OBSERVER_KINDS = {"independent-observer", "verifier-service", "recipient-interface"}
LOCATOR_KINDS = {"registry-reference", "release-asset", "object-key", "content-address"}
PUBLICATION_MECHANISMS = {"registry-push", "release-publication", "object-put", "content-addressed-publish"}
PUBLICATION_EVENTS = {"published", "rejected", "failed", "removed", "unknown"}
PERSISTENCE_EVENTS = {"present", "absent", "digest-mismatch", "unreachable", "unknown"}
READBACK_EVENTS = {"bytes-match", "digest-mismatch", "not-found", "unreachable", "unknown"}
INDEPENDENCE_DIMENSIONS = {"principal", "provider", "implementation", "process", "network-path"}
LIFECYCLE_STATES = {
    "not-published", "publication-observed", "persistence-observed", "independently-read-back",
    "rejected", "held", "contested", "unavailable",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_FREEZE_PATHS = {
    ".github/workflows/e15-a2-delivery-evidence.yml",
    ".github/workflows/e15-a3-publication-readback.yml",
    ".github/workflows/eigiib.yml",
    "EIGIIB.toml",
    "conformance/E15-A3-MANUAL-REVIEW.md",
    "conformance/delivery-evidence.json",
    "conformance/e15-a2-adoption-transition.json",
    "conformance/e15-a2-authority-freeze.json",
    "conformance/e15-a3-adoption-transition.json",
    "conformance/extension-graph.json",
    "conformance/publication-readback.json",
    "docs/E15-A3-HUMAN-MASTERY-GUIDE.md",
    "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
    "schemas/eigiib-e15-a3-adoption-transition.schema.json",
    "schemas/eigiib-e15-a3-authority-freeze.schema.json",
    "schemas/eigiib-e15-a3-publication-readback.schema.json",
    "tests/fixtures/e15-a3/expected-report.json",
    "tests/test_eigiib_delivery_evidence.py",
    "tests/test_eigiib_publication_readback.py",
    "tools/eigiib_historical_e15_a2_replay.py",
    "tools/eigiib_publication_readback_check.py",
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
        registry: Path = Path("conformance/publication-readback.json"),
        transition: Path = Path("conformance/e15-a3-adoption-transition.json"),
        freeze: Path = Path("conformance/e15-a3-authority-freeze.json"),
        parent_registry: Path = Path("conformance/delivery-evidence.json"),
        history_report: Path | None = None,
    ):
        self.root = root.resolve()
        self.registry_path = registry
        self.transition_path = transition
        self.freeze_path = freeze
        self.parent_registry_path = parent_registry
        self.history_report_path = history_report
        self.findings: list[Finding] = []
        self.parent_attempts: dict[str, dict[str, Any]] = {}
        self.parent_decisions: dict[str, dict[str, Any]] = {}
        self.publishers: dict[str, dict[str, Any]] = {}
        self.observers: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.publications: dict[str, dict[str, Any]] = {}
        self.persistence: dict[str, dict[str, Any]] = {}
        self.readbacks: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.publication_binding: dict[str, str] = {}
        self.publisher_gate: dict[str, str] = {}
        self.persistence_binding: dict[str, str] = {}
        self.persistence_observer: dict[str, str] = {}
        self.persistence_content: dict[str, str] = {}
        self.readback_binding: dict[str, str] = {}
        self.readback_observer: dict[str, str] = {}
        self.readback_content: dict[str, str] = {}
        self.readback_independence: dict[str, str] = {}
        self.valid_decisions: set[str] = set()
        self.derived_states: dict[str, str] = {}

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

    def check_auth(self, value: Any, path: str, code: str) -> str | None:
        if not isinstance(value, dict) or any(not self.nonempty(value.get(k)) for k in ("algorithm", "key_id", "signature_sha256")):
            self.add("error", code, "authentication binding is incomplete", path)
            return None
        if not HEX64.fullmatch(str(value.get("signature_sha256"))):
            self.add("error", code, "signature_sha256 must be lowercase hexadecimal SHA-256", path)
        return str(value.get("algorithm"))

    def check_profile(self) -> None:
        try:
            profile = tomllib.loads((self.root / "EIGIIB.toml").read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "E15A3.PROFILE.PARSE", str(exc), "EIGIIB.toml")
            return
        if "E15-1.0" not in profile.get("extensions", []):
            self.add("error", "E15A3.PROFILE.ADOPTION", "E15-1.0 must remain adopted", "EIGIIB.toml")
        if profile.get("revision") != PROFILE_REVISION:
            self.add("error", "E15A3.PROFILE.REVISION", f"revision must be {PROFILE_REVISION}", "EIGIIB.toml")
        expected = {
            "e15": "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
            "delivery_evidence": self.parent_registry_path.as_posix(),
            "e15_a2_transition": "conformance/e15-a2-adoption-transition.json",
            "e15_a2_authority_freeze": "conformance/e15-a2-authority-freeze.json",
            "publication_readback": self.registry_path.as_posix(),
            "e15_a3_transition": self.transition_path.as_posix(),
            "e15_a3_authority_freeze": self.freeze_path.as_posix(),
            "e15_a3_human_mastery": "docs/E15-A3-HUMAN-MASTERY-GUIDE.md",
        }
        authorities = profile.get("authorities", {})
        required = profile.get("required_authorities", [])
        for key, value in expected.items():
            if not isinstance(authorities, dict) or authorities.get(key) != value:
                self.add("error", "E15A3.PROFILE.AUTHORITY", f"authority {key} must bind {value}", "EIGIIB.toml")
            else:
                self.confined(value, "E15A3.PROFILE", True)
            if not isinstance(required, list) or key not in required:
                self.add("error", "E15A3.PROFILE.REQUIRED", f"required authority missing: {key}", "EIGIIB.toml")
        gates = profile.get("manual_gates", [])
        exact = ("complete", "e15", "conformance/E15-A3-MANUAL-REVIEW.md")
        matches = [g for g in gates if isinstance(g, dict) and g.get("id") == "e15-a3-publication-persistence-readback-review"] if isinstance(gates, list) else []
        if len(matches) != 1 or (matches[0].get("status"), matches[0].get("authority"), matches[0].get("attestation")) != exact:
            self.add("error", "E15A3.PROFILE.GATE", "E15-A3 manual gate is missing or inexact", "EIGIIB.toml")
        else:
            self.confined(exact[2], "E15A3.PROFILE", True)

    def check_history_report(self) -> str:
        if self.history_report_path is None:
            self.add("error", "E15A3.HISTORY.REPORT", "historical E15-A2 replay report is required", "")
            return "non-conformant"
        report = self.load_json(self.history_report_path, "E15A3.HISTORY")
        if report is None:
            return "non-conformant"
        if report.get("standard") != HISTORY_STANDARD or report.get("source_commit") != SOURCE_E15_A2_HEAD:
            self.add("error", "E15A3.HISTORY.HEADER", "historical E15-A2 replay header mismatch", self.history_report_path.as_posix())
        for field in ("ancestry_result", "historical_e14_result", "e15_a1_result", "e15_a2_result", "e15_a2_tests_result", "overall_result"):
            if report.get(field) != "conformant":
                self.add("error", "E15A3.HISTORY.COMPONENT", f"{field} is not conformant", self.history_report_path.as_posix())
        return "non-conformant" if any(f.code.startswith("E15A3.HISTORY") for f in self.findings) else "conformant"

    def check_transition(self, transition: dict[str, Any] | None) -> None:
        if transition is None:
            return
        path = self.transition_path.as_posix()
        if transition.get("standard") != TRANSITION_STANDARD or transition.get("status") != "adopted-e15-a3":
            self.add("error", "E15A3.TRANSITION.HEADER", "unexpected transition header", path)
        source = transition.get("source")
        exact_source = {
            "head_commit": SOURCE_E15_A2_HEAD,
            "profile_revision": "EIGIIB-E15-draft-1.1",
            "authority_freeze": "conformance/e15-a2-authority-freeze.json",
            "registry_authority": self.parent_registry_path.as_posix(),
            "checker": "tools/eigiib_delivery_evidence_check.py",
        }
        if not isinstance(source, dict) or any(source.get(k) != v for k, v in exact_source.items()):
            self.add("error", "E15A3.TRANSITION.SOURCE", "source E15-A2 authority mismatch", path)
        replay = transition.get("historical_replay")
        if not isinstance(replay, dict) or replay.get("mode") != "materialize-and-replay-exact-source-commit" or replay.get("tool") != "tools/eigiib_historical_e15_a2_replay.py":
            self.add("error", "E15A3.TRANSITION.REPLAY", "historical replay contract mismatch", path)
        target = transition.get("target")
        exact_target = {
            "slice": "E15-A3",
            "registry_authority": self.registry_path.as_posix(),
            "checker": "tools/eigiib_publication_readback_check.py",
            "authority_freeze": self.freeze_path.as_posix(),
            "profile_revision": PROFILE_REVISION,
        }
        if not isinstance(target, dict) or any(target.get(k) != v for k, v in exact_target.items()):
            self.add("error", "E15A3.TRANSITION.TARGET", "target E15-A3 authority mismatch", path)
        preservation = transition.get("historical_preservation")
        if (
            not isinstance(preservation, dict)
            or preservation.get("transition_is_additive") is not True
            or preservation.get("source_freeze_mutated") is not False
            or preservation.get("e15_a2_claims_rewritten") is not False
            or preservation.get("descendant_profile_frozen_separately") is not True
            or preservation.get("descendant_a2_test_profile_isolated") is not True
        ):
            self.add("error", "E15A3.TRANSITION.PRESERVATION", "historical preservation contract mismatch", path)

    def load_parent(self) -> None:
        parent = self.load_json(self.parent_registry_path, "E15A3.PARENT")
        if parent is None:
            return
        if parent.get("standard") != "EIGIIB-E15-A2-1.0" or parent.get("source_e15_a1_commit") != SOURCE_E15_A1_HEAD:
            self.add("error", "E15A3.PARENT.HEADER", "unexpected E15-A2 parent registry", self.parent_registry_path.as_posix())
        self.parent_attempts = self.index(parent, "transfer_attempts", "E15A3.PARENT.ATTEMPT")
        decisions = self.index(parent, "delivery_evidence_decisions", "E15A3.PARENT.DECISION")
        for identifier, decision in decisions.items():
            attempt = decision.get("attempt")
            if self.nonempty(attempt) and decision.get("lifecycle_state") == "externally-attested":
                self.parent_decisions[identifier] = decision

    def validate_profiles(self) -> None:
        for identifier, value in self.publishers.items():
            path = f"publisher_profiles[{identifier}]"
            self.check_commitment(value, path, "E15A3.PUBLISHER.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("kind") not in PUBLISHER_KINDS or value.get("identity_state") not in IDENTITY_STATES:
                self.add("error", "E15A3.PUBLISHER.SHAPE", "publisher revision, kind or identity state is invalid", path)
            for field in ("identity_authority", "principal_id", "provider_id", "implementation_id"):
                if not self.nonempty(value.get(field)):
                    self.add("error", "E15A3.PUBLISHER.IDENTITY", f"{field} is required", path)
            for field in ("locator_kinds", "publication_mechanisms", "authentication_algorithms"):
                self.string_list(value.get(field), f"{path}.{field}", "E15A3.PUBLISHER.LIST")
        for identifier, value in self.observers.items():
            path = f"readback_observer_profiles[{identifier}]"
            self.check_commitment(value, path, "E15A3.OBSERVER.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("kind") not in OBSERVER_KINDS or value.get("identity_state") not in IDENTITY_STATES:
                self.add("error", "E15A3.OBSERVER.SHAPE", "observer revision, kind or identity state is invalid", path)
            for field in ("identity_authority", "principal_id", "provider_id", "implementation_id"):
                if not self.nonempty(value.get(field)):
                    self.add("error", "E15A3.OBSERVER.IDENTITY", f"{field} is required", path)
            self.string_list(value.get("authentication_algorithms"), f"{path}.authentication_algorithms", "E15A3.OBSERVER.LIST")
        for identifier, value in self.policies.items():
            path = f"publication_policies[{identifier}]"
            self.check_commitment(value, path, "E15A3.POLICY.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("state") not in POLICY_STATES:
                self.add("error", "E15A3.POLICY.SHAPE", "policy revision or state is invalid", path)
            for field in ("allowed_publishers", "allowed_observers", "allowed_locator_kinds", "allowed_publication_mechanisms", "required_authentication_algorithms"):
                self.string_list(value.get(field), f"{path}.{field}", "E15A3.POLICY.LIST")
            dims = self.string_list(value.get("required_independence_dimensions"), f"{path}.required_independence_dimensions", "E15A3.POLICY.DIMENSIONS", allow_empty=True)
            if any(dim not in INDEPENDENCE_DIMENSIONS for dim in dims):
                self.add("error", "E15A3.POLICY.DIMENSIONS", "unknown independence dimension", path)
            if value.get("readback_requirement") not in {"required", "optional"}:
                self.add("error", "E15A3.POLICY.READBACK", "readback requirement must be required or optional", path)
            for field in ("max_publication_age_seconds", "min_observation_interval_seconds", "max_observation_age_seconds", "max_readback_age_seconds"):
                if not isinstance(value.get(field), int) or value[field] < 0:
                    self.add("error", "E15A3.POLICY.TIME", f"{field} must be a non-negative integer", path)
            if not isinstance(value.get("min_persistence_observations"), int) or value["min_persistence_observations"] < 1:
                self.add("error", "E15A3.POLICY.COUNT", "min_persistence_observations must be positive", path)

    def identity_gate(self, state: str) -> str:
        return state_gate(state, "verified", "rejected")

    def policy_gate(self, state: str) -> str:
        return state_gate(state, "active", "retired")

    def validate_publications(self) -> None:
        keys: dict[str, str] = {}
        sequences: set[tuple[str, int]] = set()
        for identifier, value in self.publications.items():
            path = f"external_publication_records[{identifier}]"
            self.check_commitment(value, path, "E15A3.PUBLICATION.COMMITMENT")
            required = (
                "revision", "source_attempt", "source_attempt_revision", "source_delivery_decision",
                "source_delivery_decision_commitment_sha256", "publisher", "publisher_revision", "policy",
                "policy_revision", "publication_idempotency_key", "locator", "locator_kind",
                "publication_mechanism", "payload_sha256", "issued_at", "valid_until", "process_id",
                "network_path_id", "source_reference",
            )
            if any(not self.nonempty(value.get(field)) for field in required):
                self.add("error", "E15A3.PUBLICATION.SHAPE", "publication string fields are incomplete", path)
            if value.get("locator_kind") not in LOCATOR_KINDS or value.get("publication_mechanism") not in PUBLICATION_MECHANISMS:
                self.add("error", "E15A3.PUBLICATION.KIND", "locator kind or publication mechanism is invalid", path)
            if value.get("publication_state") not in EVIDENCE_STATES or value.get("observed_event") not in PUBLICATION_EVENTS:
                self.add("error", "E15A3.PUBLICATION.STATE", "publication state or event is invalid", path)
            if value.get("publication_state") == "positive" and value.get("observed_event") != "published":
                self.add("error", "E15A3.PUBLICATION.COHERENCE", "positive publication requires published event", path)
            if value.get("publication_state") == "negative" and value.get("observed_event") not in {"rejected", "failed", "removed"}:
                self.add("error", "E15A3.PUBLICATION.COHERENCE", "negative publication requires rejected, failed or removed event", path)
            if not HEX64.fullmatch(str(value.get("payload_sha256", ""))) or not HEX64.fullmatch(str(value.get("source_delivery_decision_commitment_sha256", ""))):
                self.add("error", "E15A3.PUBLICATION.DIGEST", "publication digests must be lowercase hexadecimal SHA-256", path)
            if not isinstance(value.get("payload_bytes"), int) or value["payload_bytes"] < 0:
                self.add("error", "E15A3.PUBLICATION.PAYLOAD", "payload_bytes must be non-negative", path)
            if not isinstance(value.get("publication_sequence"), int) or value["publication_sequence"] < 1:
                self.add("error", "E15A3.PUBLICATION.SEQUENCE", "publication_sequence must be positive", path)
            for field in ("issued_at", "valid_until"):
                if parse_time(value.get(field)) is None:
                    self.add("error", "E15A3.PUBLICATION.TIME", f"{field} must be UTC RFC3339", path)
            algorithm = self.check_auth(value.get("authentication"), path, "E15A3.PUBLICATION.AUTH")
            key = str(value.get("publication_idempotency_key"))
            if self.nonempty(key):
                if key in keys:
                    self.add("error", "E15A3.PUBLICATION.IDEMPOTENCY", f"publication idempotency key already used by {keys[key]}", path)
                keys[key] = identifier
            seq = (str(value.get("source_attempt")), value.get("publication_sequence"))
            if isinstance(seq[1], int):
                if seq in sequences:
                    self.add("error", "E15A3.PUBLICATION.SEQUENCE", "publication sequence is duplicated for source attempt", path)
                sequences.add(seq)
            attempt = self.parent_attempts.get(str(value.get("source_attempt")))
            decision = self.parent_decisions.get(str(value.get("source_delivery_decision")))
            publisher = self.publishers.get(str(value.get("publisher")))
            policy = self.policies.get(str(value.get("policy")))
            binding = "permit"
            if attempt is None or decision is None or decision.get("attempt") != value.get("source_attempt"):
                binding = "deny"
            elif attempt.get("revision") != value.get("source_attempt_revision"):
                binding = "deny"
            elif attempt.get("payload_sha256") != value.get("payload_sha256") or attempt.get("payload_bytes") != value.get("payload_bytes"):
                binding = "deny"
            else:
                digest = ((decision.get("commitment") or {}).get("digest") if isinstance(decision.get("commitment"), dict) else None)
                if digest != value.get("source_delivery_decision_commitment_sha256"):
                    binding = "deny"
            if publisher is None or publisher.get("revision") != value.get("publisher_revision"):
                binding = "deny"
            if policy is None or policy.get("revision") != value.get("policy_revision"):
                binding = "deny"
            self.publication_binding[identifier] = binding
            gates = ["deny"] if publisher is None or policy is None else [
                self.identity_gate(str(publisher.get("identity_state"))),
                self.policy_gate(str(policy.get("state"))),
            ]
            if publisher is not None and policy is not None:
                if identifier and value.get("publisher") not in policy.get("allowed_publishers", []):
                    gates.append("deny")
                if value.get("locator_kind") not in publisher.get("locator_kinds", []) or value.get("locator_kind") not in policy.get("allowed_locator_kinds", []):
                    gates.append("deny")
                if value.get("publication_mechanism") not in publisher.get("publication_mechanisms", []) or value.get("publication_mechanism") not in policy.get("allowed_publication_mechanisms", []):
                    gates.append("deny")
                if algorithm not in publisher.get("authentication_algorithms", []) or algorithm not in policy.get("required_authentication_algorithms", []):
                    gates.append("deny")
            self.publisher_gate[identifier] = combine_gates(gates)

    def observer_auth_gate(self, value: dict[str, Any], observer: dict[str, Any] | None, policy: dict[str, Any] | None, path: str) -> str:
        algorithm = self.check_auth(value.get("authentication"), path, "E15A3.OBSERVATION.AUTH")
        if observer is None or policy is None:
            return "deny"
        gates = [self.identity_gate(str(observer.get("identity_state"))), self.policy_gate(str(policy.get("state")))]
        if value.get("observer") not in policy.get("allowed_observers", []):
            gates.append("deny")
        if algorithm not in observer.get("authentication_algorithms", []) or algorithm not in policy.get("required_authentication_algorithms", []):
            gates.append("deny")
        return combine_gates(gates)

    def validate_persistence(self) -> None:
        for identifier, value in self.persistence.items():
            path = f"bounded_persistence_observations[{identifier}]"
            self.check_commitment(value, path, "E15A3.PERSISTENCE.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("observation_state") not in EVIDENCE_STATES or value.get("observed_event") not in PERSISTENCE_EVENTS:
                self.add("error", "E15A3.PERSISTENCE.SHAPE", "observation revision, state or event is invalid", path)
            if value.get("observation_state") == "positive" and value.get("observed_event") != "present":
                self.add("error", "E15A3.PERSISTENCE.COHERENCE", "positive observation requires present event", path)
            if value.get("observation_state") == "negative" and value.get("observed_event") not in {"absent", "digest-mismatch"}:
                self.add("error", "E15A3.PERSISTENCE.COHERENCE", "negative observation requires absent or digest-mismatch event", path)
            for field in ("observed_at", "valid_until"):
                if parse_time(value.get(field)) is None:
                    self.add("error", "E15A3.PERSISTENCE.TIME", f"{field} must be UTC RFC3339", path)
            publication = self.publications.get(str(value.get("publication")))
            observer = self.observers.get(str(value.get("observer")))
            policy = self.policies.get(str(publication.get("policy"))) if publication else None
            binding = "permit"
            content = "permit"
            if publication is None or value.get("publication_revision") != publication.get("revision"):
                binding = "deny"
            else:
                if value.get("locator") != publication.get("locator"):
                    binding = "deny"
                if value.get("payload_sha256") != publication.get("payload_sha256"):
                    content = "deny"
            if observer is None or value.get("observer_revision") != observer.get("revision"):
                binding = "deny"
            self.persistence_binding[identifier] = binding
            self.persistence_content[identifier] = content
            self.persistence_observer[identifier] = self.observer_auth_gate(value, observer, policy, path)

    def validate_readbacks(self) -> None:
        for identifier, value in self.readbacks.items():
            path = f"independent_readbacks[{identifier}]"
            self.check_commitment(value, path, "E15A3.READBACK.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("readback_state") not in EVIDENCE_STATES or value.get("observed_event") not in READBACK_EVENTS:
                self.add("error", "E15A3.READBACK.SHAPE", "readback revision, state or event is invalid", path)
            if value.get("readback_state") == "positive" and value.get("observed_event") != "bytes-match":
                self.add("error", "E15A3.READBACK.COHERENCE", "positive readback requires bytes-match event", path)
            if value.get("readback_state") == "negative" and value.get("observed_event") not in {"digest-mismatch", "not-found"}:
                self.add("error", "E15A3.READBACK.COHERENCE", "negative readback requires digest-mismatch or not-found event", path)
            for field in ("read_at", "valid_until"):
                if parse_time(value.get(field)) is None:
                    self.add("error", "E15A3.READBACK.TIME", f"{field} must be UTC RFC3339", path)
            if not isinstance(value.get("bytes_read"), int) or value["bytes_read"] < 0:
                self.add("error", "E15A3.READBACK.BYTES", "bytes_read must be non-negative", path)
            publication = self.publications.get(str(value.get("publication")))
            observer = self.observers.get(str(value.get("observer")))
            publisher = self.publishers.get(str(publication.get("publisher"))) if publication else None
            policy = self.policies.get(str(publication.get("policy"))) if publication else None
            binding = "permit"
            content = "permit"
            if publication is None or value.get("publication_revision") != publication.get("revision"):
                binding = "deny"
            else:
                if value.get("locator") != publication.get("locator"):
                    binding = "deny"
                if value.get("payload_sha256") != publication.get("payload_sha256"):
                    content = "deny"
                if value.get("readback_state") == "positive" and value.get("bytes_read") != publication.get("payload_bytes"):
                    content = "deny"
            if observer is None or value.get("observer_revision") != observer.get("revision"):
                binding = "deny"
            self.readback_binding[identifier] = binding
            self.readback_content[identifier] = content
            self.readback_observer[identifier] = self.observer_auth_gate(value, observer, policy, path)
            independence = "permit"
            if publication is None or observer is None or publisher is None or policy is None:
                independence = "deny"
            else:
                comparisons = {
                    "principal": observer.get("principal_id") != publisher.get("principal_id"),
                    "provider": observer.get("provider_id") != publisher.get("provider_id"),
                    "implementation": observer.get("implementation_id") != publisher.get("implementation_id"),
                    "process": value.get("process_id") != publication.get("process_id"),
                    "network-path": value.get("network_path_id") != publication.get("network_path_id"),
                }
                if any(not comparisons.get(dim, False) for dim in policy.get("required_independence_dimensions", [])):
                    independence = "deny"
            self.readback_independence[identifier] = independence

    def freshness_gate(self, item: dict[str, Any], evaluated: datetime, issued_field: str, max_age: int) -> str:
        issued = parse_time(item.get(issued_field))
        valid_until = parse_time(item.get("valid_until"))
        if issued is None or valid_until is None:
            return "deny"
        if issued > evaluated or evaluated > valid_until or (evaluated - issued).total_seconds() > max_age:
            return "deny"
        return "permit"

    def persistence_gate(self, items: list[dict[str, Any]], policy: dict[str, Any]) -> str:
        states = [str(item.get("observation_state")) for item in items]
        if "negative" in states:
            return "deny"
        if "unavailable" in states:
            return "unavailable"
        if "contested" in states:
            return "held"
        positive = sorted((parse_time(item.get("observed_at")) for item in items if item.get("observation_state") == "positive"), key=lambda x: x or datetime.min.replace(tzinfo=timezone.utc))
        if len(positive) < int(policy.get("min_persistence_observations", 1)):
            return "held"
        interval = int(policy.get("min_observation_interval_seconds", 0))
        if any(a is None or b is None or (b - a).total_seconds() < interval for a, b in zip(positive, positive[1:])):
            return "deny"
        return "permit"

    def evidence_gate(self, states: list[str], required: bool) -> str:
        if not states:
            return "held" if required else "permit"
        if "negative" in states:
            return "deny"
        if "unavailable" in states:
            return "unavailable"
        if "contested" in states:
            return "held"
        return "permit"

    def derive_lifecycle(self, publication: dict[str, Any], gates: dict[str, str], persistence_states: list[str], readback_states: list[str], has_positive_readback: bool) -> str:
        values = list(gates.values())
        if "deny" in values or publication.get("publication_state") == "negative" or "negative" in persistence_states or "negative" in readback_states:
            return "rejected"
        if publication.get("publication_state") == "contested" or "contested" in persistence_states or "contested" in readback_states:
            return "contested"
        if "unavailable" in values or publication.get("publication_state") == "unavailable" or "unavailable" in persistence_states or "unavailable" in readback_states:
            return "unavailable"
        if publication.get("publication_state") != "positive":
            return "not-published"
        blocking = ("binding_result", "publisher_result", "observer_result", "freshness_result", "publication_result")
        if any(gates[name] == "held" for name in blocking):
            return "held"
        if gates["persistence_result"] != "permit":
            return "publication-observed"
        if has_positive_readback and gates["readback_result"] == gates["independence_result"] == gates["content_identity_result"] == "permit":
            return "independently-read-back"
        if gates["persistence_result"] == "permit":
            return "persistence-observed"
        if "held" in values:
            return "held"
        return "publication-observed"

    def validate_decisions(self) -> None:
        used_persistence: set[str] = set()
        used_readbacks: set[str] = set()
        publications_seen: set[str] = set()
        for identifier, value in self.decisions.items():
            path = f"publication_lifecycle_decisions[{identifier}]"
            self.check_commitment(value, path, "E15A3.DECISION.COMMITMENT")
            publication_id = str(value.get("publication"))
            publication = self.publications.get(publication_id)
            if publication is None or value.get("publication_revision") != publication.get("revision"):
                self.add("error", "E15A3.DECISION.PUBLICATION", "decision publication does not resolve exactly", path)
                continue
            if publication_id in publications_seen:
                self.add("error", "E15A3.DECISION.DUPLICATE", "publication has more than one decision", path)
            publications_seen.add(publication_id)
            if not isinstance(value.get("sequence"), int) or value["sequence"] < 1:
                self.add("error", "E15A3.DECISION.SEQUENCE", "decision sequence must be positive", path)
            persistence_ids = self.string_list(value.get("persistence_observations"), f"{path}.persistence_observations", "E15A3.DECISION.PERSISTENCE", allow_empty=True)
            readback_ids = self.string_list(value.get("independent_readbacks"), f"{path}.independent_readbacks", "E15A3.DECISION.READBACK", allow_empty=True)
            if used_persistence.intersection(persistence_ids) or used_readbacks.intersection(readback_ids):
                self.add("error", "E15A3.DECISION.REUSE", "observation or readback is consumed more than once", path)
            used_persistence.update(persistence_ids)
            used_readbacks.update(readback_ids)
            persistence_items = [self.persistence[x] for x in persistence_ids if x in self.persistence]
            readback_items = [self.readbacks[x] for x in readback_ids if x in self.readbacks]
            if len(persistence_items) != len(persistence_ids) or len(readback_items) != len(readback_ids):
                self.add("error", "E15A3.DECISION.REF", "decision contains unresolved observation or readback", path)
            if any(item.get("publication") != publication_id for item in persistence_items + readback_items):
                self.add("error", "E15A3.DECISION.BINDING", "decision evidence belongs to another publication", path)
            policy = self.policies.get(str(publication.get("policy")))
            if policy is None:
                self.add("error", "E15A3.DECISION.POLICY", "publication policy does not resolve", path)
                continue
            evaluated = parse_time(value.get("evaluated_at"))
            if evaluated is None:
                self.add("error", "E15A3.DECISION.TIME", "evaluated_at must be UTC RFC3339", path)
                continue
            binding = combine_gates(
                [self.publication_binding.get(publication_id, "deny")]
                + [self.persistence_binding.get(x, "deny") for x in persistence_ids]
                + [self.readback_binding.get(x, "deny") for x in readback_ids]
            )
            publisher_result = self.publisher_gate.get(publication_id, "deny")
            observer_result = combine_gates(
                [self.persistence_observer.get(x, "deny") for x in persistence_ids]
                + [self.readback_observer.get(x, "deny") for x in readback_ids]
                or ["permit"]
            )
            freshness_values = [self.freshness_gate(publication, evaluated, "issued_at", int(policy.get("max_publication_age_seconds", 0)))]
            freshness_values += [self.freshness_gate(item, evaluated, "observed_at", int(policy.get("max_observation_age_seconds", 0))) for item in persistence_items]
            freshness_values += [self.freshness_gate(item, evaluated, "read_at", int(policy.get("max_readback_age_seconds", 0))) for item in readback_items]
            freshness = combine_gates(freshness_values)
            publication_result = state_gate(str(publication.get("publication_state")), "positive", "negative")
            persistence_result = self.persistence_gate(persistence_items, policy)
            readback_states = [str(item.get("readback_state")) for item in readback_items]
            readback_result = self.evidence_gate(readback_states, policy.get("readback_requirement") == "required")
            independence_result = combine_gates([self.readback_independence.get(x, "deny") for x in readback_ids] or (["held"] if policy.get("readback_requirement") == "required" else ["permit"]))
            content_identity = combine_gates(
                [self.persistence_content.get(x, "deny") for x in persistence_ids]
                + [self.readback_content.get(x, "deny") for x in readback_ids]
                or ["permit"]
            )
            gates = {
                "binding_result": binding,
                "publisher_result": publisher_result,
                "observer_result": observer_result,
                "freshness_result": freshness,
                "publication_result": publication_result,
                "persistence_result": persistence_result,
                "readback_result": readback_result,
                "independence_result": independence_result,
                "content_identity_result": content_identity,
            }
            persistence_states = [str(item.get("observation_state")) for item in persistence_items]
            has_positive_readback = any(state == "positive" for state in readback_states)
            expected_state = self.derive_lifecycle(publication, gates, persistence_states, readback_states, has_positive_readback)
            for field, expected in gates.items():
                if value.get(field) not in GATE_STATES or value.get(field) != expected:
                    self.add("error", "E15A3.DECISION.GATE", f"{field} must be {expected}", path)
            if value.get("lifecycle_state") not in LIFECYCLE_STATES or value.get("lifecycle_state") != expected_state:
                self.add("error", "E15A3.DECISION.STATE", f"lifecycle_state must be {expected_state}", path)
            self.string_list(value.get("reasons"), f"{path}.reasons", "E15A3.DECISION.REASONS")
            self.string_list(value.get("evidence_refs"), f"{path}.evidence_refs", "E15A3.DECISION.EVIDENCE")
            if not any(f.severity == "error" and f.path == path for f in self.findings):
                self.valid_decisions.add(identifier)
                self.derived_states[identifier] = expected_state
        for identifier in sorted(set(self.persistence) - used_persistence):
            self.add("error", "E15A3.PERSISTENCE.ORPHAN", "persistence observation is not consumed by a decision", identifier)
        for identifier in sorted(set(self.readbacks) - used_readbacks):
            self.add("error", "E15A3.READBACK.ORPHAN", "readback is not consumed by a decision", identifier)
        for identifier in sorted(set(self.publications) - publications_seen):
            self.add("error", "E15A3.PUBLICATION.UNDECIDED", "publication has no lifecycle decision", identifier)

    def validate_freeze(self, freeze: dict[str, Any] | None) -> str:
        if freeze is None:
            return "non-conformant"
        path = self.freeze_path.as_posix()
        if freeze.get("standard") != FREEZE_STANDARD or freeze.get("status") != "frozen" or freeze.get("profile_revision") != PROFILE_REVISION:
            self.add("error", "E15A3.FREEZE.HEADER", "unexpected authority freeze header", path)
        source = freeze.get("source")
        if not isinstance(source, dict) or source.get("e15_a2_head_commit") != SOURCE_E15_A2_HEAD:
            self.add("error", "E15A3.FREEZE.SOURCE", "authority freeze source mismatch", path)
        authorities = freeze.get("authorities")
        if not isinstance(authorities, list):
            self.add("error", "E15A3.FREEZE.TYPE", "authorities must be an array", path)
            return "non-conformant"
        indexed: dict[str, dict[str, Any]] = {}
        for pos, entry in enumerate(authorities):
            if not isinstance(entry, dict) or not self.nonempty(entry.get("path")):
                self.add("error", "E15A3.FREEZE.ITEM", "invalid authority entry", f"{path}[{pos}]")
                continue
            rel = entry["path"]
            if rel in indexed:
                self.add("error", "E15A3.FREEZE.DUPLICATE", "duplicate frozen path", rel)
                continue
            indexed[rel] = entry
            file_path = self.confined(rel, "E15A3.FREEZE", True)
            if file_path is None:
                continue
            raw = file_path.read_bytes()
            if entry.get("bytes") != len(raw):
                self.add("error", "E15A3.FREEZE.BYTES", "frozen byte length mismatch", rel)
            if entry.get("sha256") != hashlib.sha256(raw).hexdigest():
                self.add("error", "E15A3.FREEZE.DIGEST", "frozen SHA-256 mismatch", rel)
        for rel in sorted(EXPECTED_FREEZE_PATHS - set(indexed)):
            self.add("error", "E15A3.FREEZE.MISSING", "required E15-A3 authority is not frozen", rel)
        for rel in sorted(set(indexed) - EXPECTED_FREEZE_PATHS):
            self.add("error", "E15A3.FREEZE.EXTRA", "unexpected authority is frozen", rel)
        return "non-conformant" if any(f.code.startswith("E15A3.FREEZE") for f in self.findings) else "conformant"

    def run(self) -> dict[str, Any]:
        self.check_profile()
        history_result = self.check_history_report()
        self.check_transition(self.load_json(self.transition_path, "E15A3.TRANSITION"))
        self.load_parent()
        registry = self.load_json(self.registry_path, "E15A3.REGISTRY")
        freeze = self.load_json(self.freeze_path, "E15A3.FREEZE")
        if registry is not None:
            if registry.get("standard") != STANDARD or registry.get("status") != "structural-only" or registry.get("source_e15_a2_commit") != SOURCE_E15_A2_HEAD:
                self.add("error", "E15A3.REGISTRY.HEADER", "unexpected registry header", self.registry_path.as_posix())
            self.publishers = self.index(registry, "publisher_profiles", "E15A3.PUBLISHER")
            self.observers = self.index(registry, "readback_observer_profiles", "E15A3.OBSERVER")
            self.policies = self.index(registry, "publication_policies", "E15A3.POLICY")
            self.publications = self.index(registry, "external_publication_records", "E15A3.PUBLICATION")
            self.persistence = self.index(registry, "bounded_persistence_observations", "E15A3.PERSISTENCE")
            self.readbacks = self.index(registry, "independent_readbacks", "E15A3.READBACK")
            self.decisions = self.index(registry, "publication_lifecycle_decisions", "E15A3.DECISION")
            self.validate_profiles()
            self.validate_publications()
            self.validate_persistence()
            self.validate_readbacks()
            self.validate_decisions()
        freeze_result = self.validate_freeze(freeze)
        errors = any(f.severity == "error" for f in self.findings)
        result = "not-evaluated" if not self.publications else (
            "conformant" if len(self.valid_decisions) == len(self.decisions) == len(self.publications) and not errors else "non-conformant"
        )
        states = list(self.derived_states.values())
        return {
            "tool": "eigiib-publication-readback-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if errors else "conformant",
            "historical_continuity_result": history_result,
            "authority_freeze_result": freeze_result,
            "publication_readback_result": result,
            "publisher_profile_count": len(self.publishers),
            "readback_observer_profile_count": len(self.observers),
            "publication_policy_count": len(self.policies),
            "external_publication_record_count": len(self.publications),
            "bounded_persistence_observation_count": len(self.persistence),
            "independent_readback_count": len(self.readbacks),
            "publication_lifecycle_decision_count": len(self.decisions),
            "lifecycle_state_counts": {state: states.count(state) for state in sorted(LIFECYCLE_STATES)},
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--registry", default="conformance/publication-readback.json")
    parser.add_argument("--transition", default="conformance/e15-a3-adoption-transition.json")
    parser.add_argument("--freeze", default="conformance/e15-a3-authority-freeze.json")
    parser.add_argument("--parent-registry", default="conformance/delivery-evidence.json")
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
