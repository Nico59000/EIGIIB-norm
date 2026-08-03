#!/usr/bin/env python3
"""Static EIGIIB-E15-A4 withdrawal, tombstone and post-withdrawal checker."""
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
STANDARD = "EIGIIB-E15-A4-1.0"
TRANSITION_STANDARD = "EIGIIB-E15-A4-TRANSITION-1.0"
FREEZE_STANDARD = "EIGIIB-E15-A4-FREEZE-1.0"
HISTORY_STANDARD = "EIGIIB-E15-A4-HISTORICAL-E15-A3-REPLAY-1.0"
PROFILE_REVISION = "EIGIIB-E15-draft-1.3"
FINAL_PROFILE_REVISION = "EIGIIB-E15-1.0"
SOURCE_E15_A3_HEAD = "f403e93dd6d1dcb058474d67f2cc7e73b8ad13bd"
SOURCE_E15_A2_HEAD = "25988d80571f0f8d3587d976810a2dd8e0ce2328"
WITHDRAWAL_ACTION = "eigiib:e15:withdraw"

GATE_STATES = {"permit", "deny", "held", "unavailable"}
EVIDENCE_STATES = {"positive", "negative", "contested", "unavailable"}
IDENTITY_STATES = {"verified", "rejected", "contested", "unavailable"}
POLICY_STATES = {"active", "retired", "contested", "unavailable"}
AUTHORITY_KINDS = {"governance-authority", "content-controller", "release-governor"}
OPERATOR_KINDS = {"registry-operator", "distribution-operator", "publication-operator"}
TARGET_KINDS = {"registry", "object-store", "release-service", "content-addressed-store"}
LOCATOR_KINDS = {"registry-reference", "release-asset", "object-key", "content-address"}
STOP_MECHANISMS = {
    "registry-tombstone", "release-unpublish", "object-delete-marker",
    "distribution-block", "content-address-denylist",
}
REQUEST_EVENTS = {"requested", "rejected", "cancelled", "unknown"}
TOMBSTONE_EVENTS = {"installed", "removed", "rejected", "unknown"}
STOP_EVENTS = {"stopped", "resumed", "failed", "unknown"}
POST_EVENTS = {"tombstone-visible", "not-found", "still-available", "digest-mismatch", "unreachable", "unknown"}
PUBLISHED_PARENT_STATES = {"publication-observed", "persistence-observed", "independently-read-back"}
LIFECYCLE_STATES = {
    "withdrawal-requested", "tombstoned", "distribution-stopped", "post-withdrawal-observed",
    "rejected", "held", "contested", "unavailable",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_FREEZE_PATHS = {
    ".github/workflows/e15-a3-publication-readback.yml",
    ".github/workflows/e15-a4-withdrawal-governance.yml",
    ".github/workflows/eigiib.yml",
    "EIGIIB.toml",
    "conformance/E15-A4-MANUAL-REVIEW.md",
    "conformance/e15-a3-adoption-transition.json",
    "conformance/e15-a3-authority-freeze.json",
    "conformance/e15-a4-adoption-transition.json",
    "conformance/extension-graph.json",
    "conformance/publication-readback.json",
    "conformance/withdrawal-governance.json",
    "docs/E15-A4-HUMAN-MASTERY-GUIDE.md",
    "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
    "schemas/eigiib-e15-a4-adoption-transition.schema.json",
    "schemas/eigiib-e15-a4-authority-freeze.schema.json",
    "schemas/eigiib-e15-a4-withdrawal-governance.schema.json",
    "tests/fixtures/e15-a4/expected-report.json",
    "tests/test_eigiib_publication_readback.py",
    "tests/test_eigiib_withdrawal_governance.py",
    "tools/eigiib_historical_e15_a3_replay.py",
    "tools/eigiib_withdrawal_governance_check.py",
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


def state_gate(state: str) -> str:
    if state == "positive":
        return "permit"
    if state == "negative":
        return "deny"
    if state == "unavailable":
        return "unavailable"
    return "held"


class Checker:
    def __init__(
        self,
        root: Path,
        registry: Path = Path("conformance/withdrawal-governance.json"),
        transition: Path = Path("conformance/e15-a4-adoption-transition.json"),
        freeze: Path = Path("conformance/e15-a4-authority-freeze.json"),
        parent_registry: Path = Path("conformance/publication-readback.json"),
        history_report: Path | None = None,
    ):
        self.root = root.resolve()
        self.registry_path = registry
        self.transition_path = transition
        self.freeze_path = freeze
        self.parent_registry_path = parent_registry
        self.history_report_path = history_report
        self.findings: list[Finding] = []

        self.parent_publications: dict[str, dict[str, Any]] = {}
        self.parent_decisions: dict[str, dict[str, Any]] = {}
        self.parent_observers: dict[str, dict[str, Any]] = {}

        self.authorities: dict[str, dict[str, Any]] = {}
        self.operators: dict[str, dict[str, Any]] = {}
        self.targets: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.requests: dict[str, dict[str, Any]] = {}
        self.tombstones: dict[str, dict[str, Any]] = {}
        self.stops: dict[str, dict[str, Any]] = {}
        self.observations: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}

        self.request_binding: dict[str, str] = {}
        self.request_authority: dict[str, str] = {}
        self.request_policy: dict[str, str] = {}
        self.request_content: dict[str, str] = {}
        self.tombstone_binding: dict[str, str] = {}
        self.tombstone_operator: dict[str, str] = {}
        self.tombstone_content: dict[str, str] = {}
        self.stop_binding: dict[str, str] = {}
        self.stop_operator: dict[str, str] = {}
        self.stop_content: dict[str, str] = {}
        self.observation_binding: dict[str, str] = {}
        self.observation_observer: dict[str, str] = {}
        self.observation_content: dict[str, str] = {}
        self.latest_tombstone: dict[tuple[str, str], str] = {}
        self.latest_stop: dict[tuple[str, str], str] = {}
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
            out[str(identifier)] = value
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
        return [str(item) for item in value]

    def positive_int(self, value: Any, path: str, code: str, allow_zero: bool = False) -> int | None:
        minimum = 0 if allow_zero else 1
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            self.add("error", code, f"must be an integer >= {minimum}", path)
            return None
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
            self.add("error", "E15A4.PROFILE.PARSE", str(exc), "EIGIIB.toml")
            return
        if "E15-1.0" not in profile.get("extensions", []):
            self.add("error", "E15A4.PROFILE.ADOPTION", "E15-1.0 must remain adopted", "EIGIIB.toml")
        if profile.get("revision") not in {PROFILE_REVISION, FINAL_PROFILE_REVISION}:
            self.add("error", "E15A4.PROFILE.REVISION", f"revision must be {PROFILE_REVISION} or {FINAL_PROFILE_REVISION}", "EIGIIB.toml")
        expected = {
            "e15": "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
            "publication_readback": self.parent_registry_path.as_posix(),
            "e15_a3_transition": "conformance/e15-a3-adoption-transition.json",
            "e15_a3_authority_freeze": "conformance/e15-a3-authority-freeze.json",
            "withdrawal_governance": self.registry_path.as_posix(),
            "e15_a4_transition": self.transition_path.as_posix(),
            "e15_a4_authority_freeze": self.freeze_path.as_posix(),
            "e15_a4_human_mastery": "docs/E15-A4-HUMAN-MASTERY-GUIDE.md",
        }
        authorities = profile.get("authorities", {})
        required = profile.get("required_authorities", [])
        for key, value in expected.items():
            if not isinstance(authorities, dict) or authorities.get(key) != value:
                self.add("error", "E15A4.PROFILE.AUTHORITY", f"authority {key} must bind {value}", "EIGIIB.toml")
            else:
                self.confined(value, "E15A4.PROFILE", True)
            if not isinstance(required, list) or key not in required:
                self.add("error", "E15A4.PROFILE.REQUIRED", f"required authority missing: {key}", "EIGIIB.toml")
        gates = profile.get("manual_gates", [])
        exact = ("complete", "e15", "conformance/E15-A4-MANUAL-REVIEW.md")
        matches = [g for g in gates if isinstance(g, dict) and g.get("id") == "e15-a4-withdrawal-tombstone-post-delivery-review"] if isinstance(gates, list) else []
        if len(matches) != 1 or (matches[0].get("status"), matches[0].get("authority"), matches[0].get("attestation")) != exact:
            self.add("error", "E15A4.PROFILE.GATE", "E15-A4 manual gate is missing or inexact", "EIGIIB.toml")
        else:
            self.confined(exact[2], "E15A4.PROFILE", True)

    def check_history_report(self) -> str:
        if self.history_report_path is None:
            self.add("error", "E15A4.HISTORY.REPORT", "historical E15-A3 replay report is required", "")
            return "non-conformant"
        report = self.load_json(self.history_report_path, "E15A4.HISTORY")
        if report is None:
            return "non-conformant"
        if report.get("standard") != HISTORY_STANDARD or report.get("source_commit") != SOURCE_E15_A3_HEAD:
            self.add("error", "E15A4.HISTORY.HEADER", "historical E15-A3 replay header mismatch", self.history_report_path.as_posix())
        for field in (
            "ancestry_result", "historical_e14_result", "e15_a1_result", "e15_a2_result",
            "e15_a3_result", "e15_a3_tests_result", "overall_result",
        ):
            if report.get(field) != "conformant":
                self.add("error", "E15A4.HISTORY.COMPONENT", f"{field} is not conformant", self.history_report_path.as_posix())
        return "non-conformant" if any(f.code.startswith("E15A4.HISTORY") for f in self.findings) else "conformant"

    def check_transition(self, transition: dict[str, Any] | None) -> None:
        if transition is None:
            return
        path = self.transition_path.as_posix()
        if transition.get("standard") != TRANSITION_STANDARD or transition.get("status") != "adopted-e15-a4":
            self.add("error", "E15A4.TRANSITION.HEADER", "unexpected transition header", path)
        source = transition.get("source")
        exact_source = {
            "head_commit": SOURCE_E15_A3_HEAD,
            "profile_revision": "EIGIIB-E15-draft-1.2",
            "authority_freeze": "conformance/e15-a3-authority-freeze.json",
            "registry_authority": self.parent_registry_path.as_posix(),
            "checker": "tools/eigiib_publication_readback_check.py",
        }
        if not isinstance(source, dict) or any(source.get(k) != v for k, v in exact_source.items()):
            self.add("error", "E15A4.TRANSITION.SOURCE", "source E15-A3 authority mismatch", path)
        replay = transition.get("historical_replay")
        if not isinstance(replay, dict) or replay.get("mode") != "materialize-and-replay-exact-source-commit" or replay.get("tool") != "tools/eigiib_historical_e15_a3_replay.py":
            self.add("error", "E15A4.TRANSITION.REPLAY", "historical replay contract mismatch", path)
        target = transition.get("target")
        exact_target = {
            "slice": "E15-A4",
            "registry_authority": self.registry_path.as_posix(),
            "checker": "tools/eigiib_withdrawal_governance_check.py",
            "authority_freeze": self.freeze_path.as_posix(),
            "profile_revision": PROFILE_REVISION,
        }
        if not isinstance(target, dict) or any(target.get(k) != v for k, v in exact_target.items()):
            self.add("error", "E15A4.TRANSITION.TARGET", "target E15-A4 authority mismatch", path)
        preservation = transition.get("historical_preservation")
        if (
            not isinstance(preservation, dict)
            or preservation.get("transition_is_additive") is not True
            or preservation.get("source_freeze_mutated") is not False
            or preservation.get("e15_a3_claims_rewritten") is not False
            or preservation.get("descendant_profile_frozen_separately") is not True
            or preservation.get("descendant_a3_test_profile_isolated") is not True
        ):
            self.add("error", "E15A4.TRANSITION.PRESERVATION", "historical preservation contract mismatch", path)

    def load_parent(self) -> None:
        parent = self.load_json(self.parent_registry_path, "E15A4.PARENT")
        if parent is None:
            return
        if parent.get("standard") != "EIGIIB-E15-A3-1.0" or parent.get("source_e15_a2_commit") != SOURCE_E15_A2_HEAD:
            self.add("error", "E15A4.PARENT.HEADER", "unexpected E15-A3 parent registry", self.parent_registry_path.as_posix())
        self.parent_publications = self.index(parent, "external_publication_records", "E15A4.PARENT.PUBLICATION")
        self.parent_observers = self.index(parent, "readback_observer_profiles", "E15A4.PARENT.OBSERVER")
        decisions = self.index(parent, "publication_lifecycle_decisions", "E15A4.PARENT.DECISION")
        for identifier, decision in decisions.items():
            if decision.get("lifecycle_state") in PUBLISHED_PARENT_STATES:
                self.parent_decisions[identifier] = decision

    def identity_gate(self, state: str) -> str:
        return "permit" if state == "verified" else "deny" if state == "rejected" else "unavailable" if state == "unavailable" else "held"

    def policy_gate(self, state: str) -> str:
        return "permit" if state == "active" else "deny" if state == "retired" else "unavailable" if state == "unavailable" else "held"

    def validate_profiles(self) -> None:
        for identifier, value in self.authorities.items():
            path = f"withdrawal_authority_profiles[{identifier}]"
            self.check_commitment(value, path, "E15A4.AUTHORITY.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("kind") not in AUTHORITY_KINDS or value.get("identity_state") not in IDENTITY_STATES:
                self.add("error", "E15A4.AUTHORITY.SHAPE", "authority revision, kind or identity state is invalid", path)
            for field in ("identity_authority", "principal_id", "provider_id", "implementation_id"):
                if not self.nonempty(value.get(field)):
                    self.add("error", "E15A4.AUTHORITY.IDENTITY", f"{field} is required", path)
            actions = self.string_list(value.get("actions"), f"{path}.actions", "E15A4.AUTHORITY.ACTIONS")
            if WITHDRAWAL_ACTION not in actions:
                self.add("error", "E15A4.AUTHORITY.ACTION", f"{WITHDRAWAL_ACTION} must be declared", path)
            self.string_list(value.get("authentication_algorithms"), f"{path}.authentication_algorithms", "E15A4.AUTHORITY.AUTH")

        for identifier, value in self.operators.items():
            path = f"distribution_operator_profiles[{identifier}]"
            self.check_commitment(value, path, "E15A4.OPERATOR.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("kind") not in OPERATOR_KINDS or value.get("identity_state") not in IDENTITY_STATES:
                self.add("error", "E15A4.OPERATOR.SHAPE", "operator revision, kind or identity state is invalid", path)
            for field in ("identity_authority", "principal_id", "provider_id", "implementation_id"):
                if not self.nonempty(value.get(field)):
                    self.add("error", "E15A4.OPERATOR.IDENTITY", f"{field} is required", path)
            self.string_list(value.get("managed_targets"), f"{path}.managed_targets", "E15A4.OPERATOR.TARGETS")
            mechanisms = self.string_list(value.get("stop_mechanisms"), f"{path}.stop_mechanisms", "E15A4.OPERATOR.MECHANISMS")
            if any(item not in STOP_MECHANISMS for item in mechanisms):
                self.add("error", "E15A4.OPERATOR.MECHANISM", "unknown stop mechanism", path)
            self.string_list(value.get("authentication_algorithms"), f"{path}.authentication_algorithms", "E15A4.OPERATOR.AUTH")

        for identifier, value in self.targets.items():
            path = f"distribution_target_profiles[{identifier}]"
            self.check_commitment(value, path, "E15A4.TARGET.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("kind") not in TARGET_KINDS or value.get("locator_kind") not in LOCATOR_KINDS:
                self.add("error", "E15A4.TARGET.SHAPE", "target revision, kind or locator kind is invalid", path)
            if not self.nonempty(value.get("locator")):
                self.add("error", "E15A4.TARGET.LOCATOR", "target locator is required", path)
            if not isinstance(value.get("tombstone_capable"), bool):
                self.add("error", "E15A4.TARGET.TOMBSTONE", "tombstone_capable must be boolean", path)
            mechanisms = self.string_list(value.get("stop_mechanisms"), f"{path}.stop_mechanisms", "E15A4.TARGET.MECHANISMS")
            if any(item not in STOP_MECHANISMS for item in mechanisms):
                self.add("error", "E15A4.TARGET.MECHANISM", "unknown stop mechanism", path)

        for identifier, value in self.policies.items():
            path = f"withdrawal_policies[{identifier}]"
            self.check_commitment(value, path, "E15A4.POLICY.COMMITMENT")
            if not self.nonempty(value.get("revision")) or value.get("state") not in POLICY_STATES:
                self.add("error", "E15A4.POLICY.SHAPE", "policy revision or state is invalid", path)
            allowed_authorities = self.string_list(value.get("allowed_authorities"), f"{path}.allowed_authorities", "E15A4.POLICY.AUTHORITIES")
            allowed_operators = self.string_list(value.get("allowed_operators"), f"{path}.allowed_operators", "E15A4.POLICY.OPERATORS")
            allowed_observers = self.string_list(value.get("allowed_observers"), f"{path}.allowed_observers", "E15A4.POLICY.OBSERVERS")
            registered = self.string_list(value.get("registered_targets"), f"{path}.registered_targets", "E15A4.POLICY.TARGETS")
            tombstone_targets = self.string_list(value.get("tombstone_targets"), f"{path}.tombstone_targets", "E15A4.POLICY.TOMBSTONES", allow_empty=True)
            stop_targets = self.string_list(value.get("stop_targets"), f"{path}.stop_targets", "E15A4.POLICY.STOPS")
            if not set(tombstone_targets).issubset(registered) or not set(stop_targets).issubset(registered):
                self.add("error", "E15A4.POLICY.SUBSET", "tombstone and stop targets must be registered targets", path)
            if value.get("tombstone_requirement") not in {"required", "optional"}:
                self.add("error", "E15A4.POLICY.TOMBSTONE_REQUIREMENT", "invalid tombstone requirement", path)
            if value.get("stop_coverage") != "all-registered-stop-targets":
                self.add("error", "E15A4.POLICY.STOP_COVERAGE", "stop_coverage must require every registered stop target", path)
            for field in (
                "minimum_withdrawal_sequence", "max_request_age_seconds", "max_tombstone_age_seconds",
                "max_stop_age_seconds", "max_post_observation_age_seconds",
                "required_post_withdrawal_observations_per_target", "min_post_observation_interval_seconds",
            ):
                self.positive_int(value.get(field), f"{path}.{field}", "E15A4.POLICY.INTEGER", allow_zero=field != "minimum_withdrawal_sequence")
            self.string_list(value.get("required_authentication_algorithms"), f"{path}.required_authentication_algorithms", "E15A4.POLICY.AUTH")
            for ref in allowed_authorities:
                if ref not in self.authorities:
                    self.add("error", "E15A4.POLICY.AUTHORITY_REF", f"unknown authority {ref}", path)
            for ref in allowed_operators:
                if ref not in self.operators:
                    self.add("error", "E15A4.POLICY.OPERATOR_REF", f"unknown operator {ref}", path)
            for ref in allowed_observers:
                if ref not in self.parent_observers:
                    self.add("error", "E15A4.POLICY.OBSERVER_REF", f"unknown inherited observer {ref}", path)
            for ref in registered:
                if ref not in self.targets:
                    self.add("error", "E15A4.POLICY.TARGET_REF", f"unknown target {ref}", path)
            for ref in tombstone_targets:
                target = self.targets.get(ref)
                if target is not None and target.get("tombstone_capable") is not True:
                    self.add("error", "E15A4.POLICY.TOMBSTONE_CAPABILITY", f"target {ref} is not tombstone-capable", path)

    def validate_requests(self) -> None:
        seen_keys: set[str] = set()
        for identifier, value in self.requests.items():
            path = f"withdrawal_requests[{identifier}]"
            self.check_commitment(value, path, "E15A4.REQUEST.COMMITMENT")
            publication = self.parent_publications.get(str(value.get("source_publication")))
            decision = self.parent_decisions.get(str(value.get("source_a3_decision")))
            authority = self.authorities.get(str(value.get("authority")))
            policy = self.policies.get(str(value.get("policy")))
            binding_values: list[str] = []
            if publication is None or value.get("source_publication_revision") != (publication or {}).get("revision"):
                self.add("error", "E15A4.REQUEST.PUBLICATION", "source publication does not resolve exactly", path)
                binding_values.append("deny")
            else:
                binding_values.append("permit")
            expected_pub_commit = (publication or {}).get("commitment", {}).get("digest") if isinstance((publication or {}).get("commitment"), dict) else None
            if value.get("source_publication_commitment_sha256") != expected_pub_commit:
                self.add("error", "E15A4.REQUEST.PUBLICATION_COMMITMENT", "source publication commitment mismatch", path)
                binding_values.append("deny")
            if decision is None or decision.get("publication") != value.get("source_publication"):
                self.add("error", "E15A4.REQUEST.DECISION", "source E15-A3 decision does not resolve to the publication", path)
                binding_values.append("deny")
            else:
                binding_values.append("permit")
            expected_decision_commit = (decision or {}).get("commitment", {}).get("digest") if isinstance((decision or {}).get("commitment"), dict) else None
            if value.get("source_a3_decision_commitment_sha256") != expected_decision_commit:
                self.add("error", "E15A4.REQUEST.DECISION_COMMITMENT", "source E15-A3 decision commitment mismatch", path)
                binding_values.append("deny")
            if authority is None or value.get("authority_revision") != (authority or {}).get("revision"):
                self.add("error", "E15A4.REQUEST.AUTHORITY", "withdrawal authority does not resolve exactly", path)
                binding_values.append("deny")
            if policy is None or value.get("policy_revision") != (policy or {}).get("revision"):
                self.add("error", "E15A4.REQUEST.POLICY", "withdrawal policy does not resolve exactly", path)
                binding_values.append("deny")
            scope = self.string_list(value.get("scope_targets"), f"{path}.scope_targets", "E15A4.REQUEST.SCOPE")
            if policy is not None and set(scope) != set(policy.get("registered_targets", [])):
                self.add("error", "E15A4.REQUEST.SCOPE_BINDING", "request scope must equal the policy registered target set", path)
                binding_values.append("deny")
            sequence = self.positive_int(value.get("withdrawal_sequence"), f"{path}.withdrawal_sequence", "E15A4.REQUEST.SEQUENCE")
            if policy is not None and sequence is not None and sequence < int(policy.get("minimum_withdrawal_sequence", 1)):
                self.add("error", "E15A4.REQUEST.SEQUENCE_FLOOR", "withdrawal sequence is below the policy floor", path)
                binding_values.append("deny")
            key = value.get("withdrawal_idempotency_key")
            if not self.nonempty(key):
                self.add("error", "E15A4.REQUEST.IDEMPOTENCY", "withdrawal idempotency key is required", path)
            elif key in seen_keys:
                self.add("error", "E15A4.REQUEST.IDEMPOTENCY_REUSE", "withdrawal idempotency key is reused", path)
            else:
                seen_keys.add(str(key))
            requested = parse_time(value.get("requested_at"))
            effective = parse_time(value.get("effective_at"))
            valid = parse_time(value.get("valid_until"))
            if requested is None or effective is None or valid is None or not (requested <= effective <= valid):
                self.add("error", "E15A4.REQUEST.TIME", "request times must satisfy requested_at <= effective_at <= valid_until", path)
            if value.get("request_state") not in EVIDENCE_STATES or value.get("observed_event") not in REQUEST_EVENTS:
                self.add("error", "E15A4.REQUEST.STATE", "request state or event is invalid", path)
            if value.get("request_state") == "positive" and value.get("observed_event") != "requested":
                self.add("error", "E15A4.REQUEST.EVENT", "positive request must record requested", path)
            if value.get("request_state") == "negative" and value.get("observed_event") not in {"rejected", "cancelled"}:
                self.add("error", "E15A4.REQUEST.EVENT", "negative request must record rejected or cancelled", path)
            algorithm = self.check_auth(value.get("authentication"), f"{path}.authentication", "E15A4.REQUEST.AUTH")
            required_algs = set((policy or {}).get("required_authentication_algorithms", []))
            allowed_algs = set((authority or {}).get("authentication_algorithms", []))
            if algorithm is not None and (algorithm not in required_algs or algorithm not in allowed_algs):
                self.add("error", "E15A4.REQUEST.AUTH_ALGORITHM", "request authentication algorithm is not admitted", path)
                binding_values.append("deny")
            if authority is not None and policy is not None and str(value.get("authority")) not in policy.get("allowed_authorities", []):
                self.add("error", "E15A4.REQUEST.AUTHORITY_POLICY", "authority is not admitted by policy", path)
                binding_values.append("deny")
            expected_digest = (publication or {}).get("payload_sha256")
            expected_bytes = (publication or {}).get("payload_bytes")
            self.request_content[identifier] = "permit" if value.get("payload_sha256") == expected_digest and value.get("payload_bytes") == expected_bytes else "deny"
            if self.request_content[identifier] == "deny":
                self.add("error", "E15A4.REQUEST.CONTENT", "withdrawal request content identity mismatch", path)
            self.request_binding[identifier] = combine_gates(binding_values or ["deny"])
            self.request_authority[identifier] = self.identity_gate(str((authority or {}).get("identity_state", "rejected")))
            self.request_policy[identifier] = self.policy_gate(str((policy or {}).get("state", "retired")))

    def validate_tombstones(self) -> None:
        chains: dict[tuple[str, str], list[tuple[int, str, dict[str, Any]]]] = {}
        for identifier, value in self.tombstones.items():
            path = f"registry_tombstones[{identifier}]"
            self.check_commitment(value, path, "E15A4.TOMBSTONE.COMMITMENT")
            request = self.requests.get(str(value.get("withdrawal_request")))
            target = self.targets.get(str(value.get("target")))
            operator = self.operators.get(str(value.get("operator")))
            policy = self.policies.get(str((request or {}).get("policy")))
            binding_values: list[str] = []
            if request is None or value.get("request_revision") != (request or {}).get("revision"):
                self.add("error", "E15A4.TOMBSTONE.REQUEST", "tombstone request does not resolve exactly", path)
                binding_values.append("deny")
            else:
                binding_values.append("permit")
            if target is None or value.get("target_revision") != (target or {}).get("revision"):
                self.add("error", "E15A4.TOMBSTONE.TARGET", "tombstone target does not resolve exactly", path)
                binding_values.append("deny")
            if operator is None or value.get("operator_revision") != (operator or {}).get("revision"):
                self.add("error", "E15A4.TOMBSTONE.OPERATOR", "tombstone operator does not resolve exactly", path)
                binding_values.append("deny")
            if target is not None and value.get("locator") != target.get("locator"):
                self.add("error", "E15A4.TOMBSTONE.LOCATOR", "tombstone locator differs from target locator", path)
                binding_values.append("deny")
            if policy is not None and str(value.get("target")) not in policy.get("tombstone_targets", []):
                self.add("error", "E15A4.TOMBSTONE.POLICY_TARGET", "target is not a policy tombstone target", path)
                binding_values.append("deny")
            if operator is not None and str(value.get("target")) not in operator.get("managed_targets", []):
                self.add("error", "E15A4.TOMBSTONE.OPERATOR_TARGET", "operator does not manage target", path)
                binding_values.append("deny")
            if policy is not None and str(value.get("operator")) not in policy.get("allowed_operators", []):
                self.add("error", "E15A4.TOMBSTONE.OPERATOR_POLICY", "operator is not admitted by policy", path)
                binding_values.append("deny")
            generation = self.positive_int(value.get("generation"), f"{path}.generation", "E15A4.TOMBSTONE.GENERATION")
            if value.get("tombstone_state") not in EVIDENCE_STATES or value.get("observed_event") not in TOMBSTONE_EVENTS:
                self.add("error", "E15A4.TOMBSTONE.STATE", "tombstone state or event is invalid", path)
            if value.get("tombstone_state") == "positive" and value.get("observed_event") != "installed":
                self.add("error", "E15A4.TOMBSTONE.EVENT", "positive tombstone must record installed", path)
            if value.get("tombstone_state") == "negative" and value.get("observed_event") not in {"removed", "rejected"}:
                self.add("error", "E15A4.TOMBSTONE.EVENT", "negative tombstone must record removed or rejected", path)
            observed = parse_time(value.get("observed_at")); valid = parse_time(value.get("valid_until")); effective = parse_time((request or {}).get("effective_at"))
            if observed is None or valid is None or effective is None or observed < effective or observed > valid:
                self.add("error", "E15A4.TOMBSTONE.TIME", "tombstone observation must be within the post-effective validity window", path)
            algorithm = self.check_auth(value.get("authentication"), f"{path}.authentication", "E15A4.TOMBSTONE.AUTH")
            required_algs = set((policy or {}).get("required_authentication_algorithms", []))
            allowed_algs = set((operator or {}).get("authentication_algorithms", []))
            if algorithm is not None and (algorithm not in required_algs or algorithm not in allowed_algs):
                self.add("error", "E15A4.TOMBSTONE.AUTH_ALGORITHM", "tombstone authentication algorithm is not admitted", path)
                binding_values.append("deny")
            mechanism = value.get("stop_mechanism")
            if mechanism != "registry-tombstone" or mechanism not in (target or {}).get("stop_mechanisms", []) or mechanism not in (operator or {}).get("stop_mechanisms", []):
                self.add("error", "E15A4.TOMBSTONE.MECHANISM", "registry-tombstone mechanism is not bound by target and operator", path)
                binding_values.append("deny")
            expected_digest = (request or {}).get("payload_sha256")
            self.tombstone_content[identifier] = "permit" if value.get("payload_sha256") == expected_digest else "deny"
            if self.tombstone_content[identifier] == "deny":
                self.add("error", "E15A4.TOMBSTONE.CONTENT", "tombstone content identity mismatch", path)
            self.tombstone_binding[identifier] = combine_gates(binding_values or ["deny"])
            self.tombstone_operator[identifier] = self.identity_gate(str((operator or {}).get("identity_state", "rejected")))
            if request is not None and target is not None and generation is not None:
                chains.setdefault((str(value.get("withdrawal_request")), str(value.get("target"))), []).append((generation, identifier, value))
        self._validate_chains(chains, "tombstone")

    def validate_stops(self) -> None:
        chains: dict[tuple[str, str], list[tuple[int, str, dict[str, Any]]]] = {}
        for identifier, value in self.stops.items():
            path = f"distribution_stop_records[{identifier}]"
            self.check_commitment(value, path, "E15A4.STOP.COMMITMENT")
            request = self.requests.get(str(value.get("withdrawal_request")))
            target = self.targets.get(str(value.get("target")))
            operator = self.operators.get(str(value.get("operator")))
            policy = self.policies.get(str((request or {}).get("policy")))
            binding_values: list[str] = []
            if request is None or value.get("request_revision") != (request or {}).get("revision"):
                self.add("error", "E15A4.STOP.REQUEST", "stop request does not resolve exactly", path)
                binding_values.append("deny")
            else:
                binding_values.append("permit")
            if target is None or value.get("target_revision") != (target or {}).get("revision"):
                self.add("error", "E15A4.STOP.TARGET", "stop target does not resolve exactly", path)
                binding_values.append("deny")
            if operator is None or value.get("operator_revision") != (operator or {}).get("revision"):
                self.add("error", "E15A4.STOP.OPERATOR", "stop operator does not resolve exactly", path)
                binding_values.append("deny")
            if target is not None and value.get("locator") != target.get("locator"):
                self.add("error", "E15A4.STOP.LOCATOR", "stop locator differs from target locator", path)
                binding_values.append("deny")
            if policy is not None and str(value.get("target")) not in policy.get("stop_targets", []):
                self.add("error", "E15A4.STOP.POLICY_TARGET", "target is not a policy stop target", path)
                binding_values.append("deny")
            if operator is not None and str(value.get("target")) not in operator.get("managed_targets", []):
                self.add("error", "E15A4.STOP.OPERATOR_TARGET", "operator does not manage target", path)
                binding_values.append("deny")
            if policy is not None and str(value.get("operator")) not in policy.get("allowed_operators", []):
                self.add("error", "E15A4.STOP.OPERATOR_POLICY", "operator is not admitted by policy", path)
                binding_values.append("deny")
            sequence = self.positive_int(value.get("stop_sequence"), f"{path}.stop_sequence", "E15A4.STOP.SEQUENCE")
            if value.get("stop_state") not in EVIDENCE_STATES or value.get("observed_event") not in STOP_EVENTS:
                self.add("error", "E15A4.STOP.STATE", "stop state or event is invalid", path)
            if value.get("stop_state") == "positive" and value.get("observed_event") != "stopped":
                self.add("error", "E15A4.STOP.EVENT", "positive stop must record stopped", path)
            if value.get("stop_state") == "negative" and value.get("observed_event") not in {"resumed", "failed"}:
                self.add("error", "E15A4.STOP.EVENT", "negative stop must record resumed or failed", path)
            observed = parse_time(value.get("observed_at")); valid = parse_time(value.get("valid_until")); effective = parse_time((request or {}).get("effective_at"))
            if observed is None or valid is None or effective is None or observed < effective or observed > valid:
                self.add("error", "E15A4.STOP.TIME", "stop observation must be within the post-effective validity window", path)
            algorithm = self.check_auth(value.get("authentication"), f"{path}.authentication", "E15A4.STOP.AUTH")
            required_algs = set((policy or {}).get("required_authentication_algorithms", []))
            allowed_algs = set((operator or {}).get("authentication_algorithms", []))
            if algorithm is not None and (algorithm not in required_algs or algorithm not in allowed_algs):
                self.add("error", "E15A4.STOP.AUTH_ALGORITHM", "stop authentication algorithm is not admitted", path)
                binding_values.append("deny")
            mechanism = value.get("stop_mechanism")
            if mechanism not in STOP_MECHANISMS or mechanism not in (target or {}).get("stop_mechanisms", []) or mechanism not in (operator or {}).get("stop_mechanisms", []):
                self.add("error", "E15A4.STOP.MECHANISM", "stop mechanism is not bound by target and operator", path)
                binding_values.append("deny")
            expected_digest = (request or {}).get("payload_sha256")
            self.stop_content[identifier] = "permit" if value.get("payload_sha256") == expected_digest else "deny"
            if self.stop_content[identifier] == "deny":
                self.add("error", "E15A4.STOP.CONTENT", "stop content identity mismatch", path)
            self.stop_binding[identifier] = combine_gates(binding_values or ["deny"])
            self.stop_operator[identifier] = self.identity_gate(str((operator or {}).get("identity_state", "rejected")))
            if request is not None and target is not None and sequence is not None:
                chains.setdefault((str(value.get("withdrawal_request")), str(value.get("target"))), []).append((sequence, identifier, value))
        self._validate_chains(chains, "stop")

    def _validate_chains(self, chains: dict[tuple[str, str], list[tuple[int, str, dict[str, Any]]]], kind: str) -> None:
        for key, entries in chains.items():
            entries.sort(key=lambda item: item[0])
            expected = 1
            previous_id: str | None = None
            previous_commitment: str | None = None
            for generation, identifier, value in entries:
                path = f"{kind}:{identifier}"
                if generation != expected:
                    self.add("error", f"E15A4.{kind.upper()}.CHAIN_SEQUENCE", "chain sequence must be contiguous from 1", path)
                pred_id = value.get("predecessor_id")
                pred_commitment = value.get("predecessor_commitment_sha256")
                if expected == 1:
                    if pred_id is not None or pred_commitment is not None:
                        self.add("error", f"E15A4.{kind.upper()}.CHAIN_ROOT", "first chain entry must have no predecessor", path)
                else:
                    if pred_id != previous_id or pred_commitment != previous_commitment:
                        self.add("error", f"E15A4.{kind.upper()}.CHAIN_PREDECESSOR", "chain predecessor binding mismatch", path)
                expected += 1
                previous_id = identifier
                commitment = value.get("commitment")
                previous_commitment = commitment.get("digest") if isinstance(commitment, dict) else None
            if entries:
                if kind == "tombstone":
                    self.latest_tombstone[key] = entries[-1][1]
                else:
                    self.latest_stop[key] = entries[-1][1]

    def validate_observations(self) -> None:
        for identifier, value in self.observations.items():
            path = f"post_withdrawal_observations[{identifier}]"
            self.check_commitment(value, path, "E15A4.OBSERVATION.COMMITMENT")
            request = self.requests.get(str(value.get("withdrawal_request")))
            target = self.targets.get(str(value.get("target")))
            observer = self.parent_observers.get(str(value.get("observer")))
            policy = self.policies.get(str((request or {}).get("policy")))
            binding_values: list[str] = []
            if request is None or value.get("request_revision") != (request or {}).get("revision"):
                self.add("error", "E15A4.OBSERVATION.REQUEST", "observation request does not resolve exactly", path)
                binding_values.append("deny")
            else:
                binding_values.append("permit")
            if target is None or value.get("target_revision") != (target or {}).get("revision"):
                self.add("error", "E15A4.OBSERVATION.TARGET", "observation target does not resolve exactly", path)
                binding_values.append("deny")
            if observer is None or value.get("observer_revision") != (observer or {}).get("revision"):
                self.add("error", "E15A4.OBSERVATION.OBSERVER", "inherited observer does not resolve exactly", path)
                binding_values.append("deny")
            if target is not None and value.get("locator") != target.get("locator"):
                self.add("error", "E15A4.OBSERVATION.LOCATOR", "observation locator differs from target locator", path)
                binding_values.append("deny")
            if policy is not None and str(value.get("target")) not in policy.get("registered_targets", []):
                self.add("error", "E15A4.OBSERVATION.POLICY_TARGET", "observation target is not registered by policy", path)
                binding_values.append("deny")
            if policy is not None and str(value.get("observer")) not in policy.get("allowed_observers", []):
                self.add("error", "E15A4.OBSERVATION.OBSERVER_POLICY", "observer is not admitted by policy", path)
                binding_values.append("deny")
            if value.get("observation_state") not in EVIDENCE_STATES or value.get("observed_event") not in POST_EVENTS:
                self.add("error", "E15A4.OBSERVATION.STATE", "post-withdrawal state or event is invalid", path)
            if value.get("observation_state") == "positive" and value.get("observed_event") not in {"tombstone-visible", "not-found"}:
                self.add("error", "E15A4.OBSERVATION.EVENT", "positive observation must record tombstone-visible or not-found", path)
            if value.get("observation_state") == "negative" and value.get("observed_event") not in {"still-available", "digest-mismatch"}:
                self.add("error", "E15A4.OBSERVATION.EVENT", "negative observation must record still-available or digest-mismatch", path)
            if value.get("observation_state") == "unavailable" and value.get("observed_event") != "unreachable":
                self.add("error", "E15A4.OBSERVATION.EVENT", "unavailable observation must record unreachable", path)
            observed = parse_time(value.get("observed_at")); valid = parse_time(value.get("valid_until")); effective = parse_time((request or {}).get("effective_at"))
            if observed is None or valid is None or effective is None or observed < effective or observed > valid:
                self.add("error", "E15A4.OBSERVATION.TIME", "post-withdrawal observation must be within the post-effective validity window", path)
            algorithm = self.check_auth(value.get("authentication"), f"{path}.authentication", "E15A4.OBSERVATION.AUTH")
            required_algs = set((policy or {}).get("required_authentication_algorithms", []))
            allowed_algs = set((observer or {}).get("authentication_algorithms", []))
            if algorithm is not None and (algorithm not in required_algs or algorithm not in allowed_algs):
                self.add("error", "E15A4.OBSERVATION.AUTH_ALGORITHM", "observation authentication algorithm is not admitted", path)
                binding_values.append("deny")
            expected_digest = (request or {}).get("payload_sha256")
            self.observation_content[identifier] = "permit" if value.get("payload_sha256") == expected_digest else "deny"
            if self.observation_content[identifier] == "deny":
                self.add("error", "E15A4.OBSERVATION.CONTENT", "post-withdrawal observation content identity mismatch", path)
            self.observation_binding[identifier] = combine_gates(binding_values or ["deny"])
            self.observation_observer[identifier] = self.identity_gate(str((observer or {}).get("identity_state", "rejected")))

    def freshness_gate(self, item: dict[str, Any], evaluated: datetime, issued_field: str, max_age: int) -> str:
        issued = parse_time(item.get(issued_field)); valid = parse_time(item.get("valid_until"))
        if issued is None or valid is None:
            return "deny"
        if evaluated < issued or evaluated > valid:
            return "deny"
        if max_age >= 0 and (evaluated - issued).total_seconds() > max_age:
            return "deny"
        return "permit"

    def request_freshness(self, request: dict[str, Any], evaluated: datetime, max_age: int) -> str:
        requested = parse_time(request.get("requested_at")); effective = parse_time(request.get("effective_at")); valid = parse_time(request.get("valid_until"))
        if requested is None or effective is None or valid is None:
            return "deny"
        if evaluated < effective:
            return "held"
        if evaluated > valid or (evaluated - requested).total_seconds() > max_age:
            return "deny"
        return "permit"

    def coverage_gate(self, ids: list[str], records: dict[str, dict[str, Any]], required_targets: list[str], request_id: str, state_field: str, positive_event: str) -> str:
        by_target: dict[str, dict[str, Any]] = {}
        for identifier in ids:
            record = records.get(identifier)
            if record is None or record.get("withdrawal_request") != request_id:
                return "deny"
            target = str(record.get("target"))
            if target in by_target:
                return "deny"
            by_target[target] = record
        if not set(required_targets).issubset(by_target):
            return "held"
        states = [str(by_target[target].get(state_field)) for target in required_targets]
        events = [str(by_target[target].get("observed_event")) for target in required_targets]
        if "negative" in states or any(event != positive_event for event, state in zip(events, states) if state == "positive"):
            return "deny"
        if "unavailable" in states:
            return "unavailable"
        if "contested" in states:
            return "held"
        return "permit" if all(state == "positive" for state in states) else "held"

    def post_observation_gate(self, items: list[dict[str, Any]], policy: dict[str, Any], required_targets: list[str]) -> str:
        states = [str(item.get("observation_state")) for item in items]
        if "negative" in states:
            return "deny"
        if "unavailable" in states:
            return "unavailable"
        if "contested" in states:
            return "held"
        required = int(policy.get("required_post_withdrawal_observations_per_target", 0))
        interval = int(policy.get("min_post_observation_interval_seconds", 0))
        by_target: dict[str, list[datetime]] = {target: [] for target in required_targets}
        for item in items:
            if item.get("observation_state") == "positive" and str(item.get("target")) in by_target:
                observed = parse_time(item.get("observed_at"))
                if observed is None:
                    return "deny"
                by_target[str(item.get("target"))].append(observed)
        for target in required_targets:
            times = sorted(by_target[target])
            if len(times) < required:
                return "held"
            if any((b - a).total_seconds() < interval for a, b in zip(times, times[1:])):
                return "deny"
        return "permit"

    def anti_rollback_gate(self, request_id: str, tombstone_ids: list[str], stop_ids: list[str], policy: dict[str, Any]) -> str:
        referenced_tombstones = {str(self.tombstones[x].get("target")): x for x in tombstone_ids if x in self.tombstones}
        referenced_stops = {str(self.stops[x].get("target")): x for x in stop_ids if x in self.stops}
        if len(referenced_tombstones) != len(tombstone_ids) or len(referenced_stops) != len(stop_ids):
            return "deny"
        for target in policy.get("tombstone_targets", []):
            latest = self.latest_tombstone.get((request_id, str(target)))
            if policy.get("tombstone_requirement") == "required" and latest is None:
                return "held"
            if latest is not None and referenced_tombstones.get(str(target)) != latest:
                return "deny"
        for target in policy.get("stop_targets", []):
            latest = self.latest_stop.get((request_id, str(target)))
            if latest is None:
                return "held"
            if referenced_stops.get(str(target)) != latest:
                return "deny"
        return "permit"

    def derive_lifecycle(
        self,
        request: dict[str, Any],
        gates: dict[str, str],
        tombstone_states: list[str],
        stop_states: list[str],
        observation_states: list[str],
    ) -> str:
        values = list(gates.values())
        if "deny" in values or request.get("request_state") == "negative" or "negative" in tombstone_states + stop_states + observation_states:
            return "rejected"
        if request.get("request_state") == "contested" or "contested" in tombstone_states + stop_states + observation_states:
            return "contested"
        if "unavailable" in values or request.get("request_state") == "unavailable" or "unavailable" in tombstone_states + stop_states + observation_states:
            return "unavailable"
        blocking = ("binding_result", "authority_result", "policy_result", "freshness_result", "request_result", "content_identity_result")
        if any(gates[name] == "held" for name in blocking):
            return "held"
        if gates["tombstone_result"] != "permit":
            return "withdrawal-requested"
        if gates["distribution_stop_result"] != "permit":
            return "tombstoned"
        if gates["post_withdrawal_observation_result"] != "permit":
            return "distribution-stopped"
        if gates["operator_result"] == gates["observer_result"] == gates["anti_rollback_result"] == "permit":
            return "post-withdrawal-observed"
        return "held"

    def validate_decisions(self) -> None:
        used_tombstones: set[str] = set()
        used_stops: set[str] = set()
        used_observations: set[str] = set()
        requests_seen: set[str] = set()
        for identifier, value in self.decisions.items():
            path = f"withdrawal_lifecycle_decisions[{identifier}]"
            self.check_commitment(value, path, "E15A4.DECISION.COMMITMENT")
            request_id = str(value.get("withdrawal_request"))
            request = self.requests.get(request_id)
            if request is None or value.get("request_revision") != (request or {}).get("revision"):
                self.add("error", "E15A4.DECISION.REQUEST", "decision request does not resolve exactly", path)
                continue
            if request_id in requests_seen:
                self.add("error", "E15A4.DECISION.DUPLICATE", "withdrawal request has more than one decision", path)
            requests_seen.add(request_id)
            self.positive_int(value.get("sequence"), f"{path}.sequence", "E15A4.DECISION.SEQUENCE")
            tombstone_ids = self.string_list(value.get("registry_tombstones"), f"{path}.registry_tombstones", "E15A4.DECISION.TOMBSTONES", allow_empty=True)
            stop_ids = self.string_list(value.get("distribution_stops"), f"{path}.distribution_stops", "E15A4.DECISION.STOPS", allow_empty=True)
            observation_ids = self.string_list(value.get("post_withdrawal_observations"), f"{path}.post_withdrawal_observations", "E15A4.DECISION.OBSERVATIONS", allow_empty=True)
            if used_tombstones.intersection(tombstone_ids) or used_stops.intersection(stop_ids) or used_observations.intersection(observation_ids):
                self.add("error", "E15A4.DECISION.REUSE", "evidence record is consumed more than once", path)
            used_tombstones.update(tombstone_ids); used_stops.update(stop_ids); used_observations.update(observation_ids)
            tombstone_items = [self.tombstones[x] for x in tombstone_ids if x in self.tombstones]
            stop_items = [self.stops[x] for x in stop_ids if x in self.stops]
            observation_items = [self.observations[x] for x in observation_ids if x in self.observations]
            if len(tombstone_items) != len(tombstone_ids) or len(stop_items) != len(stop_ids) or len(observation_items) != len(observation_ids):
                self.add("error", "E15A4.DECISION.REF", "decision contains unresolved evidence", path)
            if any(item.get("withdrawal_request") != request_id for item in tombstone_items + stop_items + observation_items):
                self.add("error", "E15A4.DECISION.BINDING", "decision evidence belongs to another request", path)
            policy = self.policies.get(str(request.get("policy")))
            if policy is None:
                self.add("error", "E15A4.DECISION.POLICY", "withdrawal policy does not resolve", path)
                continue
            evaluated = parse_time(value.get("evaluated_at"))
            if evaluated is None:
                self.add("error", "E15A4.DECISION.TIME", "evaluated_at must be UTC RFC3339", path)
                continue
            binding = combine_gates(
                [self.request_binding.get(request_id, "deny")]
                + [self.tombstone_binding.get(x, "deny") for x in tombstone_ids]
                + [self.stop_binding.get(x, "deny") for x in stop_ids]
                + [self.observation_binding.get(x, "deny") for x in observation_ids]
            )
            authority_result = self.request_authority.get(request_id, "deny")
            operator_result = combine_gates(
                [self.tombstone_operator.get(x, "deny") for x in tombstone_ids]
                + [self.stop_operator.get(x, "deny") for x in stop_ids]
                or ["permit"]
            )
            observer_result = combine_gates([self.observation_observer.get(x, "deny") for x in observation_ids] or ["permit"])
            policy_result = self.request_policy.get(request_id, "deny")
            freshness_values = [self.request_freshness(request, evaluated, int(policy.get("max_request_age_seconds", 0)))]
            freshness_values += [self.freshness_gate(item, evaluated, "observed_at", int(policy.get("max_tombstone_age_seconds", 0))) for item in tombstone_items]
            freshness_values += [self.freshness_gate(item, evaluated, "observed_at", int(policy.get("max_stop_age_seconds", 0))) for item in stop_items]
            freshness_values += [self.freshness_gate(item, evaluated, "observed_at", int(policy.get("max_post_observation_age_seconds", 0))) for item in observation_items]
            freshness_result = combine_gates(freshness_values)
            request_result = state_gate(str(request.get("request_state")))
            tombstone_targets = list(policy.get("tombstone_targets", []))
            if policy.get("tombstone_requirement") == "optional" and not tombstone_ids:
                tombstone_result = "permit"
            else:
                tombstone_result = self.coverage_gate(tombstone_ids, self.tombstones, tombstone_targets, request_id, "tombstone_state", "installed")
            stop_targets = list(policy.get("stop_targets", []))
            distribution_stop_result = self.coverage_gate(stop_ids, self.stops, stop_targets, request_id, "stop_state", "stopped")
            post_result = self.post_observation_gate(observation_items, policy, stop_targets)
            anti_rollback_result = self.anti_rollback_gate(request_id, tombstone_ids, stop_ids, policy)
            content_identity_result = combine_gates(
                [self.request_content.get(request_id, "deny")]
                + [self.tombstone_content.get(x, "deny") for x in tombstone_ids]
                + [self.stop_content.get(x, "deny") for x in stop_ids]
                + [self.observation_content.get(x, "deny") for x in observation_ids]
            )
            gates = {
                "binding_result": binding,
                "authority_result": authority_result,
                "operator_result": operator_result,
                "observer_result": observer_result,
                "policy_result": policy_result,
                "freshness_result": freshness_result,
                "request_result": request_result,
                "tombstone_result": tombstone_result,
                "distribution_stop_result": distribution_stop_result,
                "post_withdrawal_observation_result": post_result,
                "anti_rollback_result": anti_rollback_result,
                "content_identity_result": content_identity_result,
            }
            expected_state = self.derive_lifecycle(
                request,
                gates,
                [str(item.get("tombstone_state")) for item in tombstone_items],
                [str(item.get("stop_state")) for item in stop_items],
                [str(item.get("observation_state")) for item in observation_items],
            )
            for field, expected in gates.items():
                if value.get(field) not in GATE_STATES or value.get(field) != expected:
                    self.add("error", "E15A4.DECISION.GATE", f"{field} must be {expected}", path)
            if value.get("lifecycle_state") not in LIFECYCLE_STATES or value.get("lifecycle_state") != expected_state:
                self.add("error", "E15A4.DECISION.STATE", f"lifecycle_state must be {expected_state}", path)
            self.string_list(value.get("reasons"), f"{path}.reasons", "E15A4.DECISION.REASONS")
            self.string_list(value.get("evidence_refs"), f"{path}.evidence_refs", "E15A4.DECISION.EVIDENCE")
            if not any(f.severity == "error" and f.path == path for f in self.findings):
                self.valid_decisions.add(identifier)
                self.derived_states[identifier] = expected_state
        for identifier in sorted(set(self.tombstones) - used_tombstones):
            self.add("error", "E15A4.TOMBSTONE.ORPHAN", "tombstone is not consumed by a decision", identifier)
        for identifier in sorted(set(self.stops) - used_stops):
            self.add("error", "E15A4.STOP.ORPHAN", "distribution stop is not consumed by a decision", identifier)
        for identifier in sorted(set(self.observations) - used_observations):
            self.add("error", "E15A4.OBSERVATION.ORPHAN", "post-withdrawal observation is not consumed by a decision", identifier)
        for identifier in sorted(set(self.requests) - requests_seen):
            self.add("error", "E15A4.REQUEST.UNDECIDED", "withdrawal request has no lifecycle decision", identifier)

    def validate_freeze(self, freeze: dict[str, Any] | None) -> str:
        if freeze is None:
            return "non-conformant"
        path = self.freeze_path.as_posix()
        if freeze.get("standard") != FREEZE_STANDARD or freeze.get("status") != "frozen" or freeze.get("profile_revision") != PROFILE_REVISION:
            self.add("error", "E15A4.FREEZE.HEADER", "unexpected authority freeze header", path)
        source = freeze.get("source")
        if not isinstance(source, dict) or source.get("e15_a3_head_commit") != SOURCE_E15_A3_HEAD:
            self.add("error", "E15A4.FREEZE.SOURCE", "authority freeze source mismatch", path)
        authorities = freeze.get("authorities")
        if not isinstance(authorities, list):
            self.add("error", "E15A4.FREEZE.TYPE", "authorities must be an array", path)
            return "non-conformant"
        indexed: dict[str, dict[str, Any]] = {}
        for pos, entry in enumerate(authorities):
            if not isinstance(entry, dict) or not self.nonempty(entry.get("path")):
                self.add("error", "E15A4.FREEZE.ITEM", "invalid authority entry", f"{path}[{pos}]")
                continue
            rel = str(entry["path"])
            if rel in indexed:
                self.add("error", "E15A4.FREEZE.DUPLICATE", "duplicate frozen path", rel)
                continue
            indexed[rel] = entry
            file_path = self.confined(rel, "E15A4.FREEZE", True)
            if file_path is None:
                continue
            raw = file_path.read_bytes()
            if entry.get("bytes") != len(raw):
                self.add("error", "E15A4.FREEZE.BYTES", "frozen byte length mismatch", rel)
            if entry.get("sha256") != hashlib.sha256(raw).hexdigest():
                self.add("error", "E15A4.FREEZE.DIGEST", "frozen SHA-256 mismatch", rel)
        for rel in sorted(EXPECTED_FREEZE_PATHS - set(indexed)):
            self.add("error", "E15A4.FREEZE.MISSING", "required E15-A4 authority is not frozen", rel)
        for rel in sorted(set(indexed) - EXPECTED_FREEZE_PATHS):
            self.add("error", "E15A4.FREEZE.EXTRA", "unexpected authority is frozen", rel)
        return "non-conformant" if any(f.code.startswith("E15A4.FREEZE") for f in self.findings) else "conformant"

    def run(self) -> dict[str, Any]:
        self.check_profile()
        history_result = self.check_history_report()
        self.check_transition(self.load_json(self.transition_path, "E15A4.TRANSITION"))
        self.load_parent()
        registry = self.load_json(self.registry_path, "E15A4.REGISTRY")
        freeze = self.load_json(self.freeze_path, "E15A4.FREEZE")
        if registry is not None:
            if registry.get("standard") != STANDARD or registry.get("status") != "structural-only" or registry.get("source_e15_a3_commit") != SOURCE_E15_A3_HEAD:
                self.add("error", "E15A4.REGISTRY.HEADER", "unexpected registry header", self.registry_path.as_posix())
            self.authorities = self.index(registry, "withdrawal_authority_profiles", "E15A4.AUTHORITY")
            self.operators = self.index(registry, "distribution_operator_profiles", "E15A4.OPERATOR")
            self.targets = self.index(registry, "distribution_target_profiles", "E15A4.TARGET")
            self.policies = self.index(registry, "withdrawal_policies", "E15A4.POLICY")
            self.requests = self.index(registry, "withdrawal_requests", "E15A4.REQUEST")
            self.tombstones = self.index(registry, "registry_tombstones", "E15A4.TOMBSTONE")
            self.stops = self.index(registry, "distribution_stop_records", "E15A4.STOP")
            self.observations = self.index(registry, "post_withdrawal_observations", "E15A4.OBSERVATION")
            self.decisions = self.index(registry, "withdrawal_lifecycle_decisions", "E15A4.DECISION")
            self.validate_profiles()
            self.validate_requests()
            self.validate_tombstones()
            self.validate_stops()
            self.validate_observations()
            self.validate_decisions()
        freeze_result = self.validate_freeze(freeze)
        errors = any(f.severity == "error" for f in self.findings)
        result = "not-evaluated" if not self.requests else (
            "conformant" if len(self.valid_decisions) == len(self.decisions) == len(self.requests) and not errors else "non-conformant"
        )
        states = list(self.derived_states.values())
        return {
            "tool": "eigiib-withdrawal-governance-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if errors else "conformant",
            "historical_continuity_result": history_result,
            "authority_freeze_result": freeze_result,
            "withdrawal_governance_result": result,
            "withdrawal_authority_profile_count": len(self.authorities),
            "distribution_operator_profile_count": len(self.operators),
            "distribution_target_profile_count": len(self.targets),
            "withdrawal_policy_count": len(self.policies),
            "withdrawal_request_count": len(self.requests),
            "registry_tombstone_count": len(self.tombstones),
            "distribution_stop_record_count": len(self.stops),
            "post_withdrawal_observation_count": len(self.observations),
            "withdrawal_lifecycle_decision_count": len(self.decisions),
            "lifecycle_state_counts": {state: states.count(state) for state in sorted(LIFECYCLE_STATES)},
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--registry", default="conformance/withdrawal-governance.json")
    parser.add_argument("--transition", default="conformance/e15-a4-adoption-transition.json")
    parser.add_argument("--freeze", default="conformance/e15-a4-authority-freeze.json")
    parser.add_argument("--parent-registry", default="conformance/publication-readback.json")
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
