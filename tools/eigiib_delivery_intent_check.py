#!/usr/bin/env python3
"""Static EIGIIB-E15-A1 historical-continuity and delivery-intent checker."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import tomllib
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E15-A1-1.0"
TRANSITION_STANDARD = "EIGIIB-E15-A1-TRANSITION-1.0"
FREEZE_STANDARD = "EIGIIB-E15-A1-FREEZE-1.0"
HISTORY_STANDARD = "EIGIIB-E15-A1-HISTORICAL-E14-REPLAY-1.0"
PROFILE_REVISION = "EIGIIB-E15-draft-1.0"
FINAL_PROFILE_REVISION = "EIGIIB-E15-1.0"
SOURCE_E14_HEAD = "472e14fbb3d92205eabf10438e90295e19125ea4"
SOURCE_M0_A6_HEAD = "9cff4c1e392b6661af4b01e710f10342fe2ad402"
DELIVERY_ACTION = "eigiib:e15:deliver"
DECISION_STATES = {"admissible", "rejected", "held", "unavailable"}
ENDPOINT_STATES = {"verified", "rejected", "contested", "unavailable"}
CARRIER_STATES = {"active", "retired", "contested", "unavailable"}
POLICY_STATES = {"active", "retired", "contested", "unavailable"}

EXPECTED_INPUTS = [
    "e14_release_event", "e14_release_receipt", "released_object_commitment", "recipient_scope",
    "endpoint_identity", "carrier_profile", "delivery_policy", "external_attestation_policy",
    "durability_policy", "withdrawal_policy", "evaluation_context", "idempotency_key",
]

EXPECTED_FREEZE_PATHS = {
    ".github/workflows/e14-a2-disclosure-authorization.yml",
    ".github/workflows/e14-a3-correlation-control.yml",
    ".github/workflows/e14-a4-disclosure-revocation.yml",
    ".github/workflows/e14-a5-final-closure.yml",
    ".github/workflows/e15-a1-delivery-intent.yml",
    ".github/workflows/eigiib.yml",
    "EIGIIB.toml",
    "conformance/E15-A1-MANUAL-REVIEW.md",
    "conformance/delivery-intent.json",
    "conformance/e15-a1-adoption-transition.json",
    "conformance/extension-graph.json",
    "docs/E15-A1-HUMAN-MASTERY-GUIDE.md",
    "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
    "schemas/eigiib-e15-a1-adoption-transition.schema.json",
    "schemas/eigiib-e15-a1-authority-freeze.schema.json",
    "schemas/eigiib-e15-a1-delivery-intent.schema.json",
    "tests/fixtures/e15-a1/expected-report.json",
    "tests/test_eigiib_delivery_intent.py",
    "tools/eigiib_delivery_intent_check.py",
    "tools/eigiib_extension_graph_check.py",
    "tools/eigiib_historical_e14_replay.py",
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


def derive_state(results: dict[str, str]) -> str:
    values = list(results.values())
    if "deny" in values:
        return "rejected"
    if "unavailable" in values:
        return "unavailable"
    if "held" in values:
        return "held"
    return "admissible"


class Checker:
    def __init__(
        self,
        root: Path,
        registry: Path = Path("conformance/delivery-intent.json"),
        transition: Path = Path("conformance/e15-a1-adoption-transition.json"),
        freeze: Path = Path("conformance/e15-a1-authority-freeze.json"),
        history_report: Path | None = None,
    ):
        self.root = root.resolve()
        self.registry_path = registry
        self.transition_path = transition
        self.freeze_path = freeze
        self.history_report_path = history_report
        self.findings: list[Finding] = []
        self.endpoints: dict[str, dict[str, Any]] = {}
        self.carriers: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.intents: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.release_events: dict[str, dict[str, Any]] = {}
        self.release_receipts: dict[str, dict[str, Any]] = {}
        self.valid_intents: set[str] = set()
        self.valid_decisions: set[str] = set()
        self.derived: dict[str, dict[str, str]] = {}

    @staticmethod
    def nonempty(value: Any) -> bool:
        return isinstance(value, str) and bool(value)

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def bad(self, path: str) -> bool:
        return any(f.severity == "error" and (f.path == path or f.path.startswith(path + ".")) for f in self.findings)

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
        path = self.confined(str(rel), code, True)
        if path is None:
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
        except Exception as exc:
            self.add("error", f"{code}.PARSE", str(exc), str(rel))
            return None
        if not isinstance(value, dict):
            self.add("error", f"{code}.TYPE", "JSON root must be an object", str(rel))
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

    def check_profile(self) -> None:
        try:
            profile = tomllib.loads((self.root / "EIGIIB.toml").read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "E15A1.PROFILE.PARSE", str(exc), "EIGIIB.toml")
            return
        if "E15-1.0" not in profile.get("extensions", []):
            self.add("error", "E15A1.PROFILE.ADOPTION", "E15-1.0 must be adopted", "EIGIIB.toml")
        if profile.get("revision") not in {PROFILE_REVISION, FINAL_PROFILE_REVISION}:
            self.add("error", "E15A1.PROFILE.REVISION", f"revision must be {PROFILE_REVISION} or {FINAL_PROFILE_REVISION}", "EIGIIB.toml")
        expected = {
            "m0_a6_e15_entry": "conformance/m0-a6-e15-entry.json",
            "m0_a6_human_mastery": "docs/M0-A6-HUMAN-MASTERY-GUIDE.md",
            "e15": "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
            "delivery_intent": self.registry_path.as_posix(),
            "e15_a1_transition": self.transition_path.as_posix(),
            "e15_a1_authority_freeze": self.freeze_path.as_posix(),
            "e15_a1_human_mastery": "docs/E15-A1-HUMAN-MASTERY-GUIDE.md",
        }
        authorities = profile.get("authorities", {})
        required = profile.get("required_authorities", [])
        for key, value in expected.items():
            if not isinstance(authorities, dict) or authorities.get(key) != value:
                self.add("error", "E15A1.PROFILE.AUTHORITY", f"authority {key} must bind {value}", "EIGIIB.toml")
            else:
                self.confined(value, "E15A1.PROFILE", True)
            if not isinstance(required, list) or key not in required:
                self.add("error", "E15A1.PROFILE.REQUIRED", f"required authority missing: {key}", "EIGIIB.toml")
        gates = profile.get("manual_gates", [])
        expected_gates = {
            "m0-a6-e15-entry-normalization-review": ("complete", "m0_a6_e15_entry", "conformance/M0-A6-MANUAL-REVIEW.md"),
            "e15-a1-delivery-intent-boundary-review": ("complete", "e15", "conformance/E15-A1-MANUAL-REVIEW.md"),
        }
        for gate_id, exact in expected_gates.items():
            matches = [g for g in gates if isinstance(g, dict) and g.get("id") == gate_id] if isinstance(gates, list) else []
            if len(matches) != 1:
                self.add("error", "E15A1.PROFILE.GATE", f"{gate_id} missing or duplicated", "EIGIIB.toml")
            elif (matches[0].get("status"), matches[0].get("authority"), matches[0].get("attestation")) != exact:
                self.add("error", "E15A1.PROFILE.GATE", f"{gate_id} is not exact", "EIGIIB.toml")
            else:
                self.confined(exact[2], "E15A1.PROFILE", True)

    def check_history_report(self) -> str:
        if self.history_report_path is None:
            self.add("error", "E15A1.HISTORY.REPORT", "historical E14 replay report is required", "")
            return "non-conformant"
        report = self.load_json(self.history_report_path, "E15A1.HISTORY")
        if report is None:
            return "non-conformant"
        if report.get("standard") != HISTORY_STANDARD or report.get("source_commit") != SOURCE_E14_HEAD:
            self.add("error", "E15A1.HISTORY.HEADER", "historical replay header mismatch", str(self.history_report_path))
        if report.get("overall_result") != "conformant":
            self.add("error", "E15A1.HISTORY.RESULT", "historical E14 replay is not conformant", str(self.history_report_path))
        required = {"e14", "e14-a2", "e14-a3", "e14-a4", "e14-a5", "e14-a5-matrix"}
        components = report.get("component_results")
        if not isinstance(components, dict) or any(components.get(cid) != "conformant" for cid in required):
            self.add("error", "E15A1.HISTORY.COMPONENT", "historical component coverage is incomplete", str(self.history_report_path))
        return "non-conformant" if any(f.code.startswith("E15A1.HISTORY") for f in self.findings) else "conformant"

    def check_transition(self, transition: dict[str, Any] | None) -> None:
        if transition is None:
            return
        path = self.transition_path.as_posix()
        if transition.get("standard") != TRANSITION_STANDARD or transition.get("status") != "adopted-e15-a1":
            self.add("error", "E15A1.TRANSITION.HEADER", "unexpected transition header", path)
        source = transition.get("source")
        if not isinstance(source, dict):
            self.add("error", "E15A1.TRANSITION.SOURCE", "source must be an object", path)
        else:
            exact = {
                "head_commit": SOURCE_E14_HEAD,
                "profile_revision": "EIGIIB-E14-1.0",
                "m0_a6_head_commit": SOURCE_M0_A6_HEAD,
                "m0_a6_entry_authority": "conformance/m0-a6-e15-entry.json",
                "e14_freeze_authority": "conformance/e14-a5-authority-freeze.json",
            }
            for key, value in exact.items():
                if source.get(key) != value:
                    self.add("error", "E15A1.TRANSITION.SOURCE", f"{key} mismatch", path)
            for key in ("m0_a6_entry_authority", "e14_freeze_authority"):
                if source.get(key) == exact[key]:
                    self.confined(exact[key], "E15A1.TRANSITION", True)
        replay = transition.get("historical_replay")
        if not isinstance(replay, dict):
            self.add("error", "E15A1.TRANSITION.REPLAY", "historical_replay must be an object", path)
        else:
            if replay.get("mode") != "materialize-and-replay-exact-source-commit":
                self.add("error", "E15A1.TRANSITION.REPLAY", "historical replay mode mismatch", path)
            if replay.get("tool") != "tools/eigiib_historical_e14_replay.py":
                self.add("error", "E15A1.TRANSITION.REPLAY", "historical replay tool mismatch", path)
            self.confined("tools/eigiib_historical_e14_replay.py", "E15A1.TRANSITION", True)
        target = transition.get("target")
        if not isinstance(target, dict) or (target.get("extension"), target.get("slice"), target.get("adoption_state")) != ("E15-1.0", "E15-A1", "adopted"):
            self.add("error", "E15A1.TRANSITION.TARGET", "E15-A1 target adoption is not exact", path)
        inputs = transition.get("consumed_inputs")
        if not isinstance(inputs, dict) or list(inputs) != EXPECTED_INPUTS:
            self.add("error", "E15A1.TRANSITION.INPUTS", "consumed input set or order mismatch", path)
        preservation = transition.get("historical_preservation")
        if (
            not isinstance(preservation, dict)
            or preservation.get("e14_claims_rewritten") is not False
            or preservation.get("e14_source_freeze_mutated") is not False
            or preservation.get("transition_is_additive") is not True
            or preservation.get("descendant_profile_frozen_separately") is not True
        ):
            self.add("error", "E15A1.TRANSITION.PRESERVATION", "historical preservation is not exact", path)

    def check_upstream(self, registry: dict[str, Any]) -> None:
        if registry.get("upstream_release_registry") != "conformance/e14-release-boundary.json":
            self.add("error", "E15A1.REGISTRY.UPSTREAM", "upstream release registry mismatch", self.registry_path.as_posix())
            return
        upstream = self.load_json(Path("conformance/e14-release-boundary.json"), "E15A1.UPSTREAM")
        if upstream is None:
            return
        self.release_events = self.index(upstream, "release_events", "E15A1.UPSTREAM.EVENT")
        self.release_receipts = self.index(upstream, "release_receipts", "E15A1.UPSTREAM.RECEIPT")

    def check_commitment(self, value: dict[str, Any], path: str, code: str) -> None:
        commitment = value.get("commitment")
        if not isinstance(commitment, dict) or commitment.get("algorithm") != "sha256" or commitment.get("digest") != commitment_for(value):
            self.add("error", code, "canonical commitment mismatch", path)

    def validate_endpoints(self) -> None:
        for identifier, value in self.endpoints.items():
            path = f"endpoint:{identifier}"
            for field in ("revision", "locator", "identity_authority"):
                if not self.nonempty(value.get(field)):
                    self.add("error", "E15A1.ENDPOINT.FIELD", f"{field} must be non-empty", path)
            if value.get("kind") not in {"registry", "service", "recipient-interface"}:
                self.add("error", "E15A1.ENDPOINT.KIND", "unsupported endpoint kind", path)
            if value.get("identity_state") not in ENDPOINT_STATES:
                self.add("error", "E15A1.ENDPOINT.STATE", "unsupported identity state", path)
            self.string_list(value.get("accepted_carriers"), path, "E15A1.ENDPOINT.CARRIERS")
            self.string_list(value.get("accepted_recipient_scopes"), path, "E15A1.ENDPOINT.SCOPES")
            self.check_commitment(value, path, "E15A1.ENDPOINT.COMMITMENT")

    def validate_carriers(self) -> None:
        for identifier, value in self.carriers.items():
            path = f"carrier:{identifier}"
            for field in ("revision", "media_type", "protocol"):
                if not self.nonempty(value.get(field)):
                    self.add("error", "E15A1.CARRIER.FIELD", f"{field} must be non-empty", path)
            if value.get("state") not in CARRIER_STATES:
                self.add("error", "E15A1.CARRIER.STATE", "unsupported carrier state", path)
            for field in ("integrity_algorithms", "authentication_properties", "confidentiality_properties", "transport_properties"):
                self.string_list(value.get(field), path, f"E15A1.CARRIER.{field.upper()}", allow_empty=True)
            self.check_commitment(value, path, "E15A1.CARRIER.COMMITMENT")

    def validate_policies(self) -> None:
        for identifier, value in self.policies.items():
            path = f"policy:{identifier}"
            if not self.nonempty(value.get("revision")):
                self.add("error", "E15A1.POLICY.REVISION", "revision must be non-empty", path)
            if value.get("state") not in POLICY_STATES:
                self.add("error", "E15A1.POLICY.STATE", "unsupported policy state", path)
            for field in ("allowed_endpoints", "allowed_carriers", "allowed_recipient_scopes", "allowed_purposes", "allowed_actions"):
                self.string_list(value.get(field), path, f"E15A1.POLICY.{field.upper()}")
            self.string_list(value.get("required_transport_properties"), path, "E15A1.POLICY.TRANSPORT", allow_empty=True)
            maximum = value.get("max_payload_bytes")
            if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
                self.add("error", "E15A1.POLICY.PAYLOAD", "max_payload_bytes must be a non-negative integer", path)
            self.check_commitment(value, path, "E15A1.POLICY.COMMITMENT")

    def validate_intents(self) -> None:
        fields = (
            "revision", "release_event", "release_receipt", "released_object_commitment", "recipient_scope",
            "endpoint", "endpoint_revision", "carrier", "carrier_revision", "policy", "policy_revision",
            "purpose", "action", "idempotency_key", "payload_sha256",
        )
        for identifier, intent in self.intents.items():
            path = f"intent:{identifier}"
            for field in fields:
                if not self.nonempty(intent.get(field)):
                    self.add("error", "E15A1.INTENT.FIELD", f"{field} must be non-empty", path)
            if intent.get("action") != DELIVERY_ACTION:
                self.add("error", "E15A1.INTENT.ACTION", f"action must be {DELIVERY_ACTION}", path)
            payload_bytes = intent.get("payload_bytes")
            if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool) or payload_bytes < 0:
                self.add("error", "E15A1.INTENT.PAYLOAD", "payload_bytes must be a non-negative integer", path)
            self.string_list(intent.get("requested_transport_properties"), path, "E15A1.INTENT.TRANSPORT", allow_empty=True)
            context = intent.get("evaluation_context")
            if not isinstance(context, dict) or not self.nonempty(context.get("id")) or not self.nonempty(context.get("revision")):
                self.add("error", "E15A1.INTENT.CONTEXT", "evaluation_context requires id and revision", path)

            event = self.release_events.get(intent.get("release_event"))
            receipt = self.release_receipts.get(intent.get("release_receipt"))
            endpoint = self.endpoints.get(intent.get("endpoint"))
            carrier = self.carriers.get(intent.get("carrier"))
            policy = self.policies.get(intent.get("policy"))
            if event is None:
                self.add("error", "E15A1.INTENT.EVENT", "release event does not resolve", path)
            elif event.get("state") != "released":
                self.add("error", "E15A1.INTENT.EVENT_STATE", "source event must be released", path)
            if receipt is None:
                self.add("error", "E15A1.INTENT.RECEIPT", "release receipt does not resolve", path)
            if event and receipt:
                if event.get("receipt") != receipt.get("id") or receipt.get("event") != event.get("id"):
                    self.add("error", "E15A1.INTENT.RECEIPT_BINDING", "receipt does not bind the release event", path)
                for field in ("projection_commitment", "payload_sha256"):
                    if receipt.get(field) != intent.get("released_object_commitment"):
                        self.add("error", "E15A1.INTENT.RELEASED_COMMITMENT", f"receipt {field} mismatch", path)
            if intent.get("payload_sha256") != intent.get("released_object_commitment"):
                self.add("error", "E15A1.INTENT.PAYLOAD_DIGEST", "payload digest must equal released object commitment", path)
            if endpoint is None:
                self.add("error", "E15A1.INTENT.ENDPOINT", "endpoint does not resolve", path)
            elif endpoint.get("revision") != intent.get("endpoint_revision"):
                self.add("error", "E15A1.INTENT.ENDPOINT_REVISION", "endpoint revision is stale", path)
            if carrier is None:
                self.add("error", "E15A1.INTENT.CARRIER", "carrier does not resolve", path)
            elif carrier.get("revision") != intent.get("carrier_revision"):
                self.add("error", "E15A1.INTENT.CARRIER_REVISION", "carrier revision is stale", path)
            if policy is None:
                self.add("error", "E15A1.INTENT.POLICY", "policy does not resolve", path)
            elif policy.get("revision") != intent.get("policy_revision"):
                self.add("error", "E15A1.INTENT.POLICY_REVISION", "policy revision is stale", path)
            self.check_commitment(intent, path, "E15A1.INTENT.COMMITMENT")
            if not self.bad(path):
                self.valid_intents.add(identifier)

    @staticmethod
    def component_results(intent: dict[str, Any], endpoint: dict[str, Any], carrier: dict[str, Any],
                          policy: dict[str, Any], consumed: set[str]) -> dict[str, str]:
        endpoint_result = {
            "verified": "permit", "rejected": "deny", "contested": "held", "unavailable": "unavailable"
        }.get(endpoint.get("identity_state"), "unavailable")
        if endpoint_result == "permit" and (
            intent.get("carrier") not in endpoint.get("accepted_carriers", [])
            or intent.get("recipient_scope") not in endpoint.get("accepted_recipient_scopes", [])
        ):
            endpoint_result = "deny"

        carrier_result = {
            "active": "permit", "retired": "deny", "contested": "held", "unavailable": "unavailable"
        }.get(carrier.get("state"), "unavailable")

        state = policy.get("state")
        if state == "retired":
            policy_result = "deny"
        elif state == "contested":
            policy_result = "held"
        elif state == "unavailable":
            policy_result = "unavailable"
        else:
            permitted = (
                intent.get("endpoint") in policy.get("allowed_endpoints", [])
                and intent.get("carrier") in policy.get("allowed_carriers", [])
                and intent.get("recipient_scope") in policy.get("allowed_recipient_scopes", [])
                and intent.get("purpose") in policy.get("allowed_purposes", [])
                and intent.get("action") in policy.get("allowed_actions", [])
                and intent.get("payload_bytes", -1) <= policy.get("max_payload_bytes", -1)
                and set(policy.get("required_transport_properties", [])) <= set(intent.get("requested_transport_properties", []))
                and set(intent.get("requested_transport_properties", [])) <= set(carrier.get("transport_properties", []))
            )
            policy_result = "permit" if permitted else "deny"
        idempotency_result = "deny" if intent.get("idempotency_key") in consumed else "permit"
        return {
            "binding_result": "permit",
            "endpoint_result": endpoint_result,
            "carrier_result": carrier_result,
            "policy_result": policy_result,
            "idempotency_result": idempotency_result,
        }

    def validate_decisions(self) -> None:
        consumed: set[str] = set()
        per_intent: dict[str, int] = {}
        sequences: list[int] = []
        ordered = sorted(self.decisions.items(), key=lambda item: item[1].get("sequence", 0))
        for identifier, decision in ordered:
            path = f"decision:{identifier}"
            intent_id = decision.get("intent")
            intent = self.intents.get(intent_id)
            per_intent[intent_id] = per_intent.get(intent_id, 0) + 1
            sequence = decision.get("sequence")
            if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
                self.add("error", "E15A1.DECISION.SEQUENCE", "sequence must be a positive integer", path)
            else:
                sequences.append(sequence)
            if intent is None or intent_id not in self.valid_intents:
                self.add("error", "E15A1.DECISION.INTENT", "intent does not resolve to a valid intent", path)
                continue
            if decision.get("intent_revision") != intent.get("revision"):
                self.add("error", "E15A1.DECISION.REVISION", "intent revision is stale", path)
            endpoint = self.endpoints[intent["endpoint"]]
            carrier = self.carriers[intent["carrier"]]
            policy = self.policies[intent["policy"]]
            results = self.component_results(intent, endpoint, carrier, policy, consumed)
            derived = derive_state(results)
            for key, value in results.items():
                if decision.get(key) != value:
                    self.add("error", "E15A1.DECISION.COMPONENT", f"{key} must be {value}", path)
            if decision.get("state") != derived:
                self.add("error", "E15A1.DECISION.DERIVATION", f"state must be {derived}", path)
            reasons = self.string_list(decision.get("reasons"), path, "E15A1.DECISION.REASONS")
            evidence = self.string_list(decision.get("evidence"), path, "E15A1.DECISION.EVIDENCE", allow_empty=True)
            if derived in {"admissible", "rejected"} and not evidence:
                self.add("error", "E15A1.DECISION.MATERIAL_EVIDENCE", "admissible and rejected decisions require evidence", path)
            if not reasons:
                self.add("error", "E15A1.DECISION.REASON", "at least one reason is required", path)
            self.check_commitment(decision, path, "E15A1.DECISION.COMMITMENT")
            if derived == "admissible":
                consumed.add(intent["idempotency_key"])
            self.derived[identifier] = {**results, "state": derived}
            if not self.bad(path):
                self.valid_decisions.add(identifier)
        if sequences and sorted(sequences) != list(range(1, len(sequences) + 1)):
            self.add("error", "E15A1.DECISION.SEQUENCE_ORDER", "sequences must be unique and contiguous from 1", "delivery_decisions")
        for intent_id, count in per_intent.items():
            if count > 1:
                self.add("error", "E15A1.DECISION.DUPLICATE", "more than one decision exists for one intent", f"intent:{intent_id}")

    def validate_freeze(self, freeze: dict[str, Any] | None) -> str:
        if freeze is None:
            return "non-conformant"
        path = self.freeze_path.as_posix()
        if freeze.get("standard") != FREEZE_STANDARD or freeze.get("status") != "frozen":
            self.add("error", "E15A1.FREEZE.HEADER", "unexpected freeze header", path)
        if freeze.get("profile_revision") != PROFILE_REVISION:
            self.add("error", "E15A1.FREEZE.PROFILE", "profile revision mismatch", path)
        source = freeze.get("source")
        if not isinstance(source, dict) or source.get("e14_head_commit") != SOURCE_E14_HEAD or source.get("m0_a6_head_commit") != SOURCE_M0_A6_HEAD:
            self.add("error", "E15A1.FREEZE.SOURCE", "freeze source mismatch", path)
        entries = freeze.get("authorities")
        if not isinstance(entries, list):
            self.add("error", "E15A1.FREEZE.TYPE", "authorities must be an array", path)
            return "non-conformant"
        indexed: dict[str, dict[str, Any]] = {}
        for pos, entry in enumerate(entries):
            entry_path = f"{path}.authorities[{pos}]"
            if not isinstance(entry, dict) or not self.nonempty(entry.get("path")):
                self.add("error", "E15A1.FREEZE.ENTRY", "authority entry is invalid", entry_path)
                continue
            rel = entry["path"]
            if rel in indexed:
                self.add("error", "E15A1.FREEZE.DUPLICATE", f"duplicate frozen path {rel}", entry_path)
                continue
            indexed[rel] = entry
            file_path = self.confined(rel, "E15A1.FREEZE", True)
            if file_path is None:
                continue
            raw = file_path.read_bytes()
            if entry.get("bytes") != len(raw):
                self.add("error", "E15A1.FREEZE.BYTES", "frozen byte length mismatch", rel)
            if entry.get("sha256") != hashlib.sha256(raw).hexdigest():
                self.add("error", "E15A1.FREEZE.DIGEST", "frozen SHA-256 mismatch", rel)
        for rel in sorted(EXPECTED_FREEZE_PATHS - set(indexed)):
            self.add("error", "E15A1.FREEZE.MISSING", "required E15-A1 authority is not frozen", rel)
        for rel in sorted(set(indexed) - EXPECTED_FREEZE_PATHS):
            self.add("error", "E15A1.FREEZE.EXTRA", "unexpected authority is frozen", rel)
        return "non-conformant" if any(f.code.startswith("E15A1.FREEZE") for f in self.findings) else "conformant"

    def run(self) -> dict[str, Any]:
        self.check_profile()
        history_result = self.check_history_report()
        transition = self.load_json(self.transition_path, "E15A1.TRANSITION")
        self.check_transition(transition)
        registry = self.load_json(self.registry_path, "E15A1.REGISTRY")
        freeze = self.load_json(self.freeze_path, "E15A1.FREEZE")
        if registry is not None:
            if registry.get("standard") != STANDARD or registry.get("status") != "structural-only":
                self.add("error", "E15A1.REGISTRY.HEADER", "unexpected registry header", self.registry_path.as_posix())
            if registry.get("source_e14_commit") != SOURCE_E14_HEAD:
                self.add("error", "E15A1.REGISTRY.SOURCE", "source E14 commit mismatch", self.registry_path.as_posix())
            self.check_upstream(registry)
            self.endpoints = self.index(registry, "endpoint_profiles", "E15A1.ENDPOINT")
            self.carriers = self.index(registry, "carrier_profiles", "E15A1.CARRIER")
            self.policies = self.index(registry, "delivery_policies", "E15A1.POLICY")
            self.intents = self.index(registry, "delivery_intents", "E15A1.INTENT")
            self.decisions = self.index(registry, "delivery_decisions", "E15A1.DECISION")
            self.validate_endpoints()
            self.validate_carriers()
            self.validate_policies()
            self.validate_intents()
            self.validate_decisions()
        freeze_result = self.validate_freeze(freeze)
        errors = any(f.severity == "error" for f in self.findings)
        intent_result = "not-evaluated" if not self.intents else (
            "conformant" if len(self.valid_decisions) == len(self.decisions) and len(self.decisions) == len(self.intents) and not errors
            else "non-conformant"
        )
        states = [value.get("state") for value in self.derived.values()]
        return {
            "tool": "eigiib-delivery-intent-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if errors else "conformant",
            "historical_continuity_result": history_result,
            "authority_freeze_result": freeze_result,
            "delivery_intent_result": intent_result,
            "endpoint_profile_count": len(self.endpoints),
            "carrier_profile_count": len(self.carriers),
            "delivery_policy_count": len(self.policies),
            "delivery_intent_count": len(self.intents),
            "delivery_decision_count": len(self.decisions),
            "delivery_decision_counts": {state: states.count(state) for state in sorted(DECISION_STATES)},
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--registry", default="conformance/delivery-intent.json")
    parser.add_argument("--transition", default="conformance/e15-a1-adoption-transition.json")
    parser.add_argument("--freeze", default="conformance/e15-a1-authority-freeze.json")
    parser.add_argument("--history-report", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = Checker(
        Path(args.root),
        Path(args.registry),
        Path(args.transition),
        Path(args.freeze),
        Path(args.history_report),
    ).run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
