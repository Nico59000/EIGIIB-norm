#!/usr/bin/env python3
"""Static EIGIIB-E16-A2 replica-placement and custody-acceptance checker."""
from __future__ import annotations
import argparse, hashlib, json, re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E16-A2-1.0"
MANIFEST_STANDARD = "EIGIIB-E16-A2-AUTHORITY-MANIFEST-1.0"
TRANSITION_STANDARD = "EIGIIB-E16-A2-TRANSITION-1.0"
FREEZE_STANDARD = "EIGIIB-E16-A2-FREEZE-1.0"
HISTORY_STANDARD = "EIGIIB-E16-A2-HISTORICAL-E16-A1-REPLAY-1.0"
PROFILE_REVISION = "EIGIIB-E16-draft-1.0"
SOURCE_E16_A1_HEAD = "7fd50a2009c6a437c7fe0b680407cf337b55cf4f"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GATES = {"permit", "deny", "held", "unavailable"}
DECISIONS = {"placement-observed", "rejected", "held", "unavailable"}
ACCEPTANCE_STATES = {"accepted", "rejected", "held", "unavailable"}
DECLARATION_STATES = {"active", "retired", "contested", "unavailable"}
OBSERVATION_STATES = {"positive", "negative", "inconclusive", "unavailable"}

EXPECTED_AUTHORITIES = {
    "contract": "extensions/E16-A2-REPLICA-PLACEMENT-CUSTODY-ACCEPTANCE-FAILURE-DOMAIN-EVIDENCE.md",
    "authority_manifest": "conformance/e16-a2-authority-manifest.json",
    "registry": "conformance/replica-placement.json",
    "transition": "conformance/e16-a2-adoption-transition.json",
    "authority_freeze": "conformance/e16-a2-authority-freeze.json",
    "human_mastery": "docs/E16-A2-HUMAN-MASTERY-GUIDE.md",
    "manual_review": "conformance/E16-A2-MANUAL-REVIEW.md",
    "registry_schema": "schemas/eigiib-e16-a2-replica-placement.schema.json",
    "manifest_schema": "schemas/eigiib-e16-a2-authority-manifest.schema.json",
    "transition_schema": "schemas/eigiib-e16-a2-adoption-transition.schema.json",
    "freeze_schema": "schemas/eigiib-e16-a2-authority-freeze.schema.json",
    "checker": "tools/eigiib_replica_placement_check.py",
    "historical_replay": "tools/eigiib_historical_e16_a1_replay.py",
    "tests": "tests/test_eigiib_replica_placement.py",
    "expected_report": "tests/fixtures/e16-a2/expected-report.json",
    "workflow": ".github/workflows/e16-a2-replica-placement.yml",
}
EXPECTED_FREEZE_PATHS = set(EXPECTED_AUTHORITIES.values()) - {
    "conformance/e16-a2-authority-freeze.json"
}
EXPECTED_FREEZE_PATHS.add("extensions/E16-EXTERNAL-CUSTODY-REPLICATION-RETENTION-RECOVERY-GOVERNANCE.md")

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")

def commitment_for(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({k: v for k, v in value.items() if k != "commitment"})).hexdigest()

def combine(values: list[str]) -> str:
    if "deny" in values:
        return "deny"
    if "unavailable" in values:
        return "unavailable"
    if "held" in values:
        return "held"
    return "permit"

def derive_state(gates: dict[str, str]) -> str:
    return {
        "deny": "rejected",
        "unavailable": "unavailable",
        "held": "held",
        "permit": "placement-observed",
    }[combine(list(gates.values()))]

class Checker:
    def __init__(
        self,
        root: Path,
        registry: Path = Path("conformance/replica-placement.json"),
        manifest: Path = Path("conformance/e16-a2-authority-manifest.json"),
        transition: Path = Path("conformance/e16-a2-adoption-transition.json"),
        freeze: Path = Path("conformance/e16-a2-authority-freeze.json"),
        history_report: Path | None = None,
    ):
        self.root = root.resolve()
        self.registry_path = registry
        self.manifest_path = manifest
        self.transition_path = transition
        self.freeze_path = freeze
        self.history_report_path = history_report
        self.findings: list[Finding] = []
        self.requests: dict[str, dict[str, Any]] = {}
        self.acceptances: dict[str, dict[str, Any]] = {}
        self.declarations: dict[str, dict[str, Any]] = {}
        self.observations: dict[str, dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self.a1_bindings: dict[str, dict[str, Any]] = {}
        self.a1_decisions: dict[str, dict[str, Any]] = {}
        self.a1_custodians: dict[str, dict[str, Any]] = {}
        self.a1_replicas: dict[str, dict[str, Any]] = {}

    def add(self, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding("error", code, path, message))

    @staticmethod
    def nonempty(value: Any) -> bool:
        return isinstance(value, str) and bool(value)

    def confined(self, rel: str, must_exist: bool = True) -> Path | None:
        if not self.nonempty(rel) or Path(rel).is_absolute():
            self.add("E16A2.PATH", "path must be repository-relative", str(rel))
            return None
        path = (self.root / rel).resolve(strict=False)
        try:
            path.relative_to(self.root)
        except ValueError:
            self.add("E16A2.PATH", "path escapes repository root", rel)
            return None
        if must_exist and not path.is_file():
            self.add("E16A2.MISSING", "required file is missing", rel)
            return None
        return path

    def load(self, rel: Path, code: str) -> dict[str, Any] | None:
        path = self.confined(rel.as_posix())
        if path is None:
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add(f"{code}.PARSE", str(exc), rel.as_posix())
            return None
        if not isinstance(value, dict):
            self.add(f"{code}.TYPE", "JSON root must be an object", rel.as_posix())
            return None
        return value

    def index(self, obj: dict[str, Any], field: str, code: str) -> dict[str, dict[str, Any]]:
        values = obj.get(field)
        out: dict[str, dict[str, Any]] = {}
        if not isinstance(values, list):
            self.add(f"{code}.TYPE", f"{field} must be an array", field)
            return out
        for idx, value in enumerate(values):
            loc = f"{field}[{idx}]"
            if not isinstance(value, dict) or not self.nonempty(value.get("id")):
                self.add(f"{code}.ITEM", "item requires a non-empty id", loc)
                continue
            if value["id"] in out:
                self.add(f"{code}.DUPLICATE", f"duplicate id {value['id']}", loc)
                continue
            out[value["id"]] = value
        return out

    def check_commitment(self, value: dict[str, Any], path: str) -> None:
        commitment = value.get("commitment")
        if (
            not isinstance(commitment, dict)
            or commitment.get("algorithm") != "sha256"
            or commitment.get("digest") != commitment_for(value)
        ):
            self.add("E16A2.COMMITMENT", "invalid canonical commitment", path)

    def check_manifest(self, manifest: dict[str, Any] | None) -> None:
        if manifest is None:
            return
        if (
            manifest.get("standard") != MANIFEST_STANDARD
            or manifest.get("status") != "authoritative-slice-overlay"
            or manifest.get("profile_revision") != PROFILE_REVISION
            or manifest.get("source_e16_a1_commit") != SOURCE_E16_A1_HEAD
        ):
            self.add("E16A2.MANIFEST.HEADER", "authority manifest header is invalid", self.manifest_path.as_posix())
        required = manifest.get("required_authorities")
        authorities = manifest.get("authorities")
        if required != list(EXPECTED_AUTHORITIES):
            self.add("E16A2.MANIFEST.REQUIRED", "required authority order changed", self.manifest_path.as_posix())
        if authorities != EXPECTED_AUTHORITIES:
            self.add("E16A2.MANIFEST.AUTHORITIES", "authority bindings changed", self.manifest_path.as_posix())
        for rel in EXPECTED_AUTHORITIES.values():
            self.confined(rel)

    def check_history(self) -> str:
        if self.history_report_path is None:
            self.add("E16A2.HISTORY.MISSING", "historical E16-A1 report is required")
            return "non-conformant"
        report = self.load(self.history_report_path, "E16A2.HISTORY")
        if report is None:
            return "non-conformant"
        if (
            report.get("standard") != HISTORY_STANDARD
            or report.get("source_commit") != SOURCE_E16_A1_HEAD
            or report.get("overall_result") != "conformant"
        ):
            self.add("E16A2.HISTORY.RESULT", "historical E16-A1 report is not conformant", self.history_report_path.as_posix())
        for key in ("m0_a7_and_e15_result", "e16_a1_result", "e16_a1_tests_result"):
            if report.get(key) != "conformant":
                self.add("E16A2.HISTORY.COMPONENT", f"{key} is not conformant", self.history_report_path.as_posix())
        return "non-conformant" if any(f.code.startswith("E16A2.HISTORY") for f in self.findings) else "conformant"

    def check_transition(self, transition: dict[str, Any] | None) -> None:
        if transition is None:
            return
        if transition.get("standard") != TRANSITION_STANDARD or transition.get("status") != "adopted-e16-a2":
            self.add("E16A2.TRANSITION.HEADER", "transition header is invalid", self.transition_path.as_posix())
        source = transition.get("source", {})
        target = transition.get("target", {})
        if (
            source.get("slice") != "E16-A1"
            or source.get("head_commit") != SOURCE_E16_A1_HEAD
            or source.get("profile_revision") != PROFILE_REVISION
            or source.get("authority_freeze") != "conformance/e16-a1-authority-freeze.json"
        ):
            self.add("E16A2.TRANSITION.SOURCE", "transition source changed", self.transition_path.as_posix())
        if (
            target.get("extension") != "E16-1.0"
            or target.get("slice") != "E16-A2"
            or target.get("profile_revision") != PROFILE_REVISION
            or target.get("authority_manifest") != self.manifest_path.as_posix()
            or target.get("registry") != self.registry_path.as_posix()
        ):
            self.add("E16A2.TRANSITION.TARGET", "transition target is invalid", self.transition_path.as_posix())
        expected = {
            "e16_a1_claims_rewritten": False,
            "e16_a1_source_freeze_mutated": False,
            "transition_is_additive": True,
            "descendant_authority_frozen_separately": True,
        }
        if transition.get("historical_preservation") != expected:
            self.add("E16A2.TRANSITION.PRESERVATION", "historical preservation contract changed", self.transition_path.as_posix())

    def check_freeze(self, freeze: dict[str, Any] | None) -> str:
        if freeze is None:
            return "non-conformant"
        if (
            freeze.get("standard") != FREEZE_STANDARD
            or freeze.get("status") != "frozen"
            or freeze.get("profile_revision") != PROFILE_REVISION
            or freeze.get("source_e16_a1_commit") != SOURCE_E16_A1_HEAD
        ):
            self.add("E16A2.FREEZE.HEADER", "authority freeze header is invalid", self.freeze_path.as_posix())
        entries = freeze.get("authorities")
        if not isinstance(entries, list):
            self.add("E16A2.FREEZE.TYPE", "authorities must be an array", self.freeze_path.as_posix())
            return "non-conformant"
        by_path: dict[str, dict[str, Any]] = {}
        for idx, entry in enumerate(entries):
            loc = f"authorities[{idx}]"
            if not isinstance(entry, dict) or not self.nonempty(entry.get("path")):
                self.add("E16A2.FREEZE.ITEM", "freeze item requires a path", loc)
                continue
            path = entry["path"]
            if path in by_path:
                self.add("E16A2.FREEZE.DUPLICATE", f"duplicate frozen path {path}", loc)
                continue
            by_path[path] = entry
        if set(by_path) != EXPECTED_FREEZE_PATHS:
            self.add("E16A2.FREEZE.PATHS", "frozen authority set changed", self.freeze_path.as_posix())
        for rel in sorted(EXPECTED_FREEZE_PATHS & set(by_path)):
            path = self.confined(rel)
            if path is None:
                continue
            raw = path.read_bytes()
            entry = by_path[rel]
            if entry.get("bytes") != len(raw) or entry.get("sha256") != hashlib.sha256(raw).hexdigest():
                self.add("E16A2.FREEZE.MISMATCH", "frozen authority bytes changed", rel)
        return "non-conformant" if any(f.code.startswith("E16A2.FREEZE") for f in self.findings) else "conformant"

    def check_a1(self) -> None:
        a1 = self.load(Path("conformance/preservation-intent.json"), "E16A2.A1")
        if a1 is None:
            return
        self.a1_custodians = self.index(a1, "custodian_profiles", "E16A2.A1.CUSTODIAN")
        self.a1_replicas = self.index(a1, "replica_profiles", "E16A2.A1.REPLICA")
        self.a1_bindings = self.index(a1, "replica_bindings", "E16A2.A1.BINDING")
        self.a1_decisions = self.index(a1, "preservation_decisions", "E16A2.A1.DECISION")

    def exact_ref(
        self,
        obj: dict[str, Any],
        ident_key: str,
        revision_key: str,
        commitment_key: str,
        records: dict[str, dict[str, Any]],
        path: str,
        code: str,
    ) -> dict[str, Any] | None:
        record = records.get(obj.get(ident_key))
        if record is None:
            self.add(code, f"{ident_key} does not resolve", path)
            return None
        commitment = record.get("commitment", {})
        if (
            obj.get(revision_key) != record.get("revision")
            or obj.get(commitment_key) != commitment.get("digest")
        ):
            self.add(code, f"{ident_key} revision or commitment mismatch", path)
            return None
        return record

    def list_strings(self, value: Any, path: str, allow_empty: bool = False) -> list[str]:
        if (
            not isinstance(value, list)
            or (not allow_empty and not value)
            or any(not self.nonempty(item) for item in value)
            or len(value) != len(set(value))
        ):
            self.add("E16A2.LIST", "must be unique non-empty strings", path)
            return []
        return value

    def acceptance_gate(self, state: Any) -> str:
        return {
            "accepted": "permit",
            "rejected": "deny",
            "held": "held",
            "unavailable": "unavailable",
        }.get(state, "deny")

    def declaration_gate(self, state: Any) -> str:
        return {
            "active": "permit",
            "retired": "deny",
            "contested": "held",
            "unavailable": "unavailable",
        }.get(state, "deny")

    def observation_gate(self, state: Any) -> str:
        return {
            "positive": "permit",
            "negative": "deny",
            "inconclusive": "held",
            "unavailable": "unavailable",
        }.get(state, "deny")

    def request_integrity(self, request: dict[str, Any], path: str) -> tuple[dict[str, Any] | None, str]:
        binding = self.exact_ref(
            request,
            "source_binding",
            "source_binding_revision",
            "source_binding_commitment",
            self.a1_bindings,
            path,
            "E16A2.REQUEST.BINDING",
        )
        gate = "permit"
        if binding is None or binding.get("state") != "bound":
            gate = "deny"
        if binding is not None:
            if (
                request.get("source_intent") != binding.get("intent")
                or request.get("source_intent_revision") != binding.get("intent_revision")
                or request.get("custodian") != binding.get("custodian")
                or request.get("custodian_revision") != binding.get("custodian_revision")
                or request.get("replica") != binding.get("replica")
                or request.get("replica_revision") != binding.get("replica_revision")
                or request.get("content_sha256") != binding.get("content_sha256")
                or request.get("content_bytes") != binding.get("content_bytes")
            ):
                self.add("E16A2.REQUEST.IDENTITY", "request differs from E16-A1 binding", path)
                gate = "deny"
            admissible = any(
                decision.get("binding") == binding.get("id")
                and decision.get("binding_revision") == binding.get("revision")
                and decision.get("state") == "admissible"
                for decision in self.a1_decisions.values()
            )
            if not admissible:
                self.add("E16A2.REQUEST.A1_DECISION", "binding lacks an admissible E16-A1 decision", path)
                gate = "deny"
        dimensions = self.list_strings(request.get("requested_failure_domain_dimensions"), f"{path}.requested_failure_domain_dimensions")
        allowed_dimensions = {
            "provider", "account", "region", "facility", "administrative", "control-plane",
            "storage-implementation", "network", "power", "encryption-key"
        }
        if any(item not in allowed_dimensions for item in dimensions):
            self.add("E16A2.REQUEST.DIMENSION", "unknown requested failure-domain dimension", path)
            gate = "deny"
        if not self.nonempty(request.get("idempotency_key")):
            self.add("E16A2.REQUEST.IDEMPOTENCY", "idempotency key is required", path)
            gate = "deny"
        if not isinstance(request.get("content_bytes"), int) or request.get("content_bytes") < 0:
            self.add("E16A2.REQUEST.BYTES", "content_bytes must be non-negative", path)
            gate = "deny"
        if not isinstance(request.get("content_sha256"), str) or not HEX64.fullmatch(request["content_sha256"]):
            self.add("E16A2.REQUEST.DIGEST", "content_sha256 must be lowercase SHA-256", path)
            gate = "deny"
        return binding, gate

    def check_registry(self, registry: dict[str, Any] | None) -> str:
        if registry is None:
            return "non-conformant"
        if (
            registry.get("standard") != STANDARD
            or registry.get("status") != "structural-only"
            or registry.get("source_e16_a1_commit") != SOURCE_E16_A1_HEAD
            or registry.get("upstream_preservation_registry") != "conformance/preservation-intent.json"
            or registry.get("upstream_e16_a1_freeze") != "conformance/e16-a1-authority-freeze.json"
            or registry.get("authority_manifest") != self.manifest_path.as_posix()
        ):
            self.add("E16A2.REGISTRY.HEADER", "registry header is invalid", self.registry_path.as_posix())

        self.requests = self.index(registry, "placement_requests", "E16A2.REQUEST")
        self.acceptances = self.index(registry, "custody_acceptances", "E16A2.ACCEPTANCE")
        self.declarations = self.index(registry, "failure_domain_declarations", "E16A2.DECLARATION")
        self.observations = self.index(registry, "placement_observations", "E16A2.OBSERVATION")
        self.decisions = self.index(registry, "placement_decisions", "E16A2.DECISION")

        idempotency: dict[str, str] = {}
        request_gates: dict[str, str] = {}
        for ident, request in self.requests.items():
            path = f"placement_request:{ident}"
            self.check_commitment(request, path)
            _, gate = self.request_integrity(request, path)
            request_gates[ident] = gate
            key = request.get("idempotency_key")
            if isinstance(key, str):
                if key in idempotency:
                    self.add("E16A2.REQUEST.IDEMPOTENCY_DUPLICATE", f"idempotency key also used by {idempotency[key]}", path)
                idempotency[key] = ident

        for ident, acceptance in self.acceptances.items():
            path = f"custody_acceptance:{ident}"
            self.check_commitment(acceptance, path)
            request = self.exact_ref(
                acceptance, "request", "request_revision", "request_commitment",
                self.requests, path, "E16A2.ACCEPTANCE.REQUEST"
            )
            if acceptance.get("acceptance_state") not in ACCEPTANCE_STATES:
                self.add("E16A2.ACCEPTANCE.STATE", "invalid acceptance state", path)
            self.list_strings(acceptance.get("accepted_scope"), f"{path}.accepted_scope", allow_empty=True)
            self.list_strings(acceptance.get("evidence_refs"), f"{path}.evidence_refs")
            if request is not None and (
                acceptance.get("custodian") != request.get("custodian")
                or acceptance.get("custodian_revision") != request.get("custodian_revision")
                or acceptance.get("replica") != request.get("replica")
                or acceptance.get("replica_revision") != request.get("replica_revision")
                or acceptance.get("content_sha256") != request.get("content_sha256")
                or acceptance.get("content_bytes") != request.get("content_bytes")
            ):
                self.add("E16A2.ACCEPTANCE.IDENTITY", "acceptance differs from placement request", path)

        required_dimensions = {
            "provider", "account", "region", "administrative",
            "control_plane", "storage_implementation"
        }
        allowed_dimension_fields = required_dimensions | {"facility", "network", "power", "encryption_key"}
        for ident, declaration in self.declarations.items():
            path = f"failure_domain_declaration:{ident}"
            self.check_commitment(declaration, path)
            replica = self.a1_replicas.get(declaration.get("replica"))
            if replica is None or declaration.get("replica_revision") != replica.get("revision"):
                self.add("E16A2.DECLARATION.REPLICA", "replica reference does not resolve exactly", path)
            if declaration.get("state") not in DECLARATION_STATES:
                self.add("E16A2.DECLARATION.STATE", "invalid declaration state", path)
            dimensions = declaration.get("dimensions")
            if not isinstance(dimensions, dict):
                self.add("E16A2.DECLARATION.DIMENSIONS", "dimensions must be an object", path)
            else:
                if not required_dimensions <= set(dimensions):
                    self.add("E16A2.DECLARATION.DIMENSIONS", "required dimensions are missing", path)
                if set(dimensions) - allowed_dimension_fields:
                    self.add("E16A2.DECLARATION.DIMENSIONS", "unknown dimension field", path)
                if any(not self.nonempty(value) for value in dimensions.values()):
                    self.add("E16A2.DECLARATION.DIMENSIONS", "dimension values must be non-empty strings", path)
            self.list_strings(declaration.get("evidence_refs"), f"{path}.evidence_refs")

        for ident, observation in self.observations.items():
            path = f"placement_observation:{ident}"
            self.check_commitment(observation, path)
            request = self.exact_ref(
                observation, "request", "request_revision", "request_commitment",
                self.requests, path, "E16A2.OBSERVATION.REQUEST"
            )
            acceptance = self.exact_ref(
                observation, "acceptance", "acceptance_revision", "acceptance_commitment",
                self.acceptances, path, "E16A2.OBSERVATION.ACCEPTANCE"
            )
            declaration = self.exact_ref(
                observation, "failure_domain_declaration", "failure_domain_declaration_revision",
                "failure_domain_declaration_commitment", self.declarations, path,
                "E16A2.OBSERVATION.DECLARATION"
            )
            if observation.get("observation_state") not in OBSERVATION_STATES:
                self.add("E16A2.OBSERVATION.STATE", "invalid observation state", path)
            observer = observation.get("observer")
            if not isinstance(observer, dict) or not self.nonempty(observer.get("id")) or not self.nonempty(observer.get("revision")):
                self.add("E16A2.OBSERVATION.OBSERVER", "observer id and revision are required", path)
            method = observation.get("method")
            if (
                not isinstance(method, dict)
                or method.get("kind") not in {"repository-witness", "custodian-receipt", "provider-api", "content-readback"}
                or not self.nonempty(method.get("implementation"))
            ):
                self.add("E16A2.OBSERVATION.METHOD", "observation method is invalid", path)
            self.list_strings(observation.get("evidence_refs"), f"{path}.evidence_refs")
            if request is not None and (
                observation.get("observed_content_sha256") != request.get("content_sha256")
                or observation.get("observed_content_bytes") != request.get("content_bytes")
            ):
                self.add("E16A2.OBSERVATION.CONTENT", "observed content differs from request", path)
            if acceptance is not None and request is not None and acceptance.get("request") != request.get("id"):
                self.add("E16A2.OBSERVATION.ACCEPTANCE_LINK", "acceptance does not bind observation request", path)
            if declaration is not None and request is not None and (
                declaration.get("replica") != request.get("replica")
                or declaration.get("replica_revision") != request.get("replica_revision")
            ):
                self.add("E16A2.OBSERVATION.DECLARATION_LINK", "declaration does not bind request replica", path)

        for ident, decision in self.decisions.items():
            path = f"placement_decision:{ident}"
            self.check_commitment(decision, path)
            request = self.exact_ref(
                decision, "request", "request_revision", "request_commitment",
                self.requests, path, "E16A2.DECISION.REQUEST"
            )
            observation = self.exact_ref(
                decision, "observation", "observation_revision", "observation_commitment",
                self.observations, path, "E16A2.DECISION.OBSERVATION"
            )
            stored_gates = decision.get("gates")
            if not isinstance(stored_gates, dict) or set(stored_gates) != {
                "a1_binding", "request", "custody_acceptance", "content_identity",
                "failure_domain_declaration", "placement_observation"
            } or any(value not in GATES for value in stored_gates.values()):
                self.add("E16A2.DECISION.GATES", "stored gates are invalid", path)
                continue
            derived = {
                "a1_binding": "deny",
                "request": "deny",
                "custody_acceptance": "deny",
                "content_identity": "deny",
                "failure_domain_declaration": "deny",
                "placement_observation": "deny",
            }
            if request is not None:
                binding = self.a1_bindings.get(request.get("source_binding"))
                derived["a1_binding"] = "permit" if binding is not None and binding.get("state") == "bound" else "deny"
                derived["request"] = request_gates.get(request["id"], "deny")
            if observation is not None:
                acceptance = self.acceptances.get(observation.get("acceptance"))
                declaration = self.declarations.get(observation.get("failure_domain_declaration"))
                derived["custody_acceptance"] = self.acceptance_gate(
                    acceptance.get("acceptance_state") if acceptance else None
                )
                derived["failure_domain_declaration"] = self.declaration_gate(
                    declaration.get("state") if declaration else None
                )
                derived["placement_observation"] = self.observation_gate(observation.get("observation_state"))
                if request is not None and (
                    observation.get("observed_content_sha256") == request.get("content_sha256")
                    and observation.get("observed_content_bytes") == request.get("content_bytes")
                ):
                    derived["content_identity"] = "permit"
                else:
                    derived["content_identity"] = "deny"
                if acceptance is None or acceptance.get("request") != (request or {}).get("id"):
                    derived["custody_acceptance"] = "deny"
                if declaration is None or declaration.get("replica") != (request or {}).get("replica"):
                    derived["failure_domain_declaration"] = "deny"
            state = derive_state(derived)
            if stored_gates != derived or decision.get("state") != state:
                self.add("E16A2.DECISION.DERIVATION", "stored decision differs from derived gates or state", path)
            if decision.get("state") not in DECISIONS:
                self.add("E16A2.DECISION.STATE", "invalid placement decision state", path)
            self.list_strings(decision.get("reasons"), f"{path}.reasons")
            self.list_strings(decision.get("evidence_refs"), f"{path}.evidence_refs")

        structural_errors = [
            finding for finding in self.findings
            if not finding.code.startswith(("E16A2.HISTORY", "E16A2.FREEZE"))
        ]
        return "non-conformant" if structural_errors else "conformant"

    def run(self) -> dict[str, Any]:
        manifest = self.load(self.manifest_path, "E16A2.MANIFEST")
        transition = self.load(self.transition_path, "E16A2.TRANSITION")
        freeze = self.load(self.freeze_path, "E16A2.FREEZE")
        registry = self.load(self.registry_path, "E16A2.REGISTRY")
        self.check_manifest(manifest)
        historical = self.check_history()
        self.check_transition(transition)
        freeze_result = self.check_freeze(freeze)
        self.check_a1()
        structural = self.check_registry(registry)
        if any(
            finding.severity == "error"
            and not finding.code.startswith(("E16A2.HISTORY", "E16A2.FREEZE"))
            for finding in self.findings
        ):
            structural = "non-conformant"
        placement_result = (
            "not-evaluated"
            if structural == "conformant" and not self.decisions
            else "conformant"
            if structural == "conformant"
            else "non-conformant"
        )
        state_counts = {state: 0 for state in sorted(DECISIONS)}
        for decision in self.decisions.values():
            state = decision.get("state")
            if state in state_counts:
                state_counts[state] += 1
        return {
            "tool": "eigiib-replica-placement-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": structural,
            "historical_continuity_result": historical,
            "authority_freeze_result": freeze_result,
            "placement_result": placement_result,
            "placement_request_count": len(self.requests),
            "custody_acceptance_count": len(self.acceptances),
            "failure_domain_declaration_count": len(self.declarations),
            "placement_observation_count": len(self.observations),
            "placement_decision_count": len(self.decisions),
            "decision_state_counts": state_counts,
            "findings": [asdict(finding) for finding in sorted(self.findings)],
        }

def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--registry", default="conformance/replica-placement.json")
    parser.add_argument("--manifest", default="conformance/e16-a2-authority-manifest.json")
    parser.add_argument("--transition", default="conformance/e16-a2-adoption-transition.json")
    parser.add_argument("--freeze", default="conformance/e16-a2-authority-freeze.json")
    parser.add_argument("--history-report")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = Checker(
        Path(args.root),
        registry=Path(args.registry),
        manifest=Path(args.manifest),
        transition=Path(args.transition),
        freeze=Path(args.freeze),
        history_report=Path(args.history_report) if args.history_report else None,
    ).run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if (
        report["structural_result"] == "conformant"
        and report["historical_continuity_result"] == "conformant"
        and report["authority_freeze_result"] == "conformant"
    ) else 1

if __name__ == "__main__":
    raise SystemExit(main())
