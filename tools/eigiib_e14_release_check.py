#!/usr/bin/env python3
"""Static EIGIIB-E14-A5 release-boundary and authority-freeze checker."""
from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E14-A5-1.0"
PROFILE_REVISION = "EIGIIB-E14-1.0"
A1_STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0+E14-1.0"
A4_SOURCE_HEAD = "31e85dbd109ecbe8c27564cd3411f11358e87acb"
RELEASE_ACTION = "eigiib:e14:release-projection"
EVENT_STATES = {"released", "rejected", "held", "unavailable"}

EXPECTED_FREEZE_PATHS = {
    ".github/workflows/e14-a1-confidential-evidence.yml",
    ".github/workflows/e14-a2-disclosure-authorization.yml",
    ".github/workflows/e14-a3-correlation-control.yml",
    ".github/workflows/e14-a4-disclosure-revocation.yml",
    ".github/workflows/e14-a5-final-closure.yml",
    ".github/workflows/eigiib.yml",
    "EIGIIB.toml",
    "conformance/E14-A1-MANUAL-REVIEW.md",
    "conformance/E14-A2-MANUAL-REVIEW.md",
    "conformance/E14-A3-MANUAL-REVIEW.md",
    "conformance/E14-A4-MANUAL-REVIEW.md",
    "conformance/E14-A5-MANUAL-REVIEW.md",
    "conformance/E14-A5-F1-MANUAL-REVIEW.md",
    "conformance/confidential-evidence.json",
    "conformance/disclosure-authorization.json",
    "conformance/correlation-control.json",
    "conformance/disclosure-revocation.json",
    "conformance/e14-release-boundary.json",
    "conformance/e14-a1-adoption-transition.json",
    "conformance/e14-a5-verifier-matrix.json",
    "conformance/extension-graph.json",
    "docs/E14-A1-HUMAN-MASTERY-GUIDE.md",
    "docs/E14-A2-HUMAN-MASTERY-GUIDE.md",
    "docs/E14-A3-HUMAN-MASTERY-GUIDE.md",
    "docs/E14-A4-HUMAN-MASTERY-GUIDE.md",
    "docs/E14-A5-HUMAN-MASTERY-GUIDE.md",
    "docs/E14-CLOSURE-FORECAST.md",
    "docs/E14-FINAL-CLOSURE-REPORT.md",
    "extensions/E14-CONFIDENTIAL-EVIDENCE-SELECTIVE-DISCLOSURE-INFORMATION-MINIMIZATION.md",
    "extensions/E14-A2-DISCLOSURE-AUTHORIZATION-AUDIENCE-ELIGIBILITY-CONTEXT-REVALIDATION.md",
    "extensions/E14-A3-CORRELATION-CONTROL-SINGLE-USE-LINKABILITY-REPLAY.md",
    "extensions/E14-A4-REVOCATION-FRESHNESS-DISTRIBUTION-WITHDRAWAL-DISCLOSURE-ANTI-ROLLBACK-REPLAY.md",
    "extensions/E14-A5-INDEPENDENT-VERIFIER-MATRIX-RELEASE-BOUNDARY-FINAL-AUTHORITY-FREEZE.md",
    "extensions/E14-A5-F1-PORTABLE-AUTHORITY-REBIND-WORKFLOW-NEUTRAL-PUBLICATION.md",
    "schemas/eigiib-e14-confidential-evidence.schema.json",
    "schemas/eigiib-e14-a1-adoption-transition.schema.json",
    "schemas/eigiib-e14-a2-disclosure-authorization.schema.json",
    "schemas/eigiib-e14-a3-correlation-control.schema.json",
    "schemas/eigiib-e14-a4-disclosure-revocation.schema.json",
    "schemas/eigiib-e14-a5-release-boundary.schema.json",
    "schemas/eigiib-e14-a5-authority-freeze.schema.json",
    "tests/fixtures/e14-a5/expected-release-report.json",
    "tests/fixtures/e14-a5/expected-matrix-report.json",
    "tests/test_eigiib_e14_release.py",
    "tests/test_eigiib_e14_release_matrix.py",
    "tools/eigiib_confidential_evidence_check.py",
    "tools/eigiib_disclosure_authorization_check.py",
    "tools/eigiib_correlation_control_check.py",
    "tools/eigiib_disclosure_revocation_check.py",
    "tools/eigiib_e14_release_check.py",
    "tools/eigiib_e14_release_independent.py",
    "tools/eigiib_e14_release_matrix.py",
}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def derive_release_state(results: dict[str, str]) -> str:
    """Reference decision derivation used by repository and vector modes."""
    negative = {
        "upstream_result": {"rejected"},
        "policy_result": {"deny"},
        "recipient_result": {"unauthenticated"},
        "transport_result": {"unprotected"},
        "replay_result": {"replay-detected"},
    }
    if any(results.get(key) in values for key, values in negative.items()):
        return "rejected"
    if any(value == "unavailable" for value in results.values()):
        return "unavailable"
    if any(value == "held" for value in results.values()):
        return "held"
    return "released"


class Checker:
    def __init__(
        self,
        root: Path,
        registry: Path = Path("conformance/e14-release-boundary.json"),
        freeze: Path = Path("conformance/e14-a5-authority-freeze.json"),
        a1: Path = Path("conformance/confidential-evidence.json"),
        a2: Path = Path("conformance/disclosure-authorization.json"),
        a3: Path = Path("conformance/correlation-control.json"),
        a4: Path = Path("conformance/disclosure-revocation.json"),
    ):
        self.root = root.resolve()
        self.registry_path = registry
        self.freeze_path = freeze
        self.a1_path, self.a2_path, self.a3_path, self.a4_path = a1, a2, a3, a4
        self.findings: list[Finding] = []
        self.records: dict[str, dict[str, Any]] = {}
        self.projections: dict[str, dict[str, Any]] = {}
        self.a2_requests: dict[str, dict[str, Any]] = {}
        self.a2_decisions: dict[str, dict[str, Any]] = {}
        self.a3_requests: dict[str, dict[str, Any]] = {}
        self.a3_consumptions: dict[str, dict[str, Any]] = {}
        self.distributions: dict[str, dict[str, Any]] = {}
        self.a4_attempts: dict[str, dict[str, Any]] = {}
        self.a4_decisions: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.requests: dict[str, dict[str, Any]] = {}
        self.events: dict[str, dict[str, Any]] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.valid_requests: set[str] = set()
        self.valid_events: set[str] = set()
        self.derived: dict[str, dict[str, str]] = {}

    @staticmethod
    def nonempty(value: Any) -> bool:
        return isinstance(value, str) and bool(value)

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def bad(self, path: str) -> bool:
        return any(
            f.severity == "error" and (f.path == path or f.path.startswith(path + "."))
            for f in self.findings
        )

    def confined(self, rel: str, code: str, must_exist: bool = False) -> Path | None:
        if not self.nonempty(rel) or Path(rel).is_absolute():
            self.add("error", f"{code}.PATH", "path must be repository-relative", str(rel))
            return None
        path = (self.root / rel).resolve(strict=False)
        try:
            path.relative_to(self.root)
        except ValueError:
            self.add("error", f"{code}.PATH", "path escapes repository root", rel)
            return None
        if must_exist and not path.is_file():
            self.add("error", f"{code}.MISSING", "referenced file is missing", rel)
            return None
        return path

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

    def index(self, obj: dict[str, Any], key: str, code: str) -> dict[str, dict[str, Any]]:
        values = obj.get(key)
        if not isinstance(values, list):
            self.add("error", f"{code}.TYPE", f"{key} must be an array", key)
            return {}
        result: dict[str, dict[str, Any]] = {}
        for position, value in enumerate(values):
            path = f"{key}[{position}]"
            if not isinstance(value, dict):
                self.add("error", f"{code}.ITEM", "item must be an object", path)
                continue
            identifier = value.get("id")
            if not self.nonempty(identifier):
                self.add("error", f"{code}.ID", "id must be a non-empty string", path)
                continue
            if identifier in result:
                self.add("error", f"{code}.DUPLICATE", f"duplicate id {identifier}", path)
                continue
            result[identifier] = value
        return result

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

    @staticmethod
    def canonical_digest(value: dict[str, Any]) -> str:
        body = {key: item for key, item in value.items() if key != "commitment"}
        encoded = (json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def profile(self) -> None:
        try:
            profile = tomllib.loads((self.root / "EIGIIB.toml").read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "E14A5.PROFILE.PARSE", str(exc), "EIGIIB.toml")
            return
        if "E14-1.0" not in profile.get("extensions", []):
            self.add("error", "E14A5.PROFILE.ADOPTION", "E14-1.0 must be adopted", "EIGIIB.toml")
        if profile.get("revision") != PROFILE_REVISION:
            self.add("error", "E14A5.PROFILE.REVISION", f"revision must be {PROFILE_REVISION}", "EIGIIB.toml")
        expected = {
            "confidential_evidence": self.a1_path.as_posix(),
            "disclosure_authorization": self.a2_path.as_posix(),
            "correlation_control": self.a3_path.as_posix(),
            "disclosure_revocation": self.a4_path.as_posix(),
            "e14_a5_contract": "extensions/E14-A5-INDEPENDENT-VERIFIER-MATRIX-RELEASE-BOUNDARY-FINAL-AUTHORITY-FREEZE.md",
            "e14_release_boundary": self.registry_path.as_posix(),
            "e14_a5_verifier_matrix": "conformance/e14-a5-verifier-matrix.json",
            "e14_a5_authority_freeze": self.freeze_path.as_posix(),
            "e14_a5_human_mastery": "docs/E14-A5-HUMAN-MASTERY-GUIDE.md",
            "e14_final_closure_report": "docs/E14-FINAL-CLOSURE-REPORT.md",
            "e14_a5_f1_contract": "extensions/E14-A5-F1-PORTABLE-AUTHORITY-REBIND-WORKFLOW-NEUTRAL-PUBLICATION.md",
        }
        authorities = profile.get("authorities", {})
        required = profile.get("required_authorities", [])
        for key, value in expected.items():
            if not isinstance(authorities, dict) or authorities.get(key) != value:
                self.add("error", "E14A5.PROFILE.AUTHORITY", f"authority {key} must bind {value}", "EIGIIB.toml")
            else:
                self.confined(value, "E14A5.PROFILE", True)
            if not isinstance(required, list) or key not in required:
                self.add("error", "E14A5.PROFILE.REQUIRED", f"required authority missing: {key}", "EIGIIB.toml")
        gates = profile.get("manual_gates", [])
        matches = [
            gate for gate in gates
            if isinstance(gate, dict) and gate.get("id") == "e14-a5-final-closure-boundary-review"
        ] if isinstance(gates, list) else []
        exact = ("complete", "e14_a5_contract", "conformance/E14-A5-MANUAL-REVIEW.md")
        if len(matches) != 1:
            self.add("error", "E14A5.PROFILE.GATE", "E14-A5 manual gate missing or duplicated", "EIGIIB.toml")
        elif (matches[0].get("status"), matches[0].get("authority"), matches[0].get("attestation")) != exact:
            self.add("error", "E14A5.PROFILE.GATE", "E14-A5 manual gate is not exact", "EIGIIB.toml")
        else:
            self.confined(matches[0]["attestation"], "E14A5.PROFILE", True)
        correction_matches = [
            gate for gate in gates
            if isinstance(gate, dict) and gate.get("id") == "e14-a5-f1-portable-authority-rebind-review"
        ] if isinstance(gates, list) else []
        correction_exact = ("complete", "e14_a5_f1_contract", "conformance/E14-A5-F1-MANUAL-REVIEW.md")
        if len(correction_matches) != 1:
            self.add("error", "E14A5.PROFILE.F1_GATE", "E14-A5-F1 manual gate missing or duplicated", "EIGIIB.toml")
        elif (correction_matches[0].get("status"), correction_matches[0].get("authority"), correction_matches[0].get("attestation")) != correction_exact:
            self.add("error", "E14A5.PROFILE.F1_GATE", "E14-A5-F1 manual gate is not exact", "EIGIIB.toml")
        else:
            self.confined(correction_matches[0]["attestation"], "E14A5.PROFILE", True)

    def load_upstream(self) -> bool:
        a1 = self.load_json(self.a1_path, "E14A5.UPSTREAM.A1")
        a2 = self.load_json(self.a2_path, "E14A5.UPSTREAM.A2")
        a3 = self.load_json(self.a3_path, "E14A5.UPSTREAM.A3")
        a4 = self.load_json(self.a4_path, "E14A5.UPSTREAM.A4")
        if not all((a1, a2, a3, a4)):
            return False
        assert a1 is not None and a2 is not None and a3 is not None and a4 is not None
        standards = (
            (a1.get("standard"), A1_STANDARD, "A1"),
            (a2.get("standard"), "EIGIIB-E14-A2-1.0", "A2"),
            (a3.get("standard"), "EIGIIB-E14-A3-1.0", "A3"),
            (a4.get("standard"), "EIGIIB-E14-A4-1.0", "A4"),
        )
        for actual, expected, label in standards:
            if actual != expected:
                self.add("error", f"E14A5.UPSTREAM.{label}.STANDARD", f"unexpected {label} standard", f"upstream:{label}")
        self.records = self.index(a1, "records", "E14A5.UPSTREAM.RECORD")
        self.projections = self.index(a1, "projections", "E14A5.UPSTREAM.PROJECTION")
        self.a2_requests = self.index(a2, "requests", "E14A5.UPSTREAM.A2_REQUEST")
        self.a2_decisions = self.index(a2, "decisions", "E14A5.UPSTREAM.A2_DECISION")
        self.a3_requests = self.index(a3, "enforcement_requests", "E14A5.UPSTREAM.A3_REQUEST")
        self.a3_consumptions = self.index(a3, "consumptions", "E14A5.UPSTREAM.A3_CONSUMPTION")
        self.distributions = self.index(a4, "distribution_channels", "E14A5.UPSTREAM.DISTRIBUTION")
        self.a4_attempts = self.index(a4, "disclosure_attempts", "E14A5.UPSTREAM.A4_ATTEMPT")
        self.a4_decisions = self.index(a4, "decisions", "E14A5.UPSTREAM.A4_DECISION")
        return True

    def validate_policy_objects(self) -> None:
        for identifier, policy in self.policies.items():
            path = f"release-policy:{identifier}"
            if not self.nonempty(policy.get("revision")):
                self.add("error", "E14A5.POLICY.REVISION", "revision must be non-empty", path)
            if policy.get("state") not in {"active", "retired", "contested", "unavailable"}:
                self.add("error", "E14A5.POLICY.STATE", "unsupported policy state", path)
            for key in ("allowed_audiences", "allowed_purposes", "allowed_endpoints", "required_transport_properties"):
                self.string_list(policy.get(key), path, f"E14A5.POLICY.{key.upper()}", allow_empty=key == "required_transport_properties")
            maximum = policy.get("max_payload_bytes")
            if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
                self.add("error", "E14A5.POLICY.PAYLOAD", "max_payload_bytes must be a non-negative integer", path)
            if not isinstance(policy.get("require_recipient_authentication"), bool):
                self.add("error", "E14A5.POLICY.RECIPIENT", "require_recipient_authentication must be boolean", path)

    def validate_requests(self) -> None:
        fields = (
            "revision", "revocation_decision", "revocation_attempt", "revocation_attempt_revision",
            "source_record", "source_revision", "source_commitment", "projection", "projection_revision",
            "projection_commitment", "authorization_request", "authorization_request_revision",
            "authorization_decision", "correlation_enforcement_request", "correlation_enforcement_revision",
            "correlation_consumption", "correlation_consumption_revision", "distribution",
            "distribution_revision", "distribution_commitment", "audience", "audience_revision",
            "purpose", "endpoint", "policy", "policy_revision", "payload_sha256", "release_nonce",
        )
        for identifier, request in self.requests.items():
            path = f"release-request:{identifier}"
            for key in fields:
                if not self.nonempty(request.get(key)):
                    self.add("error", "E14A5.REQUEST.FIELD", f"{key} must be non-empty", path)
            if request.get("action") != RELEASE_ACTION:
                self.add("error", "E14A5.REQUEST.ACTION", f"action must be {RELEASE_ACTION}", path)
            payload_bytes = request.get("payload_bytes")
            if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool) or payload_bytes < 0:
                self.add("error", "E14A5.REQUEST.PAYLOAD", "payload_bytes must be a non-negative integer", path)
            self.string_list(request.get("transport_properties"), path, "E14A5.REQUEST.TRANSPORT", allow_empty=True)
            self.string_list(request.get("recipient_authentication_evidence"), path, "E14A5.REQUEST.RECIPIENT_EVIDENCE", allow_empty=True)
            self.string_list(request.get("transport_security_evidence"), path, "E14A5.REQUEST.TRANSPORT_EVIDENCE", allow_empty=True)
            if request.get("recipient_authentication_state") not in {"authenticated", "unauthenticated", "contested", "unavailable"}:
                self.add("error", "E14A5.REQUEST.RECIPIENT_STATE", "unsupported recipient state", path)
            if request.get("transport_state") not in {"protected", "unprotected", "contested", "unavailable"}:
                self.add("error", "E14A5.REQUEST.TRANSPORT_STATE", "unsupported transport state", path)

            policy = self.policies.get(request.get("policy"))
            a4_decision = self.a4_decisions.get(request.get("revocation_decision"))
            a4_attempt = self.a4_attempts.get(request.get("revocation_attempt"))
            distribution = self.distributions.get(request.get("distribution"))
            record = self.records.get(request.get("source_record"))
            projection = self.projections.get(request.get("projection"))
            a2_request = self.a2_requests.get(request.get("authorization_request"))
            a2_decision = self.a2_decisions.get(request.get("authorization_decision"))
            a3_request = self.a3_requests.get(request.get("correlation_enforcement_request"))
            a3_consumption = self.a3_consumptions.get(request.get("correlation_consumption"))
            for value, code, label in (
                (policy, "POLICY", "release policy"), (a4_decision, "A4_DECISION", "A4 decision"),
                (a4_attempt, "A4_ATTEMPT", "A4 attempt"), (distribution, "DISTRIBUTION", "distribution"),
                (record, "RECORD", "source record"), (projection, "PROJECTION", "projection"),
                (a2_request, "A2_REQUEST", "A2 request"), (a2_decision, "A2_DECISION", "A2 decision"),
                (a3_request, "A3_REQUEST", "A3 request"), (a3_consumption, "A3_CONSUMPTION", "A3 consumption"),
            ):
                if value is None:
                    self.add("error", f"E14A5.REQUEST.{code}", f"{label} does not resolve", path)
            if a4_decision and a4_decision.get("attempt") != request.get("revocation_attempt"):
                self.add("error", "E14A5.REQUEST.A4_LINK", "A4 decision does not bind the requested attempt", path)
            if a4_attempt:
                exact = {
                    "source_record": "source_record", "source_revision": "source_revision", "source_commitment": "source_commitment",
                    "projection": "projection", "projection_revision": "projection_revision", "projection_commitment": "projection_commitment",
                    "authorization_request": "authorization_request", "authorization_request_revision": "authorization_request_revision",
                    "authorization_decision": "authorization_decision", "correlation_enforcement_request": "enforcement_request",
                    "correlation_enforcement_revision": "enforcement_request_revision", "correlation_consumption": "correlation_consumption",
                    "correlation_consumption_revision": "correlation_consumption_revision", "distribution": "distribution",
                    "distribution_revision": "distribution_revision", "distribution_commitment": "distribution_commitment",
                }
                for request_key, attempt_key in exact.items():
                    if request.get(request_key) != a4_attempt.get(attempt_key):
                        self.add("error", "E14A5.REQUEST.A4_BOUNDARY", f"{request_key} differs from A4 attempt", path)
            if request.get("revocation_attempt_revision") != (a4_attempt or {}).get("revision"):
                self.add("error", "E14A5.REQUEST.A4_REVISION", "A4 attempt revision is stale", path)
            if record:
                if request.get("source_revision") != record.get("revision") or request.get("source_commitment") != record.get("commitment", {}).get("digest"):
                    self.add("error", "E14A5.REQUEST.RECORD_BOUNDARY", "source record boundary mismatch", path)
            if projection:
                if request.get("projection_revision") != projection.get("revision") or request.get("projection_commitment") != projection.get("commitment", {}).get("digest"):
                    self.add("error", "E14A5.REQUEST.PROJECTION_BOUNDARY", "projection boundary mismatch", path)
            if distribution:
                if request.get("distribution_revision") != distribution.get("revision") or request.get("distribution_commitment") != distribution.get("commitment", {}).get("digest"):
                    self.add("error", "E14A5.REQUEST.DISTRIBUTION_BOUNDARY", "distribution boundary mismatch", path)
                if request.get("audience") != distribution.get("audience") or request.get("purpose") != distribution.get("purpose") or request.get("endpoint") != distribution.get("endpoint"):
                    self.add("error", "E14A5.REQUEST.DISTRIBUTION_SCOPE", "release scope differs from distribution channel", path)
            if policy and request.get("policy_revision") != policy.get("revision"):
                self.add("error", "E14A5.REQUEST.POLICY_REVISION", "release policy revision is stale", path)
            if a2_request and request.get("authorization_request_revision") != a2_request.get("revision"):
                self.add("error", "E14A5.REQUEST.A2_REQUEST_REVISION", "authorization request revision is stale", path)
            if a3_request and request.get("correlation_enforcement_revision") != a3_request.get("revision"):
                self.add("error", "E14A5.REQUEST.A3_REQUEST_REVISION", "correlation request revision is stale", path)
            if a3_consumption and request.get("correlation_consumption_revision") != a3_consumption.get("revision"):
                self.add("error", "E14A5.REQUEST.A3_CONSUMPTION_REVISION", "correlation consumption revision is stale", path)
            if request.get("payload_sha256") != request.get("projection_commitment"):
                self.add("error", "E14A5.REQUEST.PAYLOAD_DIGEST", "payload digest must equal projection commitment in the reference envelope", path)
            if not self.bad(path):
                self.valid_requests.add(identifier)

    @staticmethod
    def component_results(request: dict[str, Any], policy: dict[str, Any], a4_decision: dict[str, Any]) -> dict[str, str]:
        upstream = a4_decision.get("state")
        upstream_result = upstream if upstream in {"admissible", "rejected", "held", "unavailable"} else "unavailable"
        policy_state = policy.get("state")
        if policy_state == "retired":
            policy_result = "deny"
        elif policy_state == "contested":
            policy_result = "held"
        elif policy_state == "unavailable":
            policy_result = "unavailable"
        else:
            permitted = (
                request.get("audience") in policy.get("allowed_audiences", [])
                and request.get("purpose") in policy.get("allowed_purposes", [])
                and request.get("endpoint") in policy.get("allowed_endpoints", [])
                and request.get("payload_bytes", -1) <= policy.get("max_payload_bytes", -1)
                and set(policy.get("required_transport_properties", [])) <= set(request.get("transport_properties", []))
            )
            policy_result = "permit" if permitted else "deny"
        recipient_state = request.get("recipient_authentication_state")
        recipient_result = {
            "authenticated": "authenticated", "unauthenticated": "unauthenticated",
            "contested": "held", "unavailable": "unavailable",
        }.get(recipient_state, "unavailable")
        if policy.get("require_recipient_authentication") is True and recipient_result == "authenticated" and not request.get("recipient_authentication_evidence"):
            recipient_result = "unauthenticated"
        transport_state = request.get("transport_state")
        transport_result = {
            "protected": "protected", "unprotected": "unprotected",
            "contested": "held", "unavailable": "unavailable",
        }.get(transport_state, "unavailable")
        if transport_result == "protected" and not request.get("transport_security_evidence"):
            transport_result = "unprotected"
        return {
            "upstream_result": upstream_result,
            "policy_result": policy_result,
            "recipient_result": recipient_result,
            "transport_result": transport_result,
        }

    def validate_receipt(self, receipt: dict[str, Any], event: dict[str, Any], request: dict[str, Any], path: str) -> None:
        exact = {
            "event": event.get("id"), "request": request.get("id"), "request_revision": request.get("revision"),
            "release_nonce": request.get("release_nonce"), "projection_commitment": request.get("projection_commitment"),
            "distribution_commitment": request.get("distribution_commitment"), "audience": request.get("audience"),
            "endpoint": request.get("endpoint"), "payload_sha256": request.get("payload_sha256"),
        }
        if not self.nonempty(receipt.get("revision")) or not self.nonempty(receipt.get("transport_session")):
            self.add("error", "E14A5.RECEIPT.FIELD", "receipt revision and transport_session must be non-empty", path)
        for key, value in exact.items():
            if receipt.get(key) != value:
                self.add("error", "E14A5.RECEIPT.BINDING", f"receipt {key} mismatch", path)
        commitment = receipt.get("commitment")
        if not isinstance(commitment, dict) or commitment.get("algorithm") != "sha256" or commitment.get("digest") != self.canonical_digest(receipt):
            self.add("error", "E14A5.RECEIPT.COMMITMENT", "receipt commitment mismatch", path)

    def validate_events(self) -> None:
        per_request: dict[str, int] = {}
        sequences: list[int] = []
        released_nonces: set[str] = set()
        for identifier, event in sorted(self.events.items(), key=lambda item: item[1].get("sequence", 0)):
            path = f"release-event:{identifier}"
            request_id = event.get("request")
            request = self.requests.get(request_id)
            per_request[request_id] = per_request.get(request_id, 0) + 1
            sequence = event.get("sequence")
            if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
                self.add("error", "E14A5.EVENT.SEQUENCE", "sequence must be a positive integer", path)
            else:
                sequences.append(sequence)
            if request is None:
                self.add("error", "E14A5.EVENT.REQUEST", "release request does not resolve", path)
                continue
            if request_id not in self.valid_requests:
                self.add("error", "E14A5.EVENT.REQUEST_INVALID", "release request boundary is invalid", path)
                continue
            if event.get("request_revision") != request.get("revision"):
                self.add("error", "E14A5.EVENT.REQUEST_REVISION", "release request revision is stale", path)
            if event.get("state") not in EVENT_STATES:
                self.add("error", "E14A5.EVENT.STATE", "unsupported event state", path)
            if not self.nonempty(event.get("evaluator")):
                self.add("error", "E14A5.EVENT.EVALUATOR", "evaluator must be non-empty", path)
            reasons = self.string_list(event.get("reasons"), path, "E14A5.EVENT.REASONS")
            evidence = self.string_list(event.get("evidence"), path, "E14A5.EVENT.EVIDENCE", allow_empty=True)
            policy = self.policies[request["policy"]]
            a4_decision = self.a4_decisions[request["revocation_decision"]]
            results = self.component_results(request, policy, a4_decision)
            nonce = request.get("release_nonce")
            if nonce in released_nonces:
                replay_result = "replay-detected"
            else:
                replay_result = "current"
            results["replay_result"] = replay_result
            derived_state = derive_release_state(results)
            for key, value in results.items():
                if event.get(key) != value:
                    self.add("error", "E14A5.EVENT.COMPONENT", f"{key} must be {value}", path)
            if event.get("state") != derived_state:
                self.add("error", "E14A5.EVENT.DERIVATION", f"event state must be {derived_state}", path)
            if derived_state in {"released", "rejected"} and not evidence:
                self.add("error", "E14A5.EVENT.MATERIAL_EVIDENCE", "released and rejected events require material evidence", path)
            if not reasons:
                self.add("error", "E14A5.EVENT.REASON", "at least one reason is required", path)
            receipt_id = event.get("receipt")
            if derived_state == "released":
                receipt = self.receipts.get(receipt_id)
                if receipt is None:
                    self.add("error", "E14A5.EVENT.RECEIPT", "released event requires one receipt", path)
                else:
                    self.validate_receipt(receipt, event, request, f"receipt:{receipt_id}")
                released_nonces.add(nonce)
            elif receipt_id is not None:
                self.add("error", "E14A5.EVENT.RECEIPT_FORBIDDEN", "non-released event must not reference a receipt", path)
            self.derived[identifier] = {**results, "state": derived_state}
            if not self.bad(path) and not (receipt_id and self.bad(f"receipt:{receipt_id}")):
                self.valid_events.add(identifier)
        if sequences and sorted(sequences) != list(range(1, len(sequences) + 1)):
            self.add("error", "E14A5.EVENT.SEQUENCE_ORDER", "event sequences must be unique and contiguous from 1", "release_events")
        for request_id, count in per_request.items():
            if count > 1:
                self.add("error", "E14A5.EVENT.DUPLICATE", "more than one event exists for one release request", f"release-request:{request_id}")
        referenced = {event.get("receipt") for event in self.events.values() if event.get("receipt") is not None}
        extra = set(self.receipts) - referenced
        for receipt_id in sorted(extra):
            self.add("error", "E14A5.RECEIPT.ORPHAN", "receipt is not referenced by a release event", f"receipt:{receipt_id}")

    def validate_freeze(self, freeze: dict[str, Any] | None) -> str:
        if freeze is None:
            return "non-conformant"
        path = self.freeze_path.as_posix()
        if freeze.get("standard") != STANDARD or freeze.get("status") != "frozen":
            self.add("error", "E14A5.FREEZE.HEADER", "unexpected freeze header", path)
        if freeze.get("source_head") != A4_SOURCE_HEAD:
            self.add("error", "E14A5.FREEZE.SOURCE_HEAD", "freeze must consume the exact E14-A4 head", path)
        if freeze.get("profile_revision") != PROFILE_REVISION:
            self.add("error", "E14A5.FREEZE.PROFILE", "freeze profile revision mismatch", path)
        entries = freeze.get("authorities")
        if not isinstance(entries, list):
            self.add("error", "E14A5.FREEZE.TYPE", "authorities must be an array", path)
            return "non-conformant"
        indexed: dict[str, dict[str, Any]] = {}
        for position, entry in enumerate(entries):
            entry_path = f"{path}.authorities[{position}]"
            if not isinstance(entry, dict) or not self.nonempty(entry.get("path")):
                self.add("error", "E14A5.FREEZE.ENTRY", "authority entry is invalid", entry_path)
                continue
            rel = entry["path"]
            if rel in indexed:
                self.add("error", "E14A5.FREEZE.DUPLICATE", f"duplicate frozen path {rel}", entry_path)
                continue
            indexed[rel] = entry
            file_path = self.confined(rel, "E14A5.FREEZE", True)
            if file_path is None:
                continue
            data = file_path.read_bytes()
            if entry.get("bytes") != len(data):
                self.add("error", "E14A5.FREEZE.BYTES", "frozen byte length mismatch", rel)
            if entry.get("sha256") != hashlib.sha256(data).hexdigest():
                self.add("error", "E14A5.FREEZE.DIGEST", "frozen SHA-256 mismatch", rel)
        missing = EXPECTED_FREEZE_PATHS - set(indexed)
        extra = set(indexed) - EXPECTED_FREEZE_PATHS
        for rel in sorted(missing):
            self.add("error", "E14A5.FREEZE.MISSING_AUTHORITY", "required E14 authority is not frozen", rel)
        for rel in sorted(extra):
            self.add("error", "E14A5.FREEZE.EXTRA_AUTHORITY", "unexpected authority appears in final freeze", rel)
        return "non-conformant" if any(f.severity == "error" and f.code.startswith("E14A5.FREEZE") for f in self.findings) else "conformant"

    def run(self) -> dict[str, Any]:
        self.profile()
        upstream_ok = self.load_upstream()
        registry = self.load_json(self.registry_path, "E14A5.REGISTRY")
        freeze = self.load_json(self.freeze_path, "E14A5.FREEZE")
        if registry:
            if registry.get("standard") != STANDARD:
                self.add("error", "E14A5.REGISTRY.STANDARD", "unexpected registry standard", self.registry_path.as_posix())
            if registry.get("status") != "structural-only":
                self.add("error", "E14A5.REGISTRY.STATUS", "registry must be structural-only", self.registry_path.as_posix())
            exact_paths = {
                "upstream_projection_registry": self.a1_path.as_posix(),
                "upstream_authorization_registry": self.a2_path.as_posix(),
                "upstream_correlation_registry": self.a3_path.as_posix(),
                "upstream_revocation_registry": self.a4_path.as_posix(),
            }
            for key, value in exact_paths.items():
                if registry.get(key) != value:
                    self.add("error", "E14A5.REGISTRY.UPSTREAM", f"{key} path mismatch", self.registry_path.as_posix())
            self.policies = self.index(registry, "release_policies", "E14A5.POLICY")
            self.requests = self.index(registry, "release_requests", "E14A5.REQUEST")
            self.events = self.index(registry, "release_events", "E14A5.EVENT")
            self.receipts = self.index(registry, "release_receipts", "E14A5.RECEIPT")
            self.validate_policy_objects()
            if upstream_ok:
                self.validate_requests()
                self.validate_events()
        freeze_result = self.validate_freeze(freeze)
        errors = any(f.severity == "error" for f in self.findings)
        release_result = "not-evaluated" if not self.events else (
            "conformant" if len(self.valid_events) == len(self.events) and not errors else "non-conformant"
        )
        states = [item.get("state") for item in self.derived.values()]
        upstream_errors = any(f.severity == "error" and f.code.startswith("E14A5.UPSTREAM") for f in self.findings)
        return {
            "tool": "eigiib-e14-release-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if errors else "conformant",
            "upstream_binding_result": "non-conformant" if upstream_errors else "conformant",
            "release_boundary_result": release_result,
            "authority_freeze_result": freeze_result,
            "release_policy_count": len(self.policies),
            "release_request_count": len(self.requests),
            "release_event_count": len(self.events),
            "release_receipt_count": len(self.receipts),
            "release_event_counts": {state: states.count(state) for state in sorted(EVENT_STATES)},
            "findings": [asdict(finding) for finding in sorted(self.findings)],
        }


def vector_mode(path: Path) -> int:
    value = json.loads(path.read_text(encoding="utf-8"))
    result = derive_release_state(value["inputs"])
    print(json.dumps({"id": value.get("id"), "state": result}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--registry", default="conformance/e14-release-boundary.json")
    parser.add_argument("--freeze", default="conformance/e14-a5-authority-freeze.json")
    parser.add_argument("--vector")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.vector:
        return vector_mode(Path(args.vector))
    report = Checker(Path(args.root), Path(args.registry), Path(args.freeze)).run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
