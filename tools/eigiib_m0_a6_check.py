#!/usr/bin/env python3
"""Validate M0-A6 E15 entry normalization without mutating the E14 freeze."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import tomllib

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-M0-A6-1.0"
HANDOFF_STANDARD = "EIGIIB-M0-A6-E15-ENTRY-1.0"
SOURCE_BRANCH = "agent/e14-a5-f1-portable-authority-rebind-workflow-neutral-publication"
SOURCE_HEAD = "472e14fbb3d92205eabf10438e90295e19125ea4"
PROFILE_REVISION = "EIGIIB-E14-1.0"
WORKING_TITLE = "Externally Attested Delivery, Durable Publication, Recipient Acknowledgement and Withdrawal Governance"
FIRST_SLICE_TITLE = "Historical Authority Continuity, Delivery Intent, Endpoint and Carrier Binding"

EXPECTED_INPUTS = [
    "e14_release_event",
    "e14_release_receipt",
    "released_object_commitment",
    "recipient_scope",
    "endpoint_identity",
    "carrier_profile",
    "delivery_policy",
    "external_attestation_policy",
    "durability_policy",
    "withdrawal_policy",
    "evaluation_context",
    "idempotency_key",
]
EXPECTED_GATE_DECISIONS = ["permit", "deny", "held", "unavailable"]
EXPECTED_EVIDENCE_STATES = ["absent", "pending", "positive", "negative", "contested", "unavailable"]
EXPECTED_DERIVED_STATES = [
    "not-started",
    "in-progress",
    "externally-attested",
    "rejected",
    "held",
    "contested",
    "unavailable",
    "withdrawn",
    "partially-withdrawn",
]
EXPECTED_SLICES = [
    ("E15-A1", ["E14-A5-F1"], FIRST_SLICE_TITLE),
    ("E15-A2", ["E15-A1"], "Transfer Attempt, External Delivery Evidence and Recipient Acknowledgement"),
    ("E15-A3", ["E15-A2"], "Durable External Publication, Registry Persistence and Independent Readback"),
    ("E15-A4", ["E15-A2", "E15-A3"], "Withdrawal, Tombstones and Post-Delivery Governance"),
    ("E15-A5", ["E15-A3", "E15-A4"], "Independent External-Evidence Matrix and Final Authority Freeze"),
]
EXPECTED_METHOD_RULES = [
    "typed-transport-declaration",
    "role-separated-diagnostics",
    "structural-before-lifecycle-interpretation",
    "role-scoped-normalization",
    "coincidence-is-not-identity",
    "local-evidence-is-not-global-state",
    "declared-composite-policy",
]
EXPECTED_SAFETY_RULES = [
    "release-event-does-not-imply-external-delivery",
    "local-send-success-does-not-imply-remote-acceptance",
    "remote-service-acceptance-does-not-imply-recipient-acknowledgement",
    "recipient-acknowledgement-does-not-prove-possession-or-human-awareness",
    "publication-does-not-imply-durability",
    "withdrawal-does-not-imply-erasure",
    "equal-values-or-identifiers-do-not-collapse-distinct-authority-roles",
    "missing-external-evidence-cannot-be-promoted-to-positive-attestation",
    "known-negative-precedes-held-and-unavailable",
    "structural-binding-precedes-lifecycle-interpretation",
]
EXPECTED_NONCLAIMS = [
    "absolute-material-delivery",
    "recipient-possession",
    "human-awareness",
    "universal-availability",
    "infinite-durability",
    "global-erasure",
    "legal-recall",
    "external-service-honesty",
    "collusion-resistance",
    "universal-interoperability",
]
REQUIRED_FILES = [
    ".github/workflows/m0-a6-e15-entry-normalization.yml",
    "conformance/M0-A6-MANUAL-REVIEW.md",
    "conformance/m0-a6-e15-entry.json",
    "docs/M0-A6-E15-NORMATIVE-ENTRY-NORMALIZATION-AND-AUTHORITY-CONTINUITY.md",
    "docs/M0-A6-HUMAN-MASTERY-GUIDE.md",
    "schemas/eigiib-m0-a6-e15-entry.schema.json",
    "tests/fixtures/m0-a6/expected-report.json",
    "tests/test_eigiib_m0_a6.py",
    "tools/eigiib_m0_a6_check.py",
]


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class ValidationError(ValueError):
    pass


class Checker:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.findings: list[Finding] = []
        self.freeze_ok = True
        self.continuity_ok = True

    def add(self, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding("error", code, path, message))

    def confined(self, relative: str, code: str, must_exist: bool = True) -> Path | None:
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            self.add(f"{code}.PATH", "path must be non-empty and repository-relative", str(relative))
            return None
        candidate = (self.root / relative).resolve(strict=False)
        try:
            candidate.relative_to(self.root)
        except ValueError:
            self.add(f"{code}.PATH", "path escapes repository root", relative)
            return None
        if must_exist and not candidate.is_file():
            self.add(f"{code}.MISSING", "required file is missing", relative)
            return None
        return candidate

    def load_json(self, relative: str, code: str) -> dict[str, Any] | None:
        path = self.confined(relative, code)
        if path is None:
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add(f"{code}.PARSE", str(exc), relative)
            return None
        if not isinstance(value, dict):
            self.add(f"{code}.TYPE", "JSON root must be an object", relative)
            return None
        return value

    def validate_required_files(self) -> None:
        for relative in REQUIRED_FILES:
            self.confined(relative, "M0A6.FILE")

    def validate_profile(self) -> None:
        path = self.confined("EIGIIB.toml", "M0A6.PROFILE")
        if path is None:
            return
        try:
            profile = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("M0A6.PROFILE.PARSE", str(exc), "EIGIIB.toml")
            return
        extensions = profile.get("extensions")
        if not isinstance(extensions, list) or "E14-1.0" not in extensions:
            self.add("M0A6.PROFILE.E14", "E14-1.0 must remain adopted", "EIGIIB.toml")
        if isinstance(extensions, list) and "E15-1.0" in extensions:
            self.add("M0A6.PROFILE.E15", "E15 must not be adopted by M0-A6", "EIGIIB.toml")
        if profile.get("revision") != PROFILE_REVISION:
            self.add("M0A6.PROFILE.REVISION", f"revision must remain {PROFILE_REVISION}", "EIGIIB.toml")
        authorities = profile.get("authorities", {})
        if isinstance(authorities, dict) and any(str(key).startswith("m0_a6") or str(key).startswith("e15") for key in authorities):
            self.add("M0A6.PROFILE.CENTRAL_MUTATION", "M0-A6 and E15 authorities must not be centrally registered before the transition bridge", "EIGIIB.toml")
        gates = profile.get("manual_gates", [])
        if isinstance(gates, list) and any(isinstance(gate, dict) and str(gate.get("id", "")).startswith(("m0-a6", "e15")) for gate in gates):
            self.add("M0A6.PROFILE.GATE", "M0-A6 or E15 manual gates must not be inserted into the frozen central profile", "EIGIIB.toml")

    def validate_no_premature_e15(self) -> None:
        patterns = (
            "extensions/E15-*",
            "schemas/eigiib-e15-*",
            "tools/eigiib_e15_*",
            "conformance/e15-*",
        )
        for pattern in patterns:
            for path in self.root.glob(pattern):
                if path.is_file():
                    self.add("M0A6.E15.PREMATURE", "E15 implementation artifact exists before the transition bridge", str(path.relative_to(self.root)))

    def validate_e14_freeze(self) -> None:
        freeze = self.load_json("conformance/e14-a5-authority-freeze.json", "M0A6.FREEZE")
        if freeze is None:
            self.freeze_ok = False
            return
        if freeze.get("standard") != "EIGIIB-E14-A5-1.0" or freeze.get("status") != "frozen":
            self.add("M0A6.FREEZE.HEADER", "unexpected E14 freeze header", "conformance/e14-a5-authority-freeze.json")
            self.freeze_ok = False
        if freeze.get("profile_revision") != PROFILE_REVISION:
            self.add("M0A6.FREEZE.PROFILE", "E14 freeze profile revision mismatch", "conformance/e14-a5-authority-freeze.json")
            self.freeze_ok = False
        entries = freeze.get("authorities")
        if not isinstance(entries, list) or not entries:
            self.add("M0A6.FREEZE.TYPE", "E14 freeze authorities must be a non-empty array", "conformance/e14-a5-authority-freeze.json")
            self.freeze_ok = False
            return
        indexed: set[str] = set()
        for position, entry in enumerate(entries):
            entry_path = f"conformance/e14-a5-authority-freeze.json.authorities[{position}]"
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                self.add("M0A6.FREEZE.ENTRY", "invalid frozen authority entry", entry_path)
                self.freeze_ok = False
                continue
            relative = entry["path"]
            if relative in indexed:
                self.add("M0A6.FREEZE.DUPLICATE", "duplicate frozen authority path", relative)
                self.freeze_ok = False
                continue
            indexed.add(relative)
            path = self.confined(relative, "M0A6.FREEZE")
            if path is None:
                self.freeze_ok = False
                continue
            data = path.read_bytes()
            if entry.get("bytes") != len(data):
                self.add("M0A6.FREEZE.BYTES", "frozen byte length differs in the current tree", relative)
                self.freeze_ok = False
            if entry.get("sha256") != hashlib.sha256(data).hexdigest():
                self.add("M0A6.FREEZE.DIGEST", "frozen digest differs in the current tree", relative)
                self.freeze_ok = False
        for mandatory in ("EIGIIB.toml", ".github/workflows/eigiib.yml", "conformance/extension-graph.json"):
            if mandatory not in indexed:
                self.add("M0A6.FREEZE.COVERAGE", "central E14 authority is absent from the freeze", mandatory)
                self.freeze_ok = False

    def validate_handoff(self) -> dict[str, Any] | None:
        handoff = self.load_json("conformance/m0-a6-e15-entry.json", "M0A6.HANDOFF")
        if handoff is None:
            return None
        if handoff.get("standard") != HANDOFF_STANDARD:
            self.add("M0A6.HANDOFF.STANDARD", "unexpected handoff standard", "conformance/m0-a6-e15-entry.json")
        if handoff.get("status") != "ready-for-e15-a1-design-not-normatively-adopted":
            self.add("M0A6.HANDOFF.STATUS", "unsafe handoff status", "conformance/m0-a6-e15-entry.json")

        source = handoff.get("source_lineage")
        if not isinstance(source, dict):
            self.add("M0A6.HANDOFF.SOURCE", "source_lineage must be an object", "source_lineage")
        else:
            exact = {
                "authority": "conformance/e14-a5-authority-freeze.json",
                "branch": SOURCE_BRANCH,
                "head_commit": SOURCE_HEAD,
                "profile_revision": PROFILE_REVISION,
                "required_terminal_slice": "E14-A5-F1",
            }
            for key, value in exact.items():
                if source.get(key) != value:
                    self.add("M0A6.HANDOFF.SOURCE", f"{key} must be {value}", f"source_lineage.{key}")

        target = handoff.get("target")
        if not isinstance(target, dict):
            self.add("M0A6.HANDOFF.TARGET", "target must be an object", "target")
        else:
            exact = {
                "identifier": "E15",
                "working_title": WORKING_TITLE,
                "adoption_state": "not-adopted",
                "extension_file": None,
                "first_principal_slice": "E15-A1",
            }
            for key, value in exact.items():
                if target.get(key) != value:
                    self.add("M0A6.HANDOFF.TARGET", f"{key} mismatch", f"target.{key}")

        gate = handoff.get("entry_gate")
        expected_gate = {
            "authority_continuity_bridge": "required-in-e15-a1",
            "central_profile_mutation": "forbidden-before-transition-bridge",
            "e14_final_closure": "complete",
            "e14_frozen_paths_unchanged": True,
            "e15_normative_text": "not-created",
            "e15_schema_and_checker": "not-created",
            "readiness": "ready-for-e15-a1-design",
        }
        if gate != expected_gate:
            self.add("M0A6.HANDOFF.GATE", "entry gate differs from the normalized contract", "entry_gate")

        if handoff.get("required_inputs") != EXPECTED_INPUTS:
            self.add("M0A6.HANDOFF.INPUTS", "required input set or order mismatch", "required_inputs")
        contract = handoff.get("input_contract")
        if not isinstance(contract, dict) or list(contract) != sorted(contract) or set(contract) != set(EXPECTED_INPUTS):
            self.add("M0A6.HANDOFF.INPUT_CONTRACT", "input contract keys must exactly cover the required inputs", "input_contract")

        vocabulary = handoff.get("decision_vocabulary")
        if not isinstance(vocabulary, dict):
            self.add("M0A6.HANDOFF.VOCABULARY", "decision vocabulary must be an object", "decision_vocabulary")
        else:
            if vocabulary.get("gate") != EXPECTED_GATE_DECISIONS:
                self.add("M0A6.HANDOFF.GATE_VOCABULARY", "gate decision vocabulary mismatch", "decision_vocabulary.gate")
            if vocabulary.get("evidence") != EXPECTED_EVIDENCE_STATES:
                self.add("M0A6.HANDOFF.EVIDENCE_VOCABULARY", "evidence vocabulary mismatch", "decision_vocabulary.evidence")
            if vocabulary.get("derived") != EXPECTED_DERIVED_STATES:
                self.add("M0A6.HANDOFF.DERIVED_VOCABULARY", "derived-state vocabulary mismatch", "decision_vocabulary.derived")

        slices = handoff.get("planned_slices")
        if not isinstance(slices, list) or len(slices) != len(EXPECTED_SLICES):
            self.add("M0A6.HANDOFF.SLICES", "planned slice count mismatch", "planned_slices")
        else:
            for entry, expected in zip(slices, EXPECTED_SLICES):
                identifier, dependencies, title = expected
                if not isinstance(entry, dict):
                    self.add("M0A6.HANDOFF.SLICE", "slice entry must be an object", identifier)
                    continue
                if entry.get("id") != identifier or entry.get("depends_on") != dependencies or entry.get("title") != title:
                    self.add("M0A6.HANDOFF.SLICE", "slice identity, dependency or title mismatch", identifier)
                if entry.get("status") != "planned-not-created":
                    self.add("M0A6.HANDOFF.SLICE_STATUS", "slice must remain planned-not-created", identifier)
                for key in ("owns", "does_not_reprove"):
                    value = entry.get(key)
                    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
                        self.add("M0A6.HANDOFF.SLICE_BOUNDARY", f"{key} must be a non-empty string array", identifier)

        continuity = handoff.get("authority_continuity")
        if not isinstance(continuity, dict):
            self.add("M0A6.HANDOFF.CONTINUITY", "authority continuity must be an object", "authority_continuity")
            self.continuity_ok = False
        else:
            exact = {
                "rule": "historical-source-commit-readback-before-descendant-central-profile-mutation",
                "frozen_source_commit": SOURCE_HEAD,
                "historical_replay_mode": "materialize-and-replay-exact-source-commit",
                "current_tree_byte_equality_required_before_e15_a1": True,
                "descendant_transition_required": True,
                "silent_retargeting_forbidden": True,
            }
            for key, value in exact.items():
                if continuity.get(key) != value:
                    self.add("M0A6.HANDOFF.CONTINUITY", f"{key} mismatch", f"authority_continuity.{key}")
                    self.continuity_ok = False
            required = continuity.get("transition_must_verify")
            if not isinstance(required, list) or len(required) != 7 or len(set(required)) != 7:
                self.add("M0A6.HANDOFF.CONTINUITY_REQUIREMENTS", "transition requirements must contain seven unique entries", "authority_continuity.transition_must_verify")
                self.continuity_ok = False

        methodology = handoff.get("methodology_translation")
        if not isinstance(methodology, dict):
            self.add("M0A6.HANDOFF.METHOD", "methodology translation must be an object", "methodology_translation")
        else:
            exact = {
                "source_status": "external-contextual-methodology-input",
                "mode": "typed-derived-rules-only",
                "direct_source_republication": False,
                "source_specific_terminology_allowed": False,
                "source_equations_allowed": False,
            }
            for key, value in exact.items():
                if methodology.get(key) != value:
                    self.add("M0A6.HANDOFF.METHOD", f"{key} mismatch", f"methodology_translation.{key}")
            rules = methodology.get("rules")
            ids = [rule.get("id") for rule in rules if isinstance(rule, dict)] if isinstance(rules, list) else []
            if ids != EXPECTED_METHOD_RULES:
                self.add("M0A6.HANDOFF.METHOD_RULES", "methodology rule set or order mismatch", "methodology_translation.rules")
            if isinstance(rules, list) and any(not isinstance(rule.get("statement"), str) or not rule.get("statement") for rule in rules if isinstance(rule, dict)):
                self.add("M0A6.HANDOFF.METHOD_STATEMENT", "methodology rule statements must be non-empty", "methodology_translation.rules")

        if handoff.get("safety_rules") != EXPECTED_SAFETY_RULES:
            self.add("M0A6.HANDOFF.SAFETY", "safety rule set or order mismatch", "safety_rules")
        if handoff.get("nonclaims") != EXPECTED_NONCLAIMS:
            self.add("M0A6.HANDOFF.NONCLAIMS", "nonclaim set or order mismatch", "nonclaims")
        return handoff

    def run(self) -> dict[str, Any]:
        self.validate_required_files()
        self.validate_profile()
        self.validate_no_premature_e15()
        self.validate_e14_freeze()
        handoff = self.validate_handoff()
        errors = bool(self.findings)
        target = handoff.get("target", {}) if isinstance(handoff, dict) else {}
        methodology = handoff.get("methodology_translation", {}) if isinstance(handoff, dict) else {}
        return {
            "tool": "eigiib-m0-a6-entry-check",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "overall_result": "non-conformant" if errors else "conformant",
            "source_head": SOURCE_HEAD,
            "target": target.get("identifier", ""),
            "adoption_state": target.get("adoption_state", ""),
            "first_principal_slice": target.get("first_principal_slice", ""),
            "planned_slice_count": len(handoff.get("planned_slices", [])) if isinstance(handoff, dict) else 0,
            "required_input_count": len(handoff.get("required_inputs", [])) if isinstance(handoff, dict) else 0,
            "methodology_rule_count": len(methodology.get("rules", [])) if isinstance(methodology, dict) else 0,
            "e14_frozen_path_result": "conformant" if self.freeze_ok else "non-conformant",
            "authority_continuity_result": "conformant" if self.continuity_ok else "non-conformant",
            "findings": [asdict(finding) for finding in sorted(self.findings)],
        }


def validate(root: Path) -> dict[str, Any]:
    return Checker(root).run()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = validate(Path(args.root))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
