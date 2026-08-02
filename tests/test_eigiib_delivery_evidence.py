from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools/eigiib_delivery_evidence_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_delivery_evidence_check", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def committed(value: dict) -> dict:
    value = dict(value)
    value["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(value)}
    return value


class E15A2Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_root = Path(__file__).resolve().parents[1]
        for rel in CHECK.EXPECTED_FREEZE_PATHS:
            source = self.source_root / rel
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file():
                shutil.copyfile(source, target)
            else:
                target.write_text(f"fixture:{rel}\n", encoding="utf-8")

        parent = json.loads((self.root / "conformance/delivery-intent.json").read_text(encoding="utf-8"))
        parent["delivery_intents"] = []
        parent["delivery_decisions"] = []
        (self.root / "conformance/delivery-intent.json").write_text(json.dumps(parent), encoding="utf-8")
        registry = json.loads((self.root / "conformance/delivery-evidence.json").read_text(encoding="utf-8"))
        for field in (
            "attester_profiles", "external_attestation_policies", "transfer_attempts",
            "external_delivery_evidence", "recipient_acknowledgements", "delivery_evidence_decisions",
        ):
            registry[field] = []
        (self.root / "conformance/delivery-evidence.json").write_text(json.dumps(registry), encoding="utf-8")

        self.history_path = self.root / "history.json"
        self.history_path.write_text(json.dumps({
            "tool": "eigiib-historical-e15-a1-replay",
            "tool_version": "0.1.0",
            "standard": CHECK.HISTORY_STANDARD,
            "source_commit": CHECK.SOURCE_E15_A1_HEAD,
            "materialization": "git-archive-isolated-tree",
            "ancestry_result": "conformant",
            "historical_e14_result": "conformant",
            "e15_a1_result": "conformant",
            "unit_test_result": "conformant",
            "overall_result": "conformant",
            "findings": [],
        }), encoding="utf-8")
        self.refresh_freeze()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def refresh_freeze(self) -> None:
        entries = []
        for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS):
            raw = (self.root / rel).read_bytes()
            entries.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        freeze = {
            "standard": CHECK.FREEZE_STANDARD,
            "status": "frozen",
            "source": {"e15_a1_head_commit": CHECK.SOURCE_E15_A1_HEAD},
            "profile_revision": CHECK.PROFILE_REVISION,
            "authorities": entries,
        }
        path = self.root / "conformance/e15-a2-authority-freeze.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(freeze), encoding="utf-8")

    def checker(self) -> CHECK.Checker:
        return CHECK.Checker(self.root, history_report=Path("history.json"))

    def test_empty_registry_is_conformant(self) -> None:
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["transfer_evidence_result"], "not-evaluated")

    def test_nonconformant_parent_history_is_rejected(self) -> None:
        data = json.loads(self.history_path.read_text())
        data["e15_a1_result"] = "non-conformant"
        data["overall_result"] = "non-conformant"
        self.history_path.write_text(json.dumps(data))
        self.assertEqual(self.checker().run()["historical_continuity_result"], "non-conformant")

    def test_parent_source_substitution_is_rejected(self) -> None:
        path = self.root / "conformance/e15-a2-adoption-transition.json"
        data = json.loads(path.read_text())
        data["source"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_frozen_authority_mutation_is_rejected(self) -> None:
        (self.root / "docs/E15-A2-HUMAN-MASTERY-GUIDE.md").write_text("changed\n")
        self.assertEqual(self.checker().run()["authority_freeze_result"], "non-conformant")

    def install_base(self, *, acknowledgement_requirement: str = "required", local_result: str = "locally-completed") -> dict:
        digest = "a" * 64
        parent_path = self.root / "conformance/delivery-intent.json"
        parent = json.loads(parent_path.read_text())
        parent["delivery_intents"] = [committed({
            "id": "intent-1", "revision": "1", "endpoint": "endpoint-1", "endpoint_revision": "1",
            "carrier": "carrier-1", "carrier_revision": "1", "recipient_scope": "scope-1",
            "payload_sha256": digest, "payload_bytes": 10,
        })]
        parent["delivery_decisions"] = [committed({
            "id": "intent-decision-1", "intent": "intent-1", "intent_revision": "1",
            "sequence": 1, "state": "admissible",
        })]
        parent_path.write_text(json.dumps(parent))

        service = committed({
            "id": "attester-service", "revision": "1", "kind": "service",
            "identity_authority": "trust-root-1", "identity_state": "verified",
            "accepted_evidence_types": ["service-acceptance", "delivery-receipt", "transport-failure", "non-delivery"],
            "accepted_endpoints": ["endpoint-1"], "authentication_algorithms": ["ed25519"],
        })
        recipient = committed({
            "id": "attester-recipient", "revision": "1", "kind": "recipient-interface",
            "identity_authority": "trust-root-1", "identity_state": "verified",
            "accepted_evidence_types": ["recipient-interface-generated"],
            "accepted_endpoints": ["endpoint-1"], "authentication_algorithms": ["ed25519"],
        })
        policy = committed({
            "id": "attestation-policy-1", "revision": "1", "state": "active",
            "allowed_attesters": ["attester-service", "attester-recipient"],
            "allowed_evidence_types": ["service-acceptance", "delivery-receipt", "transport-failure", "non-delivery"],
            "required_authentication_algorithms": ["ed25519"], "max_evidence_age_seconds": 3600,
            "acknowledgement_requirement": acknowledgement_requirement,
            "allowed_acknowledgement_types": ["recipient-interface-generated"],
            "max_acknowledgement_age_seconds": 3600,
        })
        attempt = committed({
            "id": "attempt-1", "revision": "1", "intent": "intent-1", "intent_revision": "1",
            "attempt_sequence": 1, "attempt_idempotency_key": "attempt-key-1",
            "endpoint": "endpoint-1", "endpoint_revision": "1", "carrier": "carrier-1", "carrier_revision": "1",
            "recipient_scope": "scope-1", "payload_sha256": digest, "payload_bytes": 10,
            "attestation_policy": "attestation-policy-1", "attestation_policy_revision": "1",
            "started_at": "2026-08-03T00:00:00Z", "local_result": local_result,
        })
        reg_path = self.root / "conformance/delivery-evidence.json"
        reg = json.loads(reg_path.read_text())
        reg.update({
            "attester_profiles": [service, recipient], "external_attestation_policies": [policy],
            "transfer_attempts": [attempt], "external_delivery_evidence": [],
            "recipient_acknowledgements": [], "delivery_evidence_decisions": [],
        })
        reg_path.write_text(json.dumps(reg))
        return reg

    def evidence(self, *, state: str = "positive", event: str = "accepted", payload: str = "a" * 64,
                 valid_until: str = "2026-08-03T01:00:00Z") -> dict:
        return committed({
            "id": "evidence-1", "revision": "1", "attempt": "attempt-1", "attempt_revision": "1",
            "type": "service-acceptance", "attester": "attester-service", "attester_revision": "1",
            "policy": "attestation-policy-1", "policy_revision": "1", "evidence_state": state,
            "observed_event": event, "endpoint": "endpoint-1", "carrier": "carrier-1",
            "recipient_scope": "scope-1", "payload_sha256": payload,
            "issued_at": "2026-08-03T00:01:00Z", "valid_until": valid_until,
            "authentication": {"algorithm": "ed25519", "key_id": "service-key-1", "signature_sha256": "b" * 64},
            "source_reference": "fixture://service/evidence-1",
        })

    def acknowledgement(self, *, state: str = "positive", event: str = "received") -> dict:
        return committed({
            "id": "ack-1", "revision": "1", "attempt": "attempt-1", "attempt_revision": "1",
            "delivery_evidence": "evidence-1", "delivery_evidence_revision": "1",
            "type": "recipient-interface-generated", "attester": "attester-recipient", "attester_revision": "1",
            "policy": "attestation-policy-1", "policy_revision": "1", "evidence_state": state,
            "acknowledged_event": event, "endpoint": "endpoint-1", "recipient_scope": "scope-1",
            "payload_sha256": "a" * 64, "issued_at": "2026-08-03T00:02:00Z",
            "valid_until": "2026-08-03T01:00:00Z",
            "authentication": {"algorithm": "ed25519", "key_id": "recipient-key-1", "signature_sha256": "c" * 64},
            "source_reference": "fixture://recipient/ack-1",
        })

    def decision(self, *, evidence_ids: list[str], ack_ids: list[str], binding: str = "permit",
                 attester: str = "permit", freshness: str = "permit", delivery: str = "permit",
                 acknowledgement: str = "permit", lifecycle: str = "externally-attested") -> dict:
        return committed({
            "id": "decision-1", "attempt": "attempt-1", "attempt_revision": "1", "sequence": 1,
            "delivery_evidence": evidence_ids, "acknowledgements": ack_ids,
            "binding_result": binding, "attester_result": attester, "freshness_result": freshness,
            "delivery_evidence_result": delivery, "acknowledgement_result": acknowledgement,
            "lifecycle_state": lifecycle, "evaluated_at": "2026-08-03T00:10:00Z",
            "reasons": ["typed-evidence-evaluation"], "evidence_refs": ["repository-fixture"],
        })

    def write_case(self, reg: dict, evidence: list[dict], acknowledgements: list[dict], decision: dict) -> dict:
        reg["external_delivery_evidence"] = evidence
        reg["recipient_acknowledgements"] = acknowledgements
        reg["delivery_evidence_decisions"] = [decision]
        (self.root / "conformance/delivery-evidence.json").write_text(json.dumps(reg))
        self.refresh_freeze()
        return self.checker().run()

    def test_positive_external_evidence_and_acknowledgement(self) -> None:
        reg = self.install_base()
        report = self.write_case(reg, [self.evidence()], [self.acknowledgement()], self.decision(evidence_ids=["evidence-1"], ack_ids=["ack-1"]))
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["lifecycle_state_counts"]["externally-attested"], 1)

    def test_local_completion_without_external_evidence_is_in_progress(self) -> None:
        reg = self.install_base(acknowledgement_requirement="optional")
        report = self.write_case(reg, [], [], self.decision(evidence_ids=[], ack_ids=[], delivery="held", lifecycle="in-progress"))
        self.assertEqual(report["lifecycle_state_counts"]["in-progress"], 1)

    def test_service_acceptance_does_not_imply_required_acknowledgement(self) -> None:
        reg = self.install_base(acknowledgement_requirement="required")
        report = self.write_case(reg, [self.evidence()], [], self.decision(evidence_ids=["evidence-1"], ack_ids=[], acknowledgement="held", lifecycle="held"))
        self.assertEqual(report["lifecycle_state_counts"]["held"], 1)

    def test_negative_evidence_precedes_unavailable_acknowledgement(self) -> None:
        reg = self.install_base()
        ev = self.evidence(state="negative", event="failed")
        ack = self.acknowledgement(state="unavailable", event="unknown")
        report = self.write_case(reg, [ev], [ack], self.decision(evidence_ids=["evidence-1"], ack_ids=["ack-1"], delivery="deny", acknowledgement="unavailable", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_contested_evidence_is_contested(self) -> None:
        reg = self.install_base(acknowledgement_requirement="optional")
        ev = self.evidence(state="contested", event="unknown")
        report = self.write_case(reg, [ev], [], self.decision(evidence_ids=["evidence-1"], ack_ids=[], delivery="held", lifecycle="contested"))
        self.assertEqual(report["lifecycle_state_counts"]["contested"], 1)

    def test_payload_mismatch_is_rejected(self) -> None:
        reg = self.install_base(acknowledgement_requirement="optional")
        ev = self.evidence(payload="d" * 64)
        report = self.write_case(reg, [ev], [], self.decision(evidence_ids=["evidence-1"], ack_ids=[], binding="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_expired_external_evidence_is_rejected(self) -> None:
        reg = self.install_base(acknowledgement_requirement="optional")
        ev = self.evidence(valid_until="2026-08-03T00:05:00Z")
        report = self.write_case(reg, [ev], [], self.decision(evidence_ids=["evidence-1"], ack_ids=[], freshness="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_duplicate_attempt_idempotency_key_is_nonconformant(self) -> None:
        reg = self.install_base(acknowledgement_requirement="optional")
        second = dict(reg["transfer_attempts"][0])
        second.update({"id": "attempt-2", "attempt_sequence": 2})
        second["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(second)}
        reg["transfer_attempts"].append(second)
        first_decision = self.decision(evidence_ids=[], ack_ids=[], delivery="held", lifecycle="in-progress")
        second_decision = committed({
            **{k: v for k, v in first_decision.items() if k != "commitment"},
            "id": "decision-2", "attempt": "attempt-2", "sequence": 2,
        })
        reg["delivery_evidence_decisions"] = [first_decision, second_decision]
        (self.root / "conformance/delivery-evidence.json").write_text(json.dumps(reg))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")


if __name__ == "__main__":
    unittest.main()
