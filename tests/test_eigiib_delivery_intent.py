from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import sys

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools/eigiib_delivery_intent_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_delivery_intent_check", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def committed(value: dict) -> dict:
    value = dict(value)
    value["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(value)}
    return value


class E15A1Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_root = Path(__file__).resolve().parents[1]

        seed_paths = [
            "conformance/e15-a1-adoption-transition.json",
            "conformance/delivery-intent.json",
            "conformance/E15-A1-MANUAL-REVIEW.md",
            "docs/E15-A1-HUMAN-MASTERY-GUIDE.md",
            "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
            "tools/eigiib_historical_e14_replay.py",
        ]
        for rel in seed_paths:
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.source_root / rel, target)

        fixtures = {
            "conformance/m0-a6-e15-entry.json": "{}\n",
            "conformance/e14-a5-authority-freeze.json": "{}\n",
            "conformance/M0-A6-MANUAL-REVIEW.md": "fixture\n",
            "docs/M0-A6-HUMAN-MASTERY-GUIDE.md": "fixture\n",
        }
        for rel, content in fixtures.items():
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        self.profile = '''standard = "EIGIIB-1.0"
extensions = ["E14-1.0", "E15-1.0"]
revision = "EIGIIB-E15-draft-1.0"
required_authorities = ["m0_a6_e15_entry", "m0_a6_human_mastery", "e15", "delivery_intent", "e15_a1_transition", "e15_a1_authority_freeze", "e15_a1_human_mastery"]

[authorities]
m0_a6_e15_entry = "conformance/m0-a6-e15-entry.json"
m0_a6_human_mastery = "docs/M0-A6-HUMAN-MASTERY-GUIDE.md"
e15 = "extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md"
delivery_intent = "conformance/delivery-intent.json"
e15_a1_transition = "conformance/e15-a1-adoption-transition.json"
e15_a1_authority_freeze = "conformance/e15-a1-authority-freeze.json"
e15_a1_human_mastery = "docs/E15-A1-HUMAN-MASTERY-GUIDE.md"

[[manual_gates]]
id = "m0-a6-e15-entry-normalization-review"
status = "complete"
authority = "m0_a6_e15_entry"
attestation = "conformance/M0-A6-MANUAL-REVIEW.md"

[[manual_gates]]
id = "e15-a1-delivery-intent-boundary-review"
status = "complete"
authority = "e15"
attestation = "conformance/E15-A1-MANUAL-REVIEW.md"
'''
        (self.root / "EIGIIB.toml").write_text(self.profile, encoding="utf-8")

        self.history_path = self.root / "history.json"
        self.history_path.write_text(json.dumps({
            "tool": "eigiib-historical-e14-replay",
            "tool_version": "0.1.0",
            "standard": CHECK.HISTORY_STANDARD,
            "source_commit": CHECK.SOURCE_E14_HEAD,
            "materialization": "git-archive-isolated-tree",
            "ancestry_result": "conformant",
            "component_results": {key: "conformant" for key in ["e14", "e14-a2", "e14-a3", "e14-a4", "e14-a5", "e14-a5-matrix"]},
            "overall_result": "conformant",
            "findings": [],
        }), encoding="utf-8")

        upstream = {
            "standard": "EIGIIB-E14-A5-1.0", "status": "structural-only",
            "release_policies": [], "release_requests": [], "release_events": [], "release_receipts": [],
        }
        upstream_path = self.root / "conformance/e14-release-boundary.json"
        upstream_path.parent.mkdir(parents=True, exist_ok=True)
        upstream_path.write_text(json.dumps(upstream), encoding="utf-8")

        for rel in CHECK.EXPECTED_FREEZE_PATHS:
            target = self.root / rel
            if target.exists():
                continue
            source = self.source_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file():
                shutil.copyfile(source, target)
            else:
                target.write_text(f"fixture:{rel}\n", encoding="utf-8")
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
            "source": {"e14_head_commit": CHECK.SOURCE_E14_HEAD, "m0_a6_head_commit": CHECK.SOURCE_M0_A6_HEAD},
            "profile_revision": CHECK.PROFILE_REVISION,
            "authorities": entries,
        }
        path = self.root / "conformance/e15-a1-authority-freeze.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(freeze), encoding="utf-8")

    def checker(self) -> CHECK.Checker:
        return CHECK.Checker(self.root, history_report=Path("history.json"))

    def test_empty_structural_registry_is_conformant(self) -> None:
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["delivery_intent_result"], "not-evaluated")

    def test_nonconformant_history_is_rejected(self) -> None:
        data = json.loads(self.history_path.read_text())
        data["overall_result"] = "non-conformant"
        self.history_path.write_text(json.dumps(data))
        self.assertEqual(self.checker().run()["historical_continuity_result"], "non-conformant")

    def test_source_head_substitution_is_rejected(self) -> None:
        path = self.root / "conformance/e15-a1-adoption-transition.json"
        data = json.loads(path.read_text())
        data["source"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data))
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_profile_without_e15_is_rejected(self) -> None:
        (self.root / "EIGIIB.toml").write_text(self.profile.replace(', "E15-1.0"', ""), encoding="utf-8")
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_frozen_authority_mutation_is_rejected(self) -> None:
        (self.root / "docs/E15-A1-HUMAN-MASTERY-GUIDE.md").write_text("changed\n")
        self.assertEqual(self.checker().run()["authority_freeze_result"], "non-conformant")

    def install_positive_registry(self) -> None:
        endpoint = committed({
            "id": "endpoint-1", "revision": "1", "kind": "registry", "locator": "registry://example/unit",
            "identity_authority": "trust-root-1", "identity_state": "verified",
            "accepted_carriers": ["carrier-1"], "accepted_recipient_scopes": ["scope-1"],
        })
        carrier = committed({
            "id": "carrier-1", "revision": "1", "media_type": "application/eigiib+json", "protocol": "test",
            "integrity_algorithms": ["sha256"], "authentication_properties": ["signed"],
            "confidentiality_properties": [], "transport_properties": ["integrity", "authenticated"], "state": "active",
        })
        policy = committed({
            "id": "policy-1", "revision": "1", "state": "active", "allowed_endpoints": ["endpoint-1"],
            "allowed_carriers": ["carrier-1"], "allowed_recipient_scopes": ["scope-1"],
            "allowed_purposes": ["test"], "allowed_actions": [CHECK.DELIVERY_ACTION],
            "required_transport_properties": ["integrity"], "max_payload_bytes": 100,
        })
        digest = "a" * 64
        intent = committed({
            "id": "intent-1", "revision": "1", "release_event": "event-1", "release_receipt": "receipt-1",
            "released_object_commitment": digest, "recipient_scope": "scope-1", "endpoint": "endpoint-1",
            "endpoint_revision": "1", "carrier": "carrier-1", "carrier_revision": "1", "policy": "policy-1",
            "policy_revision": "1", "purpose": "test", "action": CHECK.DELIVERY_ACTION,
            "evaluation_context": {"id": "ctx-1", "revision": "1"}, "idempotency_key": "key-1",
            "payload_sha256": digest, "payload_bytes": 10, "requested_transport_properties": ["integrity"],
        })
        decision = committed({
            "id": "decision-1", "intent": "intent-1", "intent_revision": "1", "sequence": 1,
            "binding_result": "permit", "endpoint_result": "permit", "carrier_result": "permit",
            "policy_result": "permit", "idempotency_result": "permit", "state": "admissible",
            "reasons": ["all-gates-positive"], "evidence": ["repository-fixture"],
        })
        registry = json.loads((self.root / "conformance/delivery-intent.json").read_text())
        registry.update({
            "endpoint_profiles": [endpoint], "carrier_profiles": [carrier], "delivery_policies": [policy],
            "delivery_intents": [intent], "delivery_decisions": [decision],
        })
        (self.root / "conformance/delivery-intent.json").write_text(json.dumps(registry))
        upstream_path = self.root / "conformance/e14-release-boundary.json"
        upstream = json.loads(upstream_path.read_text())
        upstream["release_events"] = [{"id": "event-1", "state": "released", "receipt": "receipt-1"}]
        upstream["release_receipts"] = [{
            "id": "receipt-1", "event": "event-1", "projection_commitment": digest, "payload_sha256": digest,
        }]
        upstream_path.write_text(json.dumps(upstream))
        self.refresh_freeze()

    def test_positive_intent_is_admissible(self) -> None:
        self.install_positive_registry()
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["delivery_intent_result"], "conformant")
        self.assertEqual(report["delivery_decision_counts"]["admissible"], 1)

    def test_retired_carrier_precedes_unavailable_endpoint(self) -> None:
        self.install_positive_registry()
        path = self.root / "conformance/delivery-intent.json"
        data = json.loads(path.read_text())
        endpoint = data["endpoint_profiles"][0]
        endpoint["identity_state"] = "unavailable"
        endpoint["commitment"]["digest"] = CHECK.commitment_for(endpoint)
        carrier = data["carrier_profiles"][0]
        carrier["state"] = "retired"
        carrier["commitment"]["digest"] = CHECK.commitment_for(carrier)
        decision = data["delivery_decisions"][0]
        decision.update({"endpoint_result": "unavailable", "carrier_result": "deny", "state": "rejected"})
        decision["commitment"]["digest"] = CHECK.commitment_for(decision)
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["delivery_decision_counts"]["rejected"], 1)

    def test_duplicate_idempotency_key_is_rejected(self) -> None:
        self.install_positive_registry()
        path = self.root / "conformance/delivery-intent.json"
        data = json.loads(path.read_text())
        second = dict(data["delivery_intents"][0])
        second.update({"id": "intent-2", "revision": "1"})
        second["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(second)}
        data["delivery_intents"].append(second)
        data["delivery_decisions"].append(committed({
            "id": "decision-2", "intent": "intent-2", "intent_revision": "1", "sequence": 2,
            "binding_result": "permit", "endpoint_result": "permit", "carrier_result": "permit",
            "policy_result": "permit", "idempotency_result": "deny", "state": "rejected",
            "reasons": ["idempotency-replay"], "evidence": ["repository-fixture"],
        }))
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["delivery_decision_counts"]["rejected"], 1)


if __name__ == "__main__":
    unittest.main()
