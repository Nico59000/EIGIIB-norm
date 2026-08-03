from __future__ import annotations
import copy, hashlib, importlib.util, json, shutil, sys, tempfile, unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("e16a2check", SOURCE / "tools/eigiib_replica_placement_check.py")
CHECK = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CHECK
spec.loader.exec_module(CHECK)

def committed(value):
    value = copy.deepcopy(value)
    value["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(value)}
    return value

class ReplicaPlacementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        needed = CHECK.EXPECTED_FREEZE_PATHS | {
            "conformance/e16-a2-authority-freeze.json",
            "conformance/e16-a1-authority-freeze.json",
            "conformance/preservation-intent.json",
        }
        for rel in needed:
            source = SOURCE / rel
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file():
                shutil.copyfile(source, target)
            else:
                target.write_text("fixture\n", encoding="utf-8")
        self.history = self.root / "history.json"
        self.history.write_text(json.dumps({
            "standard": CHECK.HISTORY_STANDARD,
            "source_commit": CHECK.SOURCE_E16_A1_HEAD,
            "overall_result": "conformant",
            "m0_a7_and_e15_result": "conformant",
            "e16_a1_result": "conformant",
            "e16_a1_tests_result": "conformant",
        }), encoding="utf-8")
        self.refresh_freeze()

    def tearDown(self):
        self.temp.cleanup()

    def refresh_freeze(self):
        entries = []
        for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS):
            raw = (self.root / rel).read_bytes()
            entries.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        (self.root / "conformance/e16-a2-authority-freeze.json").write_text(json.dumps({
            "standard": CHECK.FREEZE_STANDARD,
            "status": "frozen",
            "profile_revision": CHECK.PROFILE_REVISION,
            "source_e16_a1_commit": CHECK.SOURCE_E16_A1_HEAD,
            "authorities": entries,
        }), encoding="utf-8")

    def checker(self):
        return CHECK.Checker(self.root, history_report=Path("history.json"))

    def test_empty_registry(self):
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["placement_result"], "not-evaluated")

    def test_history_failure(self):
        data = json.loads(self.history.read_text())
        data["overall_result"] = "non-conformant"
        self.history.write_text(json.dumps(data))
        self.assertEqual(self.checker().run()["historical_continuity_result"], "non-conformant")

    def test_source_substitution(self):
        path = self.root / "conformance/e16-a2-adoption-transition.json"
        data = json.loads(path.read_text())
        data["source"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_manifest_authority_substitution(self):
        path = self.root / "conformance/e16-a2-authority-manifest.json"
        data = json.loads(path.read_text())
        data["authorities"]["registry"] = "conformance/other.json"
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_freeze_mutation(self):
        (self.root / "docs/E16-A2-HUMAN-MASTERY-GUIDE.md").write_text("changed\n")
        self.assertEqual(self.checker().run()["authority_freeze_result"], "non-conformant")

    def install_positive(self):
        digest = "a" * 64
        custodian = committed({"id": "c-1", "revision": "1", "state": "active"})
        replica = committed({"id": "r-1", "revision": "1", "custodian": "c-1", "custodian_revision": "1", "state": "active"})
        intent = committed({"id": "i-1", "revision": "1"})
        binding = committed({
            "id": "b-1", "revision": "1", "intent": "i-1", "intent_revision": "1",
            "custodian": "c-1", "custodian_revision": "1", "replica": "r-1", "replica_revision": "1",
            "content_sha256": digest, "content_bytes": 10, "state": "bound"
        })
        decision_a1 = committed({
            "id": "a1d-1", "revision": "1", "intent": "i-1", "intent_revision": "1",
            "binding": "b-1", "binding_revision": "1", "state": "admissible"
        })
        a1_path = self.root / "conformance/preservation-intent.json"
        a1 = json.loads(a1_path.read_text())
        a1.update({
            "custodian_profiles": [custodian], "replica_profiles": [replica],
            "preservation_intents": [intent], "replica_bindings": [binding],
            "preservation_decisions": [decision_a1]
        })
        a1_path.write_text(json.dumps(a1))

        request = committed({
            "id": "pr-1", "revision": "1",
            "source_binding": "b-1", "source_binding_revision": "1",
            "source_binding_commitment": binding["commitment"]["digest"],
            "source_intent": "i-1", "source_intent_revision": "1",
            "custodian": "c-1", "custodian_revision": "1",
            "replica": "r-1", "replica_revision": "1",
            "content_sha256": digest, "content_bytes": 10,
            "requested_failure_domain_dimensions": ["provider", "account", "region", "administrative", "control-plane", "storage-implementation"],
            "placement_purpose": "preserve", "action": "eigiib:e16:place",
            "evaluation_context": {"id": "ctx", "revision": "1"},
            "idempotency_key": "place-1"
        })
        acceptance = committed({
            "id": "ca-1", "revision": "1",
            "request": "pr-1", "request_revision": "1", "request_commitment": request["commitment"]["digest"],
            "custodian": "c-1", "custodian_revision": "1",
            "replica": "r-1", "replica_revision": "1",
            "content_sha256": digest, "content_bytes": 10,
            "acceptance_state": "accepted", "accepted_scope": ["store"],
            "evidence_refs": ["custodian-receipt"]
        })
        declaration = committed({
            "id": "fd-1", "revision": "1", "replica": "r-1", "replica_revision": "1",
            "declared_by": "custodian",
            "dimensions": {
                "provider": "p", "account": "a", "region": "r",
                "administrative": "adm", "control_plane": "cp",
                "storage_implementation": "impl"
            },
            "state": "active", "evidence_refs": ["declaration"]
        })
        observation = committed({
            "id": "po-1", "revision": "1",
            "request": "pr-1", "request_revision": "1", "request_commitment": request["commitment"]["digest"],
            "acceptance": "ca-1", "acceptance_revision": "1", "acceptance_commitment": acceptance["commitment"]["digest"],
            "failure_domain_declaration": "fd-1", "failure_domain_declaration_revision": "1",
            "failure_domain_declaration_commitment": declaration["commitment"]["digest"],
            "observer": {"id": "observer", "revision": "1"},
            "method": {"kind": "custodian-receipt", "implementation": "fixture"},
            "observed_content_sha256": digest, "observed_content_bytes": 10,
            "observation_state": "positive", "evidence_refs": ["placement-receipt"]
        })
        gates = {
            "a1_binding": "permit", "request": "permit", "custody_acceptance": "permit",
            "content_identity": "permit", "failure_domain_declaration": "permit",
            "placement_observation": "permit"
        }
        decision = committed({
            "id": "pd-1", "revision": "1",
            "request": "pr-1", "request_revision": "1", "request_commitment": request["commitment"]["digest"],
            "observation": "po-1", "observation_revision": "1", "observation_commitment": observation["commitment"]["digest"],
            "gates": gates, "state": "placement-observed",
            "reasons": ["all-gates-positive"], "evidence_refs": ["placement-receipt"]
        })
        registry_path = self.root / "conformance/replica-placement.json"
        registry = json.loads(registry_path.read_text())
        registry.update({
            "placement_requests": [request],
            "custody_acceptances": [acceptance],
            "failure_domain_declarations": [declaration],
            "placement_observations": [observation],
            "placement_decisions": [decision],
        })
        registry_path.write_text(json.dumps(registry))
        self.refresh_freeze()

    def test_positive_placement(self):
        self.install_positive()
        report = self.checker().run()
        self.assertEqual(report["placement_result"], "conformant")
        self.assertEqual(report["decision_state_counts"]["placement-observed"], 1)

    def test_negative_observation_precedes_unavailable_acceptance(self):
        self.install_positive()
        path = self.root / "conformance/replica-placement.json"
        data = json.loads(path.read_text())
        data["custody_acceptances"][0]["acceptance_state"] = "unavailable"
        data["custody_acceptances"][0] = committed({k: v for k, v in data["custody_acceptances"][0].items() if k != "commitment"})
        data["placement_observations"][0]["observation_state"] = "negative"
        data["placement_observations"][0]["acceptance_commitment"] = data["custody_acceptances"][0]["commitment"]["digest"]
        data["placement_observations"][0] = committed({k: v for k, v in data["placement_observations"][0].items() if k != "commitment"})
        data["placement_decisions"][0]["observation_commitment"] = data["placement_observations"][0]["commitment"]["digest"]
        data["placement_decisions"][0]["gates"]["custody_acceptance"] = "unavailable"
        data["placement_decisions"][0]["gates"]["placement_observation"] = "deny"
        data["placement_decisions"][0]["state"] = "rejected"
        data["placement_decisions"][0] = committed({k: v for k, v in data["placement_decisions"][0].items() if k != "commitment"})
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["decision_state_counts"]["rejected"], 1)
        self.assertFalse(any(f["code"] == "E16A2.DECISION.DERIVATION" for f in report["findings"]))

    def test_acceptance_identity_substitution_rejected(self):
        self.install_positive()
        path = self.root / "conformance/replica-placement.json"
        data = json.loads(path.read_text())
        data["custody_acceptances"][0]["content_bytes"] = 11
        data["custody_acceptances"][0] = committed({k: v for k, v in data["custody_acceptances"][0].items() if k != "commitment"})
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_failure_domain_substitution_rejected(self):
        self.install_positive()
        path = self.root / "conformance/replica-placement.json"
        data = json.loads(path.read_text())
        data["failure_domain_declarations"][0]["replica"] = "other"
        data["failure_domain_declarations"][0] = committed({k: v for k, v in data["failure_domain_declarations"][0].items() if k != "commitment"})
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_duplicate_idempotency_rejected(self):
        self.install_positive()
        path = self.root / "conformance/replica-placement.json"
        data = json.loads(path.read_text())
        second = copy.deepcopy(data["placement_requests"][0])
        second["id"] = "pr-2"
        second = committed({k: v for k, v in second.items() if k != "commitment"})
        data["placement_requests"].append(second)
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

if __name__ == "__main__":
    unittest.main()
