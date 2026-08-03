from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "e16a4check", SOURCE / "tools/eigiib_custodian_succession_recovery_check.py"
)
CHECK = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CHECK
spec.loader.exec_module(CHECK)


def committed(value):
    value = copy.deepcopy(value)
    value["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(value)}
    return value


class CustodianSuccessionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        needed = CHECK.EXPECTED_FREEZE_PATHS | {
            "conformance/e16-a4-authority-freeze.json",
            "conformance/e16-a3-authority-freeze.json",
            "conformance/retention-readback-restore.json",
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
        self.history.write_text(
            json.dumps(
                {
                    "standard": CHECK.HISTORY_STANDARD,
                    "source_commit": CHECK.SOURCE_E16_A3_HEAD,
                    "overall_result": "conformant",
                    "e16_a2_history_result": "conformant",
                    "e16_a3_result": "conformant",
                    "e16_a3_tests_result": "conformant",
                }
            ),
            encoding="utf-8",
        )
        self.refresh_freeze()

    def tearDown(self):
        self.temp.cleanup()

    def refresh_freeze(self):
        entries = []
        for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS):
            raw = (self.root / rel).read_bytes()
            entries.append(
                {
                    "path": rel,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        (self.root / "conformance/e16-a4-authority-freeze.json").write_text(
            json.dumps(
                {
                    "standard": CHECK.FREEZE_STANDARD,
                    "status": "frozen",
                    "profile_revision": CHECK.PROFILE_REVISION,
                    "source_e16_a3_commit": CHECK.SOURCE_E16_A3_HEAD,
                    "authorities": entries,
                }
            ),
            encoding="utf-8",
        )

    def checker(self):
        return CHECK.Checker(self.root, history_report=Path("history.json"))

    def test_empty_registry(self):
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["recovery_result"], "not-evaluated")

    def test_history_failure(self):
        data = json.loads(self.history.read_text())
        data["overall_result"] = "non-conformant"
        self.history.write_text(json.dumps(data))
        self.assertEqual(
            self.checker().run()["historical_continuity_result"], "non-conformant"
        )

    def test_source_substitution(self):
        path = self.root / "conformance/e16-a4-adoption-transition.json"
        data = json.loads(path.read_text())
        data["source"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_manifest_authority_substitution(self):
        path = self.root / "conformance/e16-a4-authority-manifest.json"
        data = json.loads(path.read_text())
        data["authorities"]["registry"] = "conformance/other.json"
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_freeze_mutation(self):
        (self.root / "docs/E16-A4-HUMAN-MASTERY-GUIDE.md").write_text("changed\n")
        self.assertEqual(
            self.checker().run()["authority_freeze_result"], "non-conformant"
        )

    def install_positive(self):
        digest = "a" * 64
        source_decision = committed(
            {
                "id": "a3d-1",
                "revision": "1",
                "state": "bounded-preservation-and-restore-verified",
                "content_sha256": digest,
                "content_bytes": 10,
                "custodian": "custodian-old",
                "replica": "replica-old",
            }
        )
        upstream_path = self.root / "conformance/retention-readback-restore.json"
        upstream = json.loads(upstream_path.read_text())
        upstream["preservation_verification_decisions"] = [source_decision]
        upstream_path.write_text(json.dumps(upstream))

        succession = committed(
            {
                "id": "sa-1",
                "revision": "1",
                "source_decision": "a3d-1",
                "source_decision_revision": "1",
                "source_decision_commitment": source_decision["commitment"]["digest"],
                "predecessor_custodian": "custodian-old",
                "predecessor_custodian_revision": "1",
                "successor_custodian": "custodian-new",
                "successor_custodian_revision": "1",
                "predecessor_replica": "replica-old",
                "predecessor_replica_revision": "1",
                "content_sha256": digest,
                "content_bytes": 10,
                "source_generation": 4,
                "authorization_state": "authorized",
                "effective_context": {"id": "ctx", "revision": "1"},
                "evidence_refs": ["succession-authorization"],
            }
        )
        plan = committed(
            {
                "id": "mp-1",
                "revision": "1",
                "succession": "sa-1",
                "succession_revision": "1",
                "succession_commitment": succession["commitment"]["digest"],
                "predecessor_custodian": "custodian-old",
                "predecessor_custodian_revision": "1",
                "successor_custodian": "custodian-new",
                "successor_custodian_revision": "1",
                "source_replica": "replica-old",
                "source_replica_revision": "1",
                "target_replica": "replica-new",
                "target_replica_revision": "1",
                "content_sha256": digest,
                "content_bytes": 10,
                "source_generation": 4,
                "target_generation": 5,
                "action": "eigiib:e16:migrate",
                "evaluation_context": {"id": "ctx", "revision": "1"},
                "idempotency_key": "migration-1",
                "state": "planned",
                "evidence_refs": ["migration-plan"],
            }
        )
        observation = committed(
            {
                "id": "mo-1",
                "revision": "1",
                "migration_plan": "mp-1",
                "migration_plan_revision": "1",
                "migration_plan_commitment": plan["commitment"]["digest"],
                "source_replica": "replica-old",
                "source_replica_revision": "1",
                "target_replica": "replica-new",
                "target_replica_revision": "1",
                "observed_content_sha256": digest,
                "observed_content_bytes": 10,
                "target_generation": 5,
                "observer": {"id": "migration-observer", "revision": "1"},
                "observation_state": "positive",
                "evidence_refs": ["migration-observation"],
            }
        )
        loss = committed(
            {
                "id": "lr-1",
                "revision": "1",
                "migration_plan": "mp-1",
                "migration_plan_revision": "1",
                "migration_plan_commitment": plan["commitment"]["digest"],
                "affected_role": "source",
                "affected_replica": "replica-old",
                "affected_replica_revision": "1",
                "generation": 4,
                "loss_state": "confirmed",
                "evidence_refs": ["source-loss"],
            }
        )
        quarantine = committed(
            {
                "id": "qr-1",
                "revision": "1",
                "subject_kind": "source-replica",
                "subject": "replica-old",
                "subject_revision": "1",
                "subject_commitment": source_decision["commitment"]["digest"],
                "generation": 4,
                "quarantine_state": "active",
                "reason": "superseded-source",
                "evidence_refs": ["source-quarantine"],
            }
        )
        replay = committed(
            {
                "id": "rr-1",
                "revision": "1",
                "migration_plan": "mp-1",
                "migration_plan_revision": "1",
                "migration_plan_commitment": plan["commitment"]["digest"],
                "migration_observation": "mo-1",
                "migration_observation_revision": "1",
                "migration_observation_commitment": observation["commitment"]["digest"],
                "candidate_replica": "replica-new",
                "candidate_replica_revision": "1",
                "content_sha256": digest,
                "content_bytes": 10,
                "accepted_generation": 4,
                "minimum_generation": 5,
                "candidate_generation": 5,
                "replay_sequence": [
                    {"position": 0, "commitment": succession["commitment"]["digest"]},
                    {"position": 1, "commitment": plan["commitment"]["digest"]},
                    {"position": 2, "commitment": observation["commitment"]["digest"]},
                ],
                "superseded_commitments": [source_decision["commitment"]["digest"]],
                "replay_state": "positive",
                "idempotency_key": "recovery-1",
                "evidence_refs": ["recovery-replay"],
            }
        )
        gates = {
            "e16_a3_continuity": "permit",
            "succession": "permit",
            "migration_plan": "permit",
            "migration_observation": "permit",
            "loss": "permit",
            "quarantine": "permit",
            "anti_rollback_recovery": "permit",
        }
        decision = committed(
            {
                "id": "rd-1",
                "revision": "1",
                "succession": "sa-1",
                "succession_revision": "1",
                "succession_commitment": succession["commitment"]["digest"],
                "migration_plan": "mp-1",
                "migration_plan_revision": "1",
                "migration_plan_commitment": plan["commitment"]["digest"],
                "migration_observation": "mo-1",
                "migration_observation_revision": "1",
                "migration_observation_commitment": observation["commitment"]["digest"],
                "recovery_replay": "rr-1",
                "recovery_replay_revision": "1",
                "recovery_replay_commitment": replay["commitment"]["digest"],
                "gates": gates,
                "state": "successor-replica-recovered",
                "reasons": ["source-loss-contained", "anti-rollback-replay-positive"],
                "evidence_refs": ["recovery-replay"],
            }
        )
        registry_path = self.root / "conformance/custodian-succession-recovery.json"
        registry = json.loads(registry_path.read_text())
        registry.update(
            {
                "succession_authorizations": [succession],
                "migration_plans": [plan],
                "migration_observations": [observation],
                "loss_reports": [loss],
                "quarantine_records": [quarantine],
                "recovery_replays": [replay],
                "recovery_decisions": [decision],
            }
        )
        registry_path.write_text(json.dumps(registry))
        self.refresh_freeze()

    def rewrite_chain(self, data):
        succession = data["succession_authorizations"][0]
        succession = committed({k: v for k, v in succession.items() if k != "commitment"})
        data["succession_authorizations"][0] = succession

        plan = data["migration_plans"][0]
        plan["succession_commitment"] = succession["commitment"]["digest"]
        plan = committed({k: v for k, v in plan.items() if k != "commitment"})
        data["migration_plans"][0] = plan

        observation = data["migration_observations"][0]
        observation["migration_plan_commitment"] = plan["commitment"]["digest"]
        observation = committed({k: v for k, v in observation.items() if k != "commitment"})
        data["migration_observations"][0] = observation

        data["loss_reports"][0]["migration_plan_commitment"] = plan["commitment"]["digest"]
        data["loss_reports"][0] = committed(
            {k: v for k, v in data["loss_reports"][0].items() if k != "commitment"}
        )

        replay = data["recovery_replays"][0]
        replay["migration_plan_commitment"] = plan["commitment"]["digest"]
        replay["migration_observation_commitment"] = observation["commitment"]["digest"]
        replay["replay_sequence"] = [
            {"position": 0, "commitment": succession["commitment"]["digest"]},
            {"position": 1, "commitment": plan["commitment"]["digest"]},
            {"position": 2, "commitment": observation["commitment"]["digest"]},
        ]
        replay = committed({k: v for k, v in replay.items() if k != "commitment"})
        data["recovery_replays"][0] = replay

        decision = data["recovery_decisions"][0]
        decision["succession_commitment"] = succession["commitment"]["digest"]
        decision["migration_plan_commitment"] = plan["commitment"]["digest"]
        decision["migration_observation_commitment"] = observation["commitment"]["digest"]
        decision["recovery_replay_commitment"] = replay["commitment"]["digest"]
        decision = committed({k: v for k, v in decision.items() if k != "commitment"})
        data["recovery_decisions"][0] = decision

    def test_positive_recovery(self):
        self.install_positive()
        report = self.checker().run()
        self.assertEqual(report["recovery_result"], "conformant")
        self.assertEqual(
            report["decision_state_counts"]["successor-replica-recovered"], 1
        )

    def test_negative_observation_precedes_unavailable_succession(self):
        self.install_positive()
        path = self.root / "conformance/custodian-succession-recovery.json"
        data = json.loads(path.read_text())
        data["succession_authorizations"][0]["authorization_state"] = "unavailable"
        data["migration_observations"][0]["observation_state"] = "negative"
        data["recovery_decisions"][0]["gates"]["succession"] = "unavailable"
        data["recovery_decisions"][0]["gates"]["migration_observation"] = "deny"
        data["recovery_decisions"][0]["state"] = "rejected"
        self.rewrite_chain(data)
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["decision_state_counts"]["rejected"], 1)
        self.assertFalse(
            any(item["code"] == "E16A4.DECISION.DERIVATION" for item in report["findings"])
        )

    def test_confirmed_target_loss_rejected(self):
        self.install_positive()
        path = self.root / "conformance/custodian-succession-recovery.json"
        data = json.loads(path.read_text())
        data["loss_reports"][0]["affected_role"] = "target"
        data["loss_reports"][0]["affected_replica"] = "replica-new"
        data["loss_reports"][0]["affected_replica_revision"] = "1"
        data["loss_reports"][0]["generation"] = 5
        data["loss_reports"][0] = committed(
            {k: v for k, v in data["loss_reports"][0].items() if k != "commitment"}
        )
        data["recovery_decisions"][0]["gates"]["loss"] = "deny"
        data["recovery_decisions"][0]["state"] = "rejected"
        data["recovery_decisions"][0] = committed(
            {k: v for k, v in data["recovery_decisions"][0].items() if k != "commitment"}
        )
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["decision_state_counts"]["rejected"], 1)

    def test_active_target_quarantine_rejected(self):
        self.install_positive()
        path = self.root / "conformance/custodian-succession-recovery.json"
        data = json.loads(path.read_text())
        q = data["quarantine_records"][0]
        q["subject_kind"] = "target-replica"
        q["subject"] = "replica-new"
        q["subject_revision"] = "1"
        q["generation"] = 5
        q["quarantine_state"] = "active"
        data["quarantine_records"][0] = committed(
            {k: v for k, v in q.items() if k != "commitment"}
        )
        data["recovery_decisions"][0]["gates"]["quarantine"] = "deny"
        data["recovery_decisions"][0]["state"] = "rejected"
        data["recovery_decisions"][0] = committed(
            {k: v for k, v in data["recovery_decisions"][0].items() if k != "commitment"}
        )
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["decision_state_counts"]["rejected"], 1)

    def test_rollback_generation_rejected(self):
        self.install_positive()
        path = self.root / "conformance/custodian-succession-recovery.json"
        data = json.loads(path.read_text())
        replay = data["recovery_replays"][0]
        replay["candidate_generation"] = 4
        data["recovery_replays"][0] = committed(
            {k: v for k, v in replay.items() if k != "commitment"}
        )
        data["recovery_decisions"][0]["recovery_replay_commitment"] = data[
            "recovery_replays"
        ][0]["commitment"]["digest"]
        data["recovery_decisions"][0] = committed(
            {k: v for k, v in data["recovery_decisions"][0].items() if k != "commitment"}
        )
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "non-conformant")
        self.assertTrue(any(item["code"] == "E16A4.REPLAY.ROLLBACK" for item in report["findings"]))

    def test_duplicate_idempotency_rejected(self):
        self.install_positive()
        path = self.root / "conformance/custodian-succession-recovery.json"
        data = json.loads(path.read_text())
        second = copy.deepcopy(data["migration_plans"][0])
        second["id"] = "mp-2"
        second = committed({k: v for k, v in second.items() if k != "commitment"})
        data["migration_plans"].append(second)
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "non-conformant")
        self.assertTrue(
            any(item["code"] == "E16A4.IDEMPOTENCY.DUPLICATE" for item in report["findings"])
        )


if __name__ == "__main__":
    unittest.main()
