import importlib.util
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "tools" / "eigiib_commit_check.py"
spec = importlib.util.spec_from_file_location("e12commit", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

STD = mod.STANDARD
BOUNDARY = {"proposal_revision": "p-r1", "policy_revision": "e10-pol-r1", "context_revision": "ctx-r1"}
IDENTITY = {"algorithm": "sha256", "digest": "a" * 64, "bytes": 42}


def automation():
    return {
        "proposals": [{
            "id": "p1", "revision": "p-r1", "action": "publish", "scope": "scope:prod", "target": "service:A",
            "operation_identity": deepcopy(IDENTITY)
        }],
        "decisions": [{
            "id": "d1", "state": "authorized", "proposal": "p1", "policy": "e10-pol", "context": "ctx",
            "proposal_revision": "p-r1", "policy_revision": "e10-pol-r1", "context_revision": "ctx-r1"
        }],
        "executions": [
            {"id": "x1", "decision": "d1", "state": "attempted"},
            {"id": "x2", "decision": "d1", "state": "attempted"}
        ]
    }


def temporal():
    return {
        "time_sources": [{"id": "ts", "domain": "mono"}],
        "policies": [{"id": "tp", "domain": "mono"}],
        "observations": [
            {"id": "o-check", "source": "ts", "tick": 100, "uncertainty": 2, "evidence": ["clock-check"]},
            {"id": "o-commit", "source": "ts", "tick": 110, "uncertainty": 2, "evidence": ["clock-commit"]},
            {"id": "o-replay", "source": "ts", "tick": 120, "uncertainty": 2, "evidence": ["clock-replay"]}
        ],
        "temporal_decisions": [
            {"id": "t-check", "subject": "d1", "policy": "tp", "observation": "o-check", "state": "valid", "e10_boundary": deepcopy(BOUNDARY)},
            {"id": "t-commit", "subject": "d1", "policy": "tp", "observation": "o-commit", "state": "valid", "e10_boundary": deepcopy(BOUNDARY)},
            {"id": "t-replay", "subject": "d1", "policy": "tp", "observation": "o-replay", "state": "valid", "e10_boundary": deepcopy(BOUNDARY)}
        ]
    }


def registry():
    return {
        "standard": STD,
        "revision": "test",
        "atomic_stores": [{
            "id": "store", "mode": "transactional-unique-key", "status": "active", "evidence": ["store-proof"]
        }],
        "policies": [{
            "id": "cp", "revision": "cp-r1", "allowed_check_temporal_states": ["valid"],
            "allowed_commit_temporal_states": ["valid"], "require_consumption": True, "require_idempotency": True
        }],
        "operations": [{
            "id": "op1", "revision": "op-r1", "policy": "cp", "e10_decision": "d1", "check_temporal_decision": "t-check",
            "action": "publish", "scope": "scope:prod", "target": "service:A", "operation_identity": deepcopy(IDENTITY),
            "e10_boundary": deepcopy(BOUNDARY)
        }],
        "idempotency_records": [{
            "id": "idem1", "store": "store", "namespace": "idem", "key": "k1", "operation": "op1",
            "state": "committed", "canonical_commit": "cm1", "evidence": ["idem-proof"]
        }],
        "attempts": [{
            "id": "a1", "operation": "op1", "e10_execution": "x1", "commit_temporal_decision": "t-commit",
            "state": "committed", "consumption": "c1", "idempotency_record": "idem1"
        }],
        "consumptions": [{
            "id": "c1", "store": "store", "namespace": "auth", "token": "once", "operation": "op1", "attempt": "a1",
            "state": "consumed", "evidence": ["consume-proof"]
        }],
        "commits": [{
            "id": "cm1", "operation": "op1", "attempt": "a1", "state": "committed", "consumption": "c1",
            "idempotency_record": "idem1", "evidence": ["commit-proof"]
        }],
        "decisions": [{
            "id": "ed1", "operation": "op1", "attempt": "a1", "policy": "cp", "state": "commit-safe", "commit": "cm1"
        }]
    }


class CommitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "conformance").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_obj(self, reg=None, auto=None, temp=None):
        reg = deepcopy(reg if reg is not None else registry())
        auto = deepcopy(auto if auto is not None else automation())
        temp = deepcopy(temp if temp is not None else temporal())
        (self.root / "conformance/commit.json").write_text(json.dumps(reg))
        (self.root / "conformance/automation.json").write_text(json.dumps(auto))
        (self.root / "conformance/temporal.json").write_text(json.dumps(temp))
        return mod.Checker(
            self.root,
            Path("conformance/commit.json"),
            Path("conformance/automation.json"),
            Path("conformance/temporal.json"),
        ).run()

    def assert_code(self, result, code):
        self.assertTrue(any(f["code"] == code for f in result["findings"]), result)

    def test_empty_structural_registry_is_conformant(self):
        empty = {"standard": STD, "revision": "empty", "atomic_stores": [], "policies": [], "operations": [], "idempotency_records": [], "attempts": [], "consumptions": [], "commits": [], "decisions": []}
        r = self.run_obj(empty, {"proposals": [], "decisions": [], "executions": []}, {"time_sources": [], "policies": [], "observations": [], "temporal_decisions": []})
        self.assertEqual(r["structural_result"], "conformant")
        self.assertEqual(r["commit_safety_result"], "not-evaluated")

    def test_positive_commit_safe(self):
        r = self.run_obj()
        self.assertEqual(r["structural_result"], "conformant")
        self.assertEqual(r["operation_binding_result"], "verified")
        self.assertEqual(r["commit_revalidation_result"], "verified")
        self.assertEqual(r["consumption_binding_result"], "verified")
        self.assertEqual(r["idempotency_binding_result"], "verified")
        self.assertEqual(r["commit_safety_result"], "verified")

    def test_action_substitution_rejected(self):
        r0 = registry(); r0["operations"][0]["action"] = "delete"
        self.assert_code(self.run_obj(r0), "E12.OP.BINDING")

    def test_missing_proposal_operation_identity_rejected(self):
        a = automation(); del a["proposals"][0]["operation_identity"]
        self.assert_code(self.run_obj(auto=a), "E12.OP.PROPOSAL_IDENTITY")

    def test_e10_boundary_mismatch_rejected(self):
        r0 = registry(); r0["operations"][0]["e10_boundary"]["context_revision"] = "stale"
        self.assert_code(self.run_obj(r0), "E12.OP.BOUNDARY")

    def test_check_temporal_state_must_be_allowed(self):
        t = temporal(); t["temporal_decisions"][0]["state"] = "expired"
        self.assert_code(self.run_obj(temp=t), "E12.OP.CHECK_STATE")

    def test_commit_temporal_decision_must_be_distinct(self):
        r0 = registry(); r0["attempts"][0]["commit_temporal_decision"] = "t-check"
        self.assert_code(self.run_obj(r0), "E12.REVALIDATION.DISTINCT")

    def test_overlapping_uncertainty_intervals_rejected(self):
        t = temporal(); t["observations"][1]["tick"] = 102; t["observations"][1]["uncertainty"] = 2
        self.assert_code(self.run_obj(temp=t), "E12.REVALIDATION.ORDER")

    def test_cross_domain_revalidation_rejected(self):
        t = temporal(); t["time_sources"].append({"id": "ts2", "domain": "other"}); t["policies"].append({"id": "tp2", "domain": "other"})
        t["observations"][1]["source"] = "ts2"; t["temporal_decisions"][1]["policy"] = "tp2"
        self.assert_code(self.run_obj(temp=t), "E12.REVALIDATION.DOMAIN")

    def test_wrong_e10_execution_binding_rejected(self):
        a = automation(); a["executions"][0]["decision"] = "other"
        self.assert_code(self.run_obj(auto=a), "E12.ATTEMPT.EXECUTION_BINDING")

    def test_duplicate_consumption_key_rejected(self):
        r0 = registry(); c2 = deepcopy(r0["consumptions"][0]); c2["id"] = "c2"; r0["consumptions"].append(c2)
        self.assert_code(self.run_obj(r0), "E12.CONSUMPTION.DUPLICATE_KEY")

    def test_consumed_record_requires_evidence(self):
        r0 = registry(); del r0["consumptions"][0]["evidence"]
        self.assert_code(self.run_obj(r0), "E12.CONSUMPTION.EVIDENCE")

    def test_unknown_store_cannot_support_consumption(self):
        r0 = registry(); r0["atomic_stores"][0]["mode"] = "unknown"
        self.assert_code(self.run_obj(r0), "E12.STORE.UNUSABLE")

    def test_duplicate_idempotency_key_rejected(self):
        r0 = registry(); i2 = deepcopy(r0["idempotency_records"][0]); i2["id"] = "idem2"; r0["idempotency_records"].append(i2)
        self.assert_code(self.run_obj(r0), "E12.IDEMPOTENCY.DUPLICATE_KEY")

    def test_idempotency_canonical_commit_binding_rejected(self):
        r0 = registry(); r0["idempotency_records"][0]["canonical_commit"] = "missing"
        self.assert_code(self.run_obj(r0), "E12.IDEMPOTENCY.COMMIT")

    def test_multiple_historical_commits_rejected(self):
        r0 = registry(); cm2 = deepcopy(r0["commits"][0]); cm2["id"] = "cm2"; cm2["state"] = "compensated"; r0["commits"].append(cm2)
        self.assert_code(self.run_obj(r0), "E12.COMMIT.MULTIPLE")

    def test_required_consumption_cannot_be_omitted(self):
        r0 = registry(); del r0["commits"][0]["consumption"]
        self.assert_code(self.run_obj(r0), "E12.COMMIT.CONSUMPTION")

    def test_required_idempotency_cannot_be_omitted(self):
        r0 = registry(); del r0["commits"][0]["idempotency_record"]
        self.assert_code(self.run_obj(r0), "E12.COMMIT.IDEMPOTENCY")

    def test_negative_decision_still_requires_resolved_trace(self):
        r0 = registry(); r0["decisions"][0].update({"state": "held", "operation": "missing"})
        self.assert_code(self.run_obj(r0), "E12.DECISION.REF")

    def test_idempotent_replay_uses_canonical_commit_without_new_consumption(self):
        r0 = registry()
        r0["attempts"].append({
            "id": "a2", "operation": "op1", "e10_execution": "x2", "commit_temporal_decision": "t-replay",
            "state": "reused", "idempotency_record": "idem1"
        })
        r0["decisions"].append({
            "id": "ed2", "operation": "op1", "attempt": "a2", "policy": "cp", "state": "idempotent-replay", "commit": "cm1"
        })
        r = self.run_obj(r0)
        self.assertEqual(r["structural_result"], "conformant")
        self.assertEqual(r["idempotent_replay_result"], "verified")

    def test_reused_attempt_must_not_consume_again(self):
        r0 = registry()
        r0["attempts"].append({"id": "a2", "operation": "op1", "e10_execution": "x2", "commit_temporal_decision": "t-replay", "state": "reused", "idempotency_record": "idem1", "consumption": "c1"})
        r0["decisions"].append({"id": "ed2", "operation": "op1", "attempt": "a2", "policy": "cp", "state": "idempotent-replay", "commit": "cm1"})
        self.assert_code(self.run_obj(r0), "E12.DECISION.REPLAY_CONSUMPTION")

    def test_reused_attempt_must_not_create_new_commit(self):
        r0 = registry()
        r0["attempts"].append({"id": "a2", "operation": "op1", "e10_execution": "x2", "commit_temporal_decision": "t-replay", "state": "reused", "idempotency_record": "idem1"})
        r0["commits"].append({"id": "cm2", "operation": "op1", "attempt": "a2", "state": "committed", "idempotency_record": "idem1", "evidence": ["bad-new-commit"]})
        r0["decisions"].append({"id": "ed2", "operation": "op1", "attempt": "a2", "policy": "cp", "state": "idempotent-replay", "commit": "cm1"})
        r = self.run_obj(r0)
        self.assertTrue(any(f["code"] in {"E12.COMMIT.MULTIPLE", "E12.DECISION.REPLAY_NEW_COMMIT"} for f in r["findings"]), r)

    def test_any_structural_error_suppresses_positive_results(self):
        r0 = registry(); r0["operations"][0]["target"] = "other"
        r = self.run_obj(r0)
        self.assertEqual(r["structural_result"], "non-conformant")
        self.assertEqual(r["commit_safety_result"], "not-evaluated")


if __name__ == "__main__":
    unittest.main()
