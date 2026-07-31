import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

hard_spec = importlib.util.spec_from_file_location("e12hard", ROOT / "tools/eigiib_commit_hardening_check.py")
hard = importlib.util.module_from_spec(hard_spec)
sys.modules[hard_spec.name] = hard
hard_spec.loader.exec_module(hard)

base_spec = importlib.util.spec_from_file_location("e12fixtures", HERE / "test_eigiib_commit.py")
base = importlib.util.module_from_spec(base_spec)
sys.modules[base_spec.name] = base
base_spec.loader.exec_module(base)


def hardened_registry():
    reg = deepcopy(base.registry())
    reg["commits"][0]["atomic_store"] = "store"
    return reg


class CommitHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "conformance").mkdir()
        (self.root / "tools").mkdir()
        shutil.copy(ROOT / "tools/eigiib_commit_check.py", self.root / "tools/eigiib_commit_check.py")

    def tearDown(self):
        self.tmp.cleanup()

    def run_obj(self, reg=None, auto=None, temp=None):
        reg = deepcopy(reg if reg is not None else hardened_registry())
        auto = deepcopy(auto if auto is not None else base.automation())
        temp = deepcopy(temp if temp is not None else base.temporal())
        (self.root / "conformance/commit.json").write_text(json.dumps(reg))
        (self.root / "conformance/automation.json").write_text(json.dumps(auto))
        (self.root / "conformance/temporal.json").write_text(json.dumps(temp))
        return hard.Checker(
            self.root,
            Path("conformance/commit.json"),
            Path("conformance/automation.json"),
            Path("conformance/temporal.json"),
        ).run()

    def assert_code(self, result, code):
        self.assertTrue(any(f["code"] == code for f in result["findings"]), result)

    def test_positive_common_atomic_domain(self):
        r = self.run_obj()
        self.assertEqual(r["hardening_result"], "conformant")
        self.assertEqual(r["fresh_commit_observation_result"], "verified")
        self.assertEqual(r["atomic_commit_domain_result"], "verified")

    def test_same_zero_uncertainty_observation_is_not_revalidation(self):
        temp = base.temporal()
        temp["observations"][0]["uncertainty"] = 0
        temp["temporal_decisions"][1]["observation"] = "o-check"
        r = self.run_obj(temp=temp)
        self.assert_code(r, "E12H.REVALIDATION.OBSERVATION_REUSE")

    def test_positive_commit_requires_explicit_atomic_store(self):
        reg = base.registry()
        r = self.run_obj(reg=reg)
        self.assert_code(r, "E12H.COMMIT.STORE")

    def test_consumption_store_must_equal_commit_store(self):
        reg = hardened_registry()
        reg["atomic_stores"].append({"id": "store2", "mode": "transactional-unique-key", "status": "active", "evidence": ["store2-proof"]})
        reg["consumptions"][0]["store"] = "store2"
        r = self.run_obj(reg=reg)
        self.assert_code(r, "E12H.COMMIT.CONSUMPTION_STORE")

    def test_idempotency_store_must_equal_commit_store(self):
        reg = hardened_registry()
        reg["atomic_stores"].append({"id": "store2", "mode": "transactional-unique-key", "status": "active", "evidence": ["store2-proof"]})
        reg["idempotency_records"][0]["store"] = "store2"
        r = self.run_obj(reg=reg)
        self.assert_code(r, "E12H.COMMIT.IDEMPOTENCY_STORE")

    def test_replay_key_store_must_equal_canonical_commit_store(self):
        reg = hardened_registry()
        reg["atomic_stores"].append({"id": "store2", "mode": "transactional-unique-key", "status": "active", "evidence": ["store2-proof"]})
        reg["idempotency_records"][0]["store"] = "store2"
        reg["decisions"][0]["state"] = "held"
        reg["attempts"].append({
            "id": "a2", "operation": "op1", "e10_execution": "x2", "commit_temporal_decision": "t-replay",
            "state": "reused", "idempotency_record": "idem1"
        })
        reg["decisions"].append({
            "id": "ed2", "operation": "op1", "attempt": "a2", "policy": "cp", "state": "idempotent-replay", "commit": "cm1"
        })
        r = self.run_obj(reg=reg)
        self.assert_code(r, "E12H.REPLAY.STORE")

    def test_empty_structural_registry_remains_conformant(self):
        empty = {"standard": base.STD, "revision": "empty", "atomic_stores": [], "policies": [], "operations": [], "idempotency_records": [], "attempts": [], "consumptions": [], "commits": [], "decisions": []}
        r = self.run_obj(empty, {"proposals": [], "decisions": [], "executions": []}, {"time_sources": [], "policies": [], "observations": [], "temporal_decisions": []})
        self.assertEqual(r["hardening_result"], "conformant")
        self.assertEqual(r["atomic_commit_domain_result"], "not-evaluated")


if __name__ == "__main__":
    unittest.main()
