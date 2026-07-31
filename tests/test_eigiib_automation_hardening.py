import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "e10hardening", HERE.parent / "tools" / "eigiib_automation_hardening_check.py"
)
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)
Checker = mod.Checker
STANDARD = mod.STANDARD


class AutomationHardeningTests(unittest.TestCase):
    def base(self, state="denied"):
        return {
            "standard": STANDARD,
            "revision": "hardening-test",
            "principals": [],
            "delegations": [],
            "contexts": [{"id": "ctx", "revision": "c1"}],
            "policies": [{"id": "pol", "revision": "r1"}],
            "proposals": [{"id": "p", "revision": "p1", "policy": "pol", "context": "ctx"}],
            "approvals": [],
            "decisions": [{
                "id": "d",
                "proposal": "p",
                "policy": "pol",
                "context": "ctx",
                "state": state,
                "proposal_revision": "p1",
                "policy_revision": "r1",
                "context_revision": "c1",
            }],
            "executions": [],
            "effects": [],
            "accountability_traces": [],
        }

    def run_obj(self, obj):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "conformance").mkdir()
            (root / "conformance/automation.json").write_text(json.dumps(obj), encoding="utf-8")
            return Checker(root, Path("conformance/automation.json")).run()

    def codes(self, report):
        return {f["code"] for f in report["findings"]}

    def test_exact_negative_decision_boundary_passes(self):
        report = self.run_obj(self.base("denied"))
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["decision_boundary_result"], "verified")

    def test_denied_stale_proposal_revision_rejected(self):
        obj = self.base("denied")
        obj["decisions"][0]["proposal_revision"] = "old"
        self.assertIn("E10H.DECISION.PROPOSAL_REV", self.codes(self.run_obj(obj)))

    def test_held_stale_policy_revision_rejected(self):
        obj = self.base("held")
        obj["decisions"][0]["policy_revision"] = "old"
        self.assertIn("E10H.DECISION.POLICY_REV", self.codes(self.run_obj(obj)))

    def test_unavailable_stale_context_revision_rejected(self):
        obj = self.base("unavailable")
        obj["decisions"][0]["context_revision"] = "old"
        self.assertIn("E10H.DECISION.CONTEXT_REV", self.codes(self.run_obj(obj)))

    def test_cross_boundary_negative_decision_rejected(self):
        obj = self.base("denied")
        obj["policies"].append({"id": "other", "revision": "r2"})
        obj["decisions"][0]["policy"] = "other"
        obj["decisions"][0]["policy_revision"] = "r2"
        self.assertIn("E10H.DECISION.BOUNDARY", self.codes(self.run_obj(obj)))


if __name__ == "__main__":
    unittest.main()
