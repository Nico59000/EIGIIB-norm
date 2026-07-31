import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "e10checker_separation", HERE.parent / "tools" / "eigiib_automation_check.py"
)
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)
Checker = mod.Checker
STANDARD = mod.STANDARD


class AutomationSeparationTests(unittest.TestCase):
    def valid(self):
        return {
            "standard": STANDARD,
            "revision": "test-separation",
            "principals": [
                {"id": "actor", "kind": "service", "status": "active", "direct_scopes": ["mutate"]},
                {"id": "reviewer", "kind": "human", "status": "active", "direct_scopes": ["approve-mutate"]},
                {"id": "worker", "kind": "service", "status": "active", "direct_scopes": ["mutate"]},
            ],
            "delegations": [],
            "contexts": [{"id": "ctx", "revision": "c1"}],
            "policies": [{
                "id": "pol",
                "revision": "r1",
                "action_scope": "mutate",
                "approval_scope": "approve-mutate",
                "required_approvals": 1,
                "allow_self_approval": False,
                "allow_automation_actor": False,
                "allow_automation_executor": False,
                "max_delegation_depth": 0,
                "require_e9_context": False,
                "allowed_e9_states": ["nominal-restored"],
            }],
            "proposals": [{
                "id": "p",
                "revision": "p1",
                "actor": "actor",
                "requested_executor": "worker",
                "action": "deploy",
                "scope": "mutate",
                "target": "svc",
                "policy": "pol",
                "context": "ctx",
            }],
            "approvals": [{
                "id": "a",
                "proposal": "p",
                "approver": "reviewer",
                "state": "approved",
                "proposal_revision": "p1",
                "policy_revision": "r1",
                "context_revision": "c1",
                "authority_path": [],
                "evidence": ["approval-evidence"],
            }],
            "decisions": [{
                "id": "d",
                "proposal": "p",
                "policy": "pol",
                "context": "ctx",
                "state": "authorized",
                "proposal_revision": "p1",
                "policy_revision": "r1",
                "context_revision": "c1",
                "actor_authority_path": [],
                "approvals": ["a"],
            }],
            "executions": [{
                "id": "x",
                "decision": "d",
                "executor": "worker",
                "state": "succeeded",
                "authority_path": [],
                "evidence": ["execution-evidence"],
            }],
            "effects": [{
                "id": "f",
                "execution": "x",
                "state": "observed",
                "evidence": ["effect-evidence"],
            }],
            "accountability_traces": [{
                "id": "t",
                "decision": "d",
                "execution": "x",
                "effect": "f",
                "participants": ["actor", "worker", "reviewer"],
                "state": "trace-complete",
            }],
        }

    def run_obj(self, obj):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "conformance").mkdir()
            (root / "conformance/automation.json").write_text(json.dumps(obj), encoding="utf-8")
            (root / "conformance/degraded.json").write_text(json.dumps({"decisions": []}), encoding="utf-8")
            return Checker(
                root,
                Path("conformance/automation.json"),
                Path("conformance/degraded.json"),
            ).run()

    def test_schema_requires_evidence_only_for_approved_state(self):
        schema = json.loads((HERE.parent / "schemas" / "eigiib-e10-automation.schema.json").read_text(encoding="utf-8"))
        approval = schema["$defs"]["approval"]
        self.assertNotIn("evidence", approval["required"])
        conditions = approval.get("allOf", [])
        self.assertTrue(any(
            c.get("if", {}).get("properties", {}).get("state", {}).get("const") == "approved"
            and "evidence" in c.get("then", {}).get("required", [])
            for c in conditions
        ))

    def test_rejected_unused_approval_needs_no_positive_evidence(self):
        obj = self.valid()
        obj["approvals"].append({
            "id": "reject",
            "proposal": "p",
            "approver": "reviewer",
            "state": "rejected",
            "proposal_revision": "p1",
            "policy_revision": "r1",
            "context_revision": "c1",
            "authority_path": [],
        })
        result = self.run_obj(obj)
        self.assertEqual(result["structural_result"], "conformant")
        self.assertEqual(result["authorization_result"], "verified")

    def test_failed_execution_can_be_traceable_without_observed_effect(self):
        obj = self.valid()
        obj["executions"][0] = {
            "id": "x",
            "decision": "d",
            "executor": "worker",
            "state": "failed",
            "authority_path": [],
        }
        obj["effects"][0] = {
            "id": "f",
            "execution": "x",
            "state": "not-observed",
        }
        result = self.run_obj(obj)
        self.assertEqual(result["structural_result"], "conformant")
        self.assertEqual(result["authorization_result"], "verified")
        self.assertEqual(result["execution_result"], "verified")
        self.assertEqual(result["effect_result"], "not-evaluated")
        self.assertEqual(result["accountability_result"], "verified")


if __name__ == "__main__":
    unittest.main()
