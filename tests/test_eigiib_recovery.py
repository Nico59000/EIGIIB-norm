import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("e7checker", HERE.parent / "tools" / "eigiib_recovery_check.py")
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)
Checker = mod.Checker
STANDARD = mod.STANDARD


class RecoveryTests(unittest.TestCase):
    def base(self):
        return {
            "standard": STANDARD,
            "revision": "test",
            "incidents": [],
            "trust_states": [],
            "evidence": [],
            "actions": [],
            "plans": [],
            "transitions": [],
            "rollback_records": [],
            "decisions": [],
        }

    def run_obj(self, obj, extras=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "conformance").mkdir()
            (root / "conformance/recovery.json").write_text(json.dumps(obj), encoding="utf-8")
            (root / "conformance/trust.json").write_text(json.dumps((extras or {}).get("trust", {"decisions": []})), encoding="utf-8")
            (root / "conformance/transparency.json").write_text(json.dumps((extras or {}).get("transparency", {"trust_history_decisions": []})), encoding="utf-8")
            (root / "conformance/gossip.json").write_text(json.dumps((extras or {}).get("gossip", {})), encoding="utf-8")
            for path, text in (extras or {}).get("files", {}).items():
                p = root / path
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            return Checker(
                root,
                Path("conformance/recovery.json"),
                Path("conformance/trust.json"),
                Path("conformance/transparency.json"),
                Path("conformance/gossip.json"),
            ).run()

    def valid(self):
        o = self.base()
        o["incidents"] = [{"id": "i", "state": "closed", "sources": []}]
        o["trust_states"] = [
            {"id": "s0", "epoch": 1, "status": "superseded"},
            {"id": "s1", "epoch": 2, "status": "active"},
        ]
        o["evidence"] = [{"id": "ev", "kind": "test"}]
        o["actions"] = [
            {"id": "a0", "incident": "i", "kind": "quarantine", "status": "completed", "evidence": ["ev"]},
            {"id": "a1", "incident": "i", "kind": "rotate", "status": "completed", "evidence": ["ev"]},
        ]
        o["plans"] = [{"id": "p", "incident": "i", "actions": ["a0", "a1"], "dependencies": [{"before": "a0", "after": "a1"}]}]
        o["transitions"] = [{"id": "t", "from_state": "s0", "to_state": "s1", "actions": ["a1"], "status": "verified"}]
        o["decisions"] = [
            {"id": "d0", "incident": "i", "state": "contained", "actions": ["a0"]},
            {"id": "d1", "incident": "i", "state": "closed", "transition": "t", "actions": ["a1"], "open_blockers": []},
        ]
        return o

    def test_valid_recovery(self):
        r = self.run_obj(self.valid())
        self.assertEqual(r["structural_result"], "conformant")
        self.assertEqual(r["closure_result"], "verified")

    def test_cycle_rejected(self):
        o = self.valid()
        o["plans"][0]["dependencies"].append({"before": "a1", "after": "a0"})
        r = self.run_obj(o)
        self.assertTrue(any(f["code"] == "E7.PLAN.CYCLE" for f in r["findings"]))

    def test_completed_without_evidence(self):
        o = self.valid()
        o["actions"][1]["evidence"] = []
        r = self.run_obj(o)
        self.assertTrue(any(f["code"] == "E7.ACTION.NO_EVIDENCE" for f in r["findings"]))

    def test_epoch_must_advance(self):
        o = self.valid()
        o["trust_states"][1]["epoch"] = 1
        r = self.run_obj(o)
        self.assertTrue(any(f["code"] == "E7.TRANSITION.EPOCH" for f in r["findings"]))

    def test_close_requires_closed_incident(self):
        o = self.valid()
        o["incidents"][0]["state"] = "continuity-established"
        r = self.run_obj(o)
        self.assertTrue(any(f["code"] == "E7.DECISION.INCIDENT_STATE" for f in r["findings"]))

    def test_rollback_requires_compensation(self):
        o = self.valid()
        o["rollback_records"] = [{"id": "rb", "incident": "i", "superseded_transition": "t", "compensating_actions": []}]
        r = self.run_obj(o)
        self.assertTrue(any(f["code"] == "E7.ROLLBACK.COMPENSATION" for f in r["findings"]))

    def test_path_escape_rejected(self):
        o = self.valid()
        o["evidence"].append({"id": "evil", "kind": "local", "path": "../escape"})
        r = self.run_obj(o)
        self.assertTrue(any(f["code"] == "E7.PATH.ESCAPE" for f in r["findings"]))


if __name__ == "__main__":
    unittest.main()
