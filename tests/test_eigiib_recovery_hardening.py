import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("e7h", HERE.parent / "tools" / "eigiib_recovery_hardening_check.py")
mod = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = mod; SPEC.loader.exec_module(mod)
Checker = mod.Checker; STANDARD = mod.STANDARD

class HardeningTests(unittest.TestCase):
    def base(self):
        return {"standard":STANDARD,"revision":"test","incidents":[{"id":"i","state":"closed","sources":[]}],"trust_states":[{"id":"s0","epoch":1,"status":"superseded"},{"id":"s1","epoch":2,"status":"active"}],"evidence":[{"id":"ev","kind":"test"}],"actions":[{"id":"a","incident":"i","kind":"rotate","status":"completed","evidence":["ev"]}],"plans":[{"id":"p","incident":"i","actions":["a"],"dependencies":[]}],"transitions":[{"id":"t","incident":"i","from_state":"s0","to_state":"s1","actions":["a"],"status":"verified"}],"rollback_records":[],"decisions":[]}
    def run_obj(self,o,extras=None):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); (r/"conformance").mkdir(); (r/"conformance/recovery.json").write_text(json.dumps(o)); (r/"conformance/trust.json").write_text(json.dumps((extras or {}).get("trust",{"decisions":[]}))); (r/"conformance/transparency.json").write_text(json.dumps((extras or {}).get("transparency",{"trust_history_decisions":[]}))); (r/"conformance/gossip.json").write_text(json.dumps((extras or {}).get("gossip",{})))
            return Checker(r,Path("conformance/recovery.json"),Path("conformance/trust.json"),Path("conformance/transparency.json"),Path("conformance/gossip.json")).run()
    def test_valid(self):
        r=self.run_obj(self.base()); self.assertEqual(r["hardening_result"],"conformant"); self.assertEqual(r["verified_transition_count"],1)
    def test_transition_incident_boundary(self):
        o=self.base(); o["incidents"].append({"id":"j","state":"recovering","sources":[]}); o["transitions"][0]["incident"]="j"; r=self.run_obj(o); self.assertTrue(any(f["code"]=="E7H.TRANSITION.ACTION_INCIDENT" for f in r["findings"])); self.assertEqual(r["verified_transition_count"],0)
    def test_plan_incident_boundary(self):
        o=self.base(); o["incidents"].append({"id":"j","state":"recovering","sources":[]}); o["actions"][0]["incident"]="j"; r=self.run_obj(o); self.assertTrue(any(f["code"]=="E7H.PLAN.ACTION_INCIDENT" for f in r["findings"]))
    def test_required_lower_layer_binding(self):
        o=self.base(); o["transitions"][0].update({"require_e4_authenticated":True,"e4_decision":"missing"}); r=self.run_obj(o); self.assertTrue(any(f["code"]=="E7H.TRANSITION.E4" for f in r["findings"])); self.assertEqual(r["verified_transition_count"],0)
    def test_rollback_reason_and_epoch(self):
        o=self.base(); o["trust_states"].append({"id":"s2","epoch":3,"status":"active"}); o["actions"].append({"id":"b","incident":"i","kind":"rollback","status":"completed","evidence":["ev"]}); o["transitions"].append({"id":"t2","incident":"i","from_state":"s1","to_state":"s2","actions":["b"],"status":"verified"}); o["rollback_records"]=[{"id":"rb","incident":"i","superseded_transition":"t2","compensating_actions":["b"],"replacement_transition":"t"}]; r=self.run_obj(o); codes={f["code"] for f in r["findings"]}; self.assertIn("E7H.ROLLBACK.REASON",codes); self.assertIn("E7H.ROLLBACK.REPLACEMENT_EPOCH",codes)
    def test_reopen_state(self):
        o=self.base(); o["decisions"]=[{"id":"d","incident":"i","state":"reopened"}]; r=self.run_obj(o); self.assertTrue(any(f["code"]=="E7H.DECISION.REOPEN_STATE" for f in r["findings"]))
    def test_reopen_warnings_preserve_boundary(self):
        o=self.base(); o["incidents"][0]["state"]="reopened"; o["decisions"]=[{"id":"d","incident":"i","state":"reopened"}]; r=self.run_obj(o); codes={f["code"] for f in r["findings"] if f["severity"]=="warning"}; self.assertIn("E7H.DECISION.REOPEN_PRIOR",codes); self.assertIn("E7H.DECISION.REOPEN_EVIDENCE",codes)
    def test_external_evidence_binding(self):
        o=self.base(); o["evidence"].append({"id":"x","kind":"attestation","e6_evidence":"missing"}); r=self.run_obj(o); self.assertTrue(any(f["code"]=="E7H.EVIDENCE.E6" for f in r["findings"]))

if __name__ == '__main__': unittest.main()
