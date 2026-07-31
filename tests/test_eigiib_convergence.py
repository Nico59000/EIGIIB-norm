import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("e8",HERE.parent/"tools/eigiib_convergence_check.py")
mod=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=mod; SPEC.loader.exec_module(mod)
Checker=mod.Checker; STANDARD=mod.STANDARD

class E8Tests(unittest.TestCase):
    def base(self):
        return {"standard":STANDARD,"revision":"test","relying_parties":[],"migrations":[],"observations":[],"compatibility_windows":[],"policies":[],"exceptions":[],"adoption_decisions":[],"cutover_decisions":[]}
    def valid(self):
        o=self.base()
        o["relying_parties"]=[
            {"id":"a","domain":"d1","class":"c1","required":True,"status":"active"},
            {"id":"b","domain":"d2","class":"c1","required":True,"status":"active"},
        ]
        o["migrations"]=[{"id":"m","from_epoch":1,"to_epoch":2,"status":"cutover"}]
        ev=[{"kind":"test"}]
        o["observations"]=[
            {"id":"oa","migration":"m","party":"a","phase":"cutover","new_state":"accepted","old_state":"rejected","evidence":ev},
            {"id":"ob","migration":"m","party":"b","phase":"cutover","new_state":"accepted","old_state":"rejected","evidence":ev},
        ]
        o["compatibility_windows"]=[{"id":"w","migration":"m","state":"closed","allow_old":False}]
        o["policies"]=[{"id":"p","minimum":2,"distinct_by":"domain","require_old_rejected":True,"require_all_required_parties":True,"allow_exceptions":False,"required_domains":["d1","d2"],"required_classes":["c1"]}]
        o["adoption_decisions"]=[{"id":"ad","migration":"m","policy":"p","state":"converged","observations":["oa","ob"],"exceptions":[]}]
        o["cutover_decisions"]=[{"id":"co","migration":"m","state":"verified","adoption_decision":"ad","compatibility_window":"w","require_e7_continuity":True,"e7_decision":"e7ok"}]
        return o
    def run_obj(self,o,recovery=None):
        with tempfile.TemporaryDirectory() as td:
            r=Path(td); (r/"conformance").mkdir()
            (r/"conformance/convergence.json").write_text(json.dumps(o))
            (r/"conformance/recovery.json").write_text(json.dumps(recovery or {"decisions":[{"id":"e7ok","state":"continuity-established"}]}))
            return Checker(r,Path("conformance/convergence.json"),Path("conformance/recovery.json")).run()
    def test_valid_cutover(self):
        x=self.run_obj(self.valid()); self.assertEqual(x["structural_result"],"conformant"); self.assertEqual(x["cutover_result"],"verified")
    def test_quorum_overclaim_rejected(self):
        o=self.valid(); o["adoption_decisions"][0]["observations"]=["oa"]
        x=self.run_obj(o); self.assertTrue(any(f["code"]=="E8.ADOPTION.QUORUM" for f in x["findings"]))
    def test_old_acceptance_rejected_when_policy_requires_rejection(self):
        o=self.valid(); o["observations"][1]["old_state"]="accepted"
        x=self.run_obj(o); self.assertTrue(any(f["code"] in {"E8.ADOPTION.QUORUM","E8.ADOPTION.REQUIRED_PARTIES"} for f in x["findings"]))
    def test_domain_distinctness_blocks_fake_quorum(self):
        o=self.valid(); o["relying_parties"][1]["domain"]="d1"; o["policies"][0]["required_domains"]=["d1"]
        x=self.run_obj(o); self.assertTrue(any(f["code"]=="E8.ADOPTION.QUORUM" for f in x["findings"]))
    def test_required_party_missing_rejected(self):
        o=self.valid(); o["policies"][0]["minimum"]=1; o["policies"][0]["required_domains"]=["d1"]; o["adoption_decisions"][0]["observations"]=["oa"]
        x=self.run_obj(o); self.assertTrue(any(f["code"]=="E8.ADOPTION.REQUIRED_PARTIES" for f in x["findings"]))
    def test_explicit_exception_is_visible(self):
        o=self.valid(); o["policies"][0].update({"minimum":1,"required_domains":["d1"],"allow_exceptions":True})
        o["exceptions"]=[{"id":"x","migration":"m","party":"b","reason":"offline legacy appliance","disposition":"temporary"}]
        o["adoption_decisions"][0]={"id":"ad","migration":"m","policy":"p","state":"converged-with-exceptions","observations":["oa"],"exceptions":["x"]}
        x=self.run_obj(o); self.assertEqual(x["adoption_result"],"verified")
    def test_cutover_requires_e7_continuity(self):
        o=self.valid(); x=self.run_obj(o,{"decisions":[]})
        self.assertTrue(any(f["code"]=="E8.CUTOVER.E7" for f in x["findings"]))
    def test_closed_window_cannot_allow_old(self):
        o=self.valid(); o["compatibility_windows"][0]["allow_old"]=True
        x=self.run_obj(o); self.assertTrue(any(f["code"]=="E8.WINDOW.CLOSED_ALLOWS_OLD" for f in x["findings"]))
    def test_path_escape_rejected(self):
        o=self.valid(); o["observations"][0]["evidence"]=[{"path":"../escape"}]
        x=self.run_obj(o); self.assertTrue(any(f["code"]=="E8.PATH.ESCAPE" for f in x["findings"]))

    def test_cutover_rejects_declared_but_unverified_adoption(self):
        o=self.valid()
        o["observations"][1]["new_state"]="rejected"
        x=self.run_obj(o)
        self.assertTrue(any(f["code"]=="E8.CUTOVER.ADOPTION_UNVERIFIED" for f in x["findings"]))
    def test_positive_convergence_rejects_zero_minimum(self):
        o=self.valid()
        o["policies"][0].update({"minimum":0,"require_all_required_parties":False,"required_domains":[],"required_classes":[]})
        o["adoption_decisions"][0]["observations"]=[]
        x=self.run_obj(o)
        self.assertTrue(any(f["code"]=="E8.ADOPTION.ZERO_MINIMUM" for f in x["findings"]))
    def test_declared_e7_transition_must_resolve(self):
        o=self.valid()
        o["migrations"][0]["e7_transition"]="t7"
        x=self.run_obj(o,{"decisions":[{"id":"e7ok","state":"continuity-established"}],"transitions":[]})
        self.assertTrue(any(f["code"]=="E8.MIGRATION.E7_TRANSITION" for f in x["findings"]))
    def test_exception_result_stays_typed(self):
        o=self.valid(); o["policies"][0].update({"minimum":1,"required_domains":["d1"],"allow_exceptions":True})
        o["exceptions"]=[{"id":"x","migration":"m","party":"b","reason":"offline","disposition":"temporary"}]
        o["adoption_decisions"][0]={"id":"ad","migration":"m","policy":"p","state":"converged-with-exceptions","observations":["oa"],"exceptions":["x"]}
        x=self.run_obj(o)
        self.assertEqual(x["legacy_rejection_result"],"verified-with-exceptions")
        self.assertEqual(x["cutover_result"],"verified-with-exceptions")

if __name__=="__main__": unittest.main()
