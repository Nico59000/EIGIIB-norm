import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("e11h",HERE.parent/"tools"/"eigiib_temporal_hardening_check.py")
mod=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=mod; SPEC.loader.exec_module(mod)
Checker=mod.Checker

class HardeningTests(unittest.TestCase):
    def obj(self):
        b={"proposal_revision":"p1","policy_revision":"q1","context_revision":"c1"}
        return {
          "standard":"EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0","revision":"test",
          "time_domains":[{"id":"td","unit":"second","ordering":"total","status":"active"}],
          "time_sources":[{"id":"clock","domain":"td","kind":"witnessed","status":"active"}],
          "observations":[{"id":"now","source":"clock","tick":120,"uncertainty":1,"evidence":["e"]}],
          "policies":[{"id":"pol","revision":"r","domain":"td","require_e10_authorized":True,"require_lease":True,"require_replay_guard":True,"max_observation_uncertainty":2,"max_lease_age_ticks":100,"allow_grace":False,"grace_ticks":0,"max_renewal_depth":2}],
          "leases":[{"id":"l1","subject_kind":"e10-decision","subject":"d","domain":"td","generation":0,"issued_tick":100,"valid_from":110,"valid_until":150,"status":"active","predecessor":None,"evidence":["le"],"e10_boundary":dict(b)}],
          "renewals":[],
          "replay_assertions":[{"id":"rp","namespace":"n","token":"t","subject":"d","state":"available","evidence":["re"],"observation":"now","e10_boundary":dict(b)}],
          "temporal_decisions":[{"id":"t","subject":"d","policy":"pol","observation":"now","lease":"l1","replay_assertion":"rp","state":"valid","e10_boundary":dict(b)}]
        }
    def auto(self): return {"decisions":[{"id":"d","state":"authorized","proposal_revision":"p1","policy_revision":"q1","context_revision":"c1"}]}
    def run_obj(self,o=None,a=None):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"conformance").mkdir(); (root/"tools").mkdir()
            (root/"conformance/temporal.json").write_text(json.dumps(o if o is not None else self.obj()))
            (root/"conformance/automation.json").write_text(json.dumps(a if a is not None else self.auto()))
            (root/"tools/eigiib_temporal_check.py").write_text((HERE.parent/"tools/eigiib_temporal_check.py").read_text())
            return Checker(root,Path("conformance/temporal.json"),Path("conformance/automation.json")).run()
    def codes(self,r): return {x["code"] for x in r["findings"]}
    def test_valid_hardening(self): self.assertEqual(self.run_obj()["structural_result"],"conformant")
    def test_context_revision_change_rejected(self):
        o=self.obj(); o["temporal_decisions"][0]["e10_boundary"]["context_revision"]="old"; self.assertIn("E11H.E10.BOUNDARY",self.codes(self.run_obj(o)))
    def test_lease_boundary_change_rejected(self):
        o=self.obj(); o["leases"][0]["e10_boundary"]["policy_revision"]="old"; self.assertIn("E11H.LEASE.BOUNDARY",self.codes(self.run_obj(o)))
    def test_replay_boundary_change_rejected(self):
        o=self.obj(); o["replay_assertions"][0]["e10_boundary"]["proposal_revision"]="old"; self.assertIn("E11H.REPLAY.BOUNDARY",self.codes(self.run_obj(o)))
    def test_replay_observation_mismatch_rejected(self):
        o=self.obj(); o["observations"].append({"id":"old","source":"clock","tick":119,"uncertainty":1,"evidence":["e"]}); o["replay_assertions"][0]["observation"]="old"; self.assertIn("E11H.REPLAY.OBSERVATION",self.codes(self.run_obj(o)))
    def test_inactive_domain_rejected_for_positive_state(self):
        o=self.obj(); o["time_domains"][0]["status"]="retired"; self.assertIn("E11H.DOMAIN.ACTIVE",self.codes(self.run_obj(o)))
    def test_retired_domain_allows_historical_expired_record(self):
        o=self.obj(); o["time_domains"][0]["status"]="retired"; o["observations"][0]["tick"]=160; o["temporal_decisions"][0]["state"]="expired"; self.assertEqual(self.run_obj(o)["structural_result"],"conformant")
    def test_negative_interval_origin_rejected(self):
        o=self.obj(); o["observations"][0].update(tick=0,uncertainty=1); o["temporal_decisions"][0]["state"]="not-yet-valid"; self.assertIn("E11H.OBS.ORIGIN",self.codes(self.run_obj(o)))
    def with_successor(self):
        o=self.obj(); b=dict(o["leases"][0]["e10_boundary"])
        o["leases"].append({"id":"l2","subject_kind":"e10-decision","subject":"d","domain":"td","generation":1,"issued_tick":130,"valid_from":140,"valid_until":190,"status":"active","predecessor":"l1","evidence":["le2"],"e10_boundary":b})
        o["temporal_decisions"][0]["lease"]="l2"; o["observations"][0]["tick"]=145
        return o
    def test_used_successor_requires_approved_renewal(self):
        o=self.with_successor(); self.assertIn("E11H.RENEWAL.EVIDENCE",self.codes(self.run_obj(o)))
    def test_backdated_successor_rejected(self):
        o=self.with_successor(); o["leases"][1]["issued_tick"]=90; o["renewals"]=[{"id":"rn","predecessor":"l1","successor":"l2","state":"approved","evidence":["x"]}]; self.assertIn("E11H.LEASE.BACKDATED",self.codes(self.run_obj(o)))
    def test_renewal_fork_rejected(self):
        o=self.with_successor(); b=dict(o["leases"][0]["e10_boundary"])
        o["leases"].append({"id":"l3","subject_kind":"e10-decision","subject":"d","domain":"td","generation":1,"issued_tick":131,"valid_from":141,"valid_until":195,"status":"active","predecessor":"l1","evidence":["le3"],"e10_boundary":b})
        o["renewals"]=[{"id":"r2","predecessor":"l1","successor":"l2","state":"approved","evidence":["x"]},{"id":"r3","predecessor":"l1","successor":"l3","state":"approved","evidence":["x"]}]
        self.assertIn("E11H.RENEWAL.FORK",self.codes(self.run_obj(o)))
    def test_empty_registry_conforms(self):
        o={"standard":"EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0","revision":"x","time_domains":[],"time_sources":[],"observations":[],"policies":[],"leases":[],"renewals":[],"replay_assertions":[],"temporal_decisions":[]}
        self.assertEqual(self.run_obj(o,{"decisions":[]})["structural_result"],"conformant")
if __name__=="__main__": unittest.main()
