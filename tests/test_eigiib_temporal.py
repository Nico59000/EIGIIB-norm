import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("e11checker",HERE.parent/"tools"/"eigiib_temporal_check.py")
mod=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=mod; SPEC.loader.exec_module(mod)
Checker=mod.Checker; STANDARD=mod.STANDARD

class TemporalTests(unittest.TestCase):
    def base(self):
        return {"standard":STANDARD,"revision":"test","time_domains":[],"time_sources":[],"observations":[],"policies":[],"leases":[],"renewals":[],"replay_assertions":[],"temporal_decisions":[]}
    def valid(self):
        o=self.base()
        o["time_domains"]=[{"id":"td","unit":"second","ordering":"total","status":"active"}]
        o["time_sources"]=[{"id":"clock","domain":"td","kind":"witnessed","status":"active"}]
        o["observations"]=[{"id":"now","source":"clock","tick":120,"uncertainty":1,"evidence":["clock-evidence"]}]
        o["policies"]=[{"id":"pol","revision":"r1","domain":"td","require_e10_authorized":True,"require_lease":True,"require_replay_guard":True,"max_observation_uncertainty":2,"max_lease_age_ticks":100,"allow_grace":False,"grace_ticks":0,"max_renewal_depth":2}]
        o["leases"]=[{"id":"lease1","subject_kind":"e10-decision","subject":"authz","domain":"td","generation":0,"issued_tick":100,"valid_from":110,"valid_until":150,"status":"active","predecessor":None,"evidence":["lease-evidence"]}]
        o["replay_assertions"]=[{"id":"rp","namespace":"deploy","token":"n1","subject":"authz","state":"available","evidence":["nonce-evidence"]}]
        o["temporal_decisions"]=[{"id":"t1","subject":"authz","policy":"pol","observation":"now","lease":"lease1","replay_assertion":"rp","state":"valid"}]
        return o
    def automation(self,state="authorized"):
        return {"decisions":[{"id":"authz","state":state}]}
    def run_obj(self,obj,automation=None,files=None):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"conformance").mkdir()
            (root/"conformance/temporal.json").write_text(json.dumps(obj),encoding="utf-8")
            (root/"conformance/automation.json").write_text(json.dumps(automation or {"decisions":[]}),encoding="utf-8")
            for p,t in (files or {}).items(): q=root/p; q.parent.mkdir(parents=True,exist_ok=True); q.write_text(t,encoding="utf-8")
            return Checker(root,Path("conformance/temporal.json"),Path("conformance/automation.json")).run()
    def codes(self,r): return {f["code"] for f in r["findings"]}

    def test_valid(self):
        r=self.run_obj(self.valid(),self.automation()); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["temporal_validity_result"],"verified")
    def test_expired(self):
        o=self.valid(); o["observations"][0]["tick"]=160; o["temporal_decisions"][0]["state"]="expired"; r=self.run_obj(o,self.automation()); self.assertEqual(r["structural_result"],"conformant")
    def test_not_yet_valid(self):
        o=self.valid(); o["observations"][0]["tick"]=105; o["temporal_decisions"][0]["state"]="not-yet-valid"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_grace_valid(self):
        o=self.valid(); p=o["policies"][0]; p["allow_grace"]=True; p["grace_ticks"]=20; o["observations"][0]["tick"]=155; o["temporal_decisions"][0]["state"]="grace-valid"; self.assertEqual(self.run_obj(o,self.automation())["temporal_validity_result"],"grace")
    def test_uncertainty_crosses_expiry(self):
        o=self.valid(); o["observations"][0].update(tick=149,uncertainty=2); o["temporal_decisions"][0]["state"]="indeterminate"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_uncertainty_over_policy_is_indeterminate(self):
        o=self.valid(); o["observations"][0]["uncertainty"]=3; o["temporal_decisions"][0]["state"]="indeterminate"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_stale(self):
        o=self.valid(); o["policies"][0]["max_lease_age_ticks"]=15; o["observations"][0]["tick"]=130; o["temporal_decisions"][0]["state"]="stale"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_stale_threshold_cross_is_indeterminate(self):
        o=self.valid(); o["policies"][0]["max_lease_age_ticks"]=20; o["observations"][0].update(tick=120,uncertainty=2); o["temporal_decisions"][0]["state"]="indeterminate"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_missing_e10(self):
        o=self.valid(); o["temporal_decisions"][0]["state"]="unavailable"; self.assertEqual(self.run_obj(o,{"decisions":[]})["structural_result"],"non-conformant")
    def test_denied_e10_unavailable(self):
        o=self.valid(); o["temporal_decisions"][0]["state"]="unavailable"; self.assertEqual(self.run_obj(o,self.automation("denied"))["structural_result"],"conformant")
    def test_cross_domain_rejected(self):
        o=self.valid(); o["time_domains"].append({"id":"other","unit":"second","ordering":"total","status":"active"}); o["time_sources"][0]["domain"]="other"; self.assertIn("E11.DECISION.DOMAIN",self.codes(self.run_obj(o,self.automation())))
    def test_inactive_source_unavailable(self):
        o=self.valid(); o["time_sources"][0]["status"]="suspended"; o["temporal_decisions"][0]["state"]="unavailable"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_observation_evidence_required(self):
        o=self.valid(); o["observations"][0]["evidence"]=[]; self.assertIn("E11.EVIDENCE.EMPTY",self.codes(self.run_obj(o,self.automation())))
    def test_active_lease_requires_evidence(self):
        o=self.valid(); o["leases"][0]["evidence"]=[]; self.assertIn("E11.EVIDENCE.EMPTY",self.codes(self.run_obj(o,self.automation())))
    def test_lease_subject_mismatch(self):
        o=self.valid(); o["leases"][0]["subject"]="other"; self.assertIn("E11.DECISION.LEASE_SUBJECT",self.codes(self.run_obj(o,self.automation())))
    def test_lease_domain_mismatch(self):
        o=self.valid(); o["time_domains"].append({"id":"other","unit":"second","ordering":"total","status":"active"}); o["leases"][0]["domain"]="other"; self.assertIn("E11.DECISION.LEASE_DOMAIN",self.codes(self.run_obj(o,self.automation())))
    def test_revoked_lease_unavailable(self):
        o=self.valid(); o["leases"][0]["status"]="revoked"; o["temporal_decisions"][0]["state"]="unavailable"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_replay_consumed_rejected(self):
        o=self.valid(); o["replay_assertions"][0]["state"]="consumed"; o["temporal_decisions"][0]["state"]="replay-rejected"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_replay_unknown_unavailable(self):
        o=self.valid(); o["replay_assertions"][0]["state"]="unknown"; o["temporal_decisions"][0]["state"]="unavailable"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_duplicate_replay_token_rejected(self):
        o=self.valid(); r=dict(o["replay_assertions"][0]); r["id"]="rp2"; o["replay_assertions"].append(r); self.assertIn("E11.REPLAY.DUPLICATE",self.codes(self.run_obj(o,self.automation())))
    def test_replay_subject_mismatch(self):
        o=self.valid(); o["replay_assertions"][0]["subject"]="other"; self.assertIn("E11.DECISION.REPLAY_SUBJECT",self.codes(self.run_obj(o,self.automation())))
    def test_valid_renewal(self):
        o=self.valid(); o["leases"].append({"id":"lease2","subject_kind":"e10-decision","subject":"authz","domain":"td","generation":1,"issued_tick":140,"valid_from":145,"valid_until":190,"status":"active","predecessor":"lease1","evidence":["lease2-evidence"]}); o["renewals"]=[{"id":"rn","predecessor":"lease1","successor":"lease2","state":"approved","evidence":["renewal-evidence"]}]; o["temporal_decisions"][0]["lease"]="lease2"; o["observations"][0]["tick"]=150; r=self.run_obj(o,self.automation()); self.assertEqual(r["renewal_result"],"verified")
    def test_renewal_generation_rejected(self):
        o=self.valid(); o["leases"].append({"id":"lease2","subject_kind":"e10-decision","subject":"authz","domain":"td","generation":3,"issued_tick":140,"valid_from":145,"valid_until":190,"status":"active","predecessor":"lease1","evidence":["lease2-evidence"]}); o["renewals"]=[{"id":"rn","predecessor":"lease1","successor":"lease2","state":"approved","evidence":["x"]}]; self.assertIn("E11.RENEWAL.GENERATION",self.codes(self.run_obj(o,self.automation())))
    def test_renewal_identity_rejected(self):
        o=self.valid(); o["leases"].append({"id":"lease2","subject_kind":"e10-decision","subject":"other","domain":"td","generation":1,"issued_tick":140,"valid_from":145,"valid_until":190,"status":"active","predecessor":"lease1","evidence":["lease2-evidence"]}); o["renewals"]=[{"id":"rn","predecessor":"lease1","successor":"lease2","state":"approved","evidence":["x"]}]; self.assertIn("E11.RENEWAL.IDENTITY",self.codes(self.run_obj(o,self.automation())))
    def test_lease_cycle_rejected(self):
        o=self.valid(); o["leases"][0]["predecessor"]="lease2"; o["leases"].append({"id":"lease2","subject_kind":"e10-decision","subject":"authz","domain":"td","generation":1,"issued_tick":90,"valid_from":100,"valid_until":160,"status":"active","predecessor":"lease1","evidence":["lease2-evidence"]}); self.assertIn("E11.LEASE.CYCLE",self.codes(self.run_obj(o,self.automation())))
    def test_renewal_depth_enforced(self):
        o=self.valid(); o["policies"][0]["max_renewal_depth"]=0; o["leases"].append({"id":"lease2","subject_kind":"e10-decision","subject":"authz","domain":"td","generation":1,"issued_tick":105,"valid_from":110,"valid_until":170,"status":"active","predecessor":"lease1","evidence":["lease2-evidence"]}); o["temporal_decisions"][0]["lease"]="lease2"; o["temporal_decisions"][0]["state"]="unavailable"; self.assertEqual(self.run_obj(o,self.automation())["structural_result"],"conformant")
    def test_declared_state_mismatch_rejected(self):
        o=self.valid(); o["observations"][0]["tick"]=160; self.assertIn("E11.DECISION.MISMATCH",self.codes(self.run_obj(o,self.automation())))
    def test_path_escape_rejected(self):
        o=self.valid(); o["observations"][0]["evidence"]=[{"path":"../escape"}]; self.assertIn("E11.PATH.ESCAPE",self.codes(self.run_obj(o,self.automation())))
    def test_grace_config_coherence(self):
        o=self.valid(); o["policies"][0]["grace_ticks"]=5; self.assertIn("E11.POLICY.GRACE",self.codes(self.run_obj(o,self.automation())))
    def test_empty_registry_conforms(self):
        r=self.run_obj(self.base(),{"decisions":[]}); self.assertEqual(r["structural_result"],"conformant"); self.assertEqual(r["temporal_validity_result"],"not-evaluated")
    def test_structural_error_suppresses_positive(self):
        o=self.valid(); o["time_domains"][0]["ordering"]="partial"; r=self.run_obj(o,self.automation()); self.assertEqual(r["structural_result"],"non-conformant"); self.assertEqual(r["temporal_validity_result"],"not-evaluated")

if __name__=="__main__": unittest.main()
