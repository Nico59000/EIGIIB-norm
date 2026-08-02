from __future__ import annotations
import copy, importlib.util, json, sys, tempfile, unittest
from pathlib import Path

TOOL=Path(__file__).parents[1]/"tools"/"eigiib_disclosure_revocation_check.py"
SPEC=importlib.util.spec_from_file_location("eigiib_a4",TOOL);MODULE=importlib.util.module_from_spec(SPEC);assert SPEC and SPEC.loader;sys.modules[SPEC.name]=MODULE;SPEC.loader.exec_module(MODULE);Checker=MODULE.Checker
A1_STANDARD="EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0+E14-1.0";H64="a"*64;P64="b"*64

def seal(x):
 x=copy.deepcopy(x);x["commitment"]={"algorithm":"sha256","digest":"0"*64};x["commitment"]["digest"]=Checker.canonical_digest(x);return x

def record():return {"id":"rec-1","revision":"r1","subject":"subject:1","classification":"confidential","revocation_state":"active","commitment":{"algorithm":"sha256","digest":H64}}
def projection():return {"id":"proj-1","revision":"p1","source_record":"rec-1","source_revision":"r1","source_commitment":H64,"state":"sealed","commitment":{"algorithm":"sha256","digest":P64},"authorized_audience":{"id":"aud-1","revision":"a1"},"disclosure_policy":{"id":"pol-1","revision":"pol1"},"evaluation_context":{"id":"ctx-1","revision":"c1"},"correlation_controls":["audience-bound","single-use"],"claims":[]}
def auth_request():return {"id":"req-1","revision":"ar1","projection":"proj-1","projection_revision":"p1","projection_commitment":P64,"source_record":"rec-1","source_revision":"r1","source_commitment":H64,"audience":"aud-1","audience_revision":"a1","policy":"pol-1","policy_revision":"pol1","context":"ctx-1","context_revision":"c1","purpose":"audit","action":"eigiib:e14:disclose-projection","operation":"op-1"}
def auth_decision(state="permit"):return {"id":"dec-1","request":"req-1","request_revision":"ar1","state":state,"projection_result":"admissible","audience_result":"eligible","policy_result":"permit","context_result":"admissible","evaluator":"test","reasons":["test"],"evidence":["e:a2"]}
def enforcement():return {"id":"er-1","revision":"er1","authorization_decision":"dec-1","authorization_request":"req-1","authorization_request_revision":"ar1","projection":"proj-1","projection_revision":"p1","projection_commitment":P64,"source_record":"rec-1","source_revision":"r1","source_commitment":H64,"audience":"aud-1","audience_revision":"a1","purpose":"audit","operation":"op-1","control_profile":"prof-1","control_profile_revision":"cp1","budget":"bud-1","budget_revision":"b1","linkability_domain":"dom-1","operation_nonce":"nonce-1"}
def consumption(state="committed"):return {"id":"con-1","revision":"c1","enforcement_request":"er-1","enforcement_request_revision":"er1","state":state,"sequence":1,"reasons":["test"],"evidence":["e:a3"]}
def freshness(state="active",epoch=10):return {"id":"fresh-1","revision":"f1","state":state,"current_epoch":epoch}
def distribution(state="active"):
 return seal({"id":"dist-1","revision":"d1","state":state,"projection":"proj-1","projection_revision":"p1","projection_commitment":P64,"audience":"aud-1","purpose":"audit","endpoint":"channel:1"})
def history(ident,kind,subject,revision,commitment,state="active",generation=1,predecessor=None,observed=5,valid=20):
 return seal({"id":ident,"authority":"fresh-1","authority_revision":"f1","subject_kind":kind,"subject":subject,"subject_revision":revision,"subject_commitment":commitment,"generation":generation,"predecessor":predecessor,"state":state,"observed_epoch":observed,"valid_until_epoch":valid,"evidence":[f"e:{ident}"]})
def attempt(dist,hs,hp,hd):
 return {"id":"att-1","revision":"at1","source_record":"rec-1","source_revision":"r1","source_commitment":H64,"projection":"proj-1","projection_revision":"p1","projection_commitment":P64,"authorization_request":"req-1","authorization_request_revision":"ar1","authorization_decision":"dec-1","authorization_decision_request_revision":"ar1","enforcement_request":"er-1","enforcement_request_revision":"er1","correlation_consumption":"con-1","correlation_consumption_revision":"c1","distribution":"dist-1","distribution_revision":"d1","distribution_commitment":dist["commitment"]["digest"],"freshness_source":"fresh-1","freshness_source_revision":"f1","evaluation_epoch":10,"source_head":{"id":hs["id"],"commitment":hs["commitment"]["digest"],"minimum_generation":1},"projection_head":{"id":hp["id"],"commitment":hp["commitment"]["digest"],"minimum_generation":1},"distribution_head":{"id":hd["id"],"commitment":hd["commitment"]["digest"],"minimum_generation":1}}
def decision(state="admissible",source="active",projection_state="active",distribution_state="available",fresh="fresh",rollback="current",auth="permit",corr="committed"):
 return {"id":"rd-1","attempt":"att-1","attempt_revision":"at1","state":state,"source_status_result":source,"projection_status_result":projection_state,"distribution_status_result":distribution_state,"freshness_result":fresh,"rollback_result":rollback,"authorization_result":auth,"correlation_result":corr,"evaluator":"test","reasons":["test"],"evidence":["e:a4"] if state in {"admissible","rejected"} else []}

class A4Tests(unittest.TestCase):
 def base(self):
  d=distribution();hs=history("hs-1","source-record","rec-1","r1",H64);hp=history("hp-1","projection","proj-1","p1",P64);hd=history("hd-1","distribution","dist-1","d1",d["commitment"]["digest"])
  a1={"standard":A1_STANDARD,"status":"structural-only","records":[record()],"projections":[projection()]}
  a2={"standard":"EIGIIB-E14-A2-1.0","status":"structural-only","upstream_registry":"conformance/confidential-evidence.json","audiences":[],"disclosure_policies":[],"evaluation_contexts":[],"requests":[auth_request()],"decisions":[auth_decision()]}
  a3={"standard":"EIGIIB-E14-A3-1.0","status":"structural-only","upstream_projection_registry":"conformance/confidential-evidence.json","upstream_authorization_registry":"conformance/disclosure-authorization.json","control_profiles":[],"budgets":[],"enforcement_requests":[enforcement()],"consumptions":[consumption()]}
  a4={"standard":"EIGIIB-E14-A4-1.0","status":"structural-only","upstream_projection_registry":"conformance/confidential-evidence.json","upstream_authorization_registry":"conformance/disclosure-authorization.json","upstream_correlation_registry":"conformance/correlation-control.json","freshness_sources":[freshness()],"distribution_channels":[d],"status_histories":[hs,hp,hd],"disclosure_attempts":[attempt(d,hs,hp,hd)],"decisions":[decision()]}
  return a1,a2,a3,a4
 def run_case(self,a1,a2,a3,a4):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp)
   files={"conformance/confidential-evidence.json":a1,"conformance/disclosure-authorization.json":a2,"conformance/correlation-control.json":a3,"conformance/disclosure-revocation.json":a4}
   for rel,obj in files.items():(root/rel).parent.mkdir(parents=True,exist_ok=True);(root/rel).write_text(json.dumps(obj),encoding="utf-8")
   for rel in ("conformance/E14-A4-MANUAL-REVIEW.md","extensions/E14-A4-REVOCATION-FRESHNESS-DISTRIBUTION-WITHDRAWAL-DISCLOSURE-ANTI-ROLLBACK-REPLAY.md","docs/E14-A4-HUMAN-MASTERY-GUIDE.md"):(root/rel).parent.mkdir(parents=True,exist_ok=True);(root/rel).write_text("x",encoding="utf-8")
   (root/"EIGIIB.toml").write_text('''extensions=["E14-1.0"]
revision="EIGIIB-E14-draft-1.0"
required_authorities=["confidential_evidence","disclosure_authorization","correlation_control","e14_a4_contract","disclosure_revocation","e14_a4_human_mastery"]
[authorities]
confidential_evidence="conformance/confidential-evidence.json"
disclosure_authorization="conformance/disclosure-authorization.json"
correlation_control="conformance/correlation-control.json"
e14_a4_contract="extensions/E14-A4-REVOCATION-FRESHNESS-DISTRIBUTION-WITHDRAWAL-DISCLOSURE-ANTI-ROLLBACK-REPLAY.md"
disclosure_revocation="conformance/disclosure-revocation.json"
e14_a4_human_mastery="docs/E14-A4-HUMAN-MASTERY-GUIDE.md"
[[manual_gates]]
id="e14-a4-revocation-freshness-boundary-review"
status="complete"
authority="e14_a4_contract"
attestation="conformance/E14-A4-MANUAL-REVIEW.md"
''',encoding="utf-8")
   return Checker(root).run()
 def conformant(self,r):self.assertEqual(r["structural_result"],"conformant",r["findings"])
 def reseal_history(self,a4,index):a4["status_histories"][index]=seal(a4["status_histories"][index]);return a4["status_histories"][index]
 def update_ref(self,a4,key,h):a4["disclosure_attempts"][0][key]={"id":h["id"],"commitment":h["commitment"]["digest"],"minimum_generation":1}
 def test_empty_registry_exact_report(self):
  a1,a2,a3,a4=self.base();a1["records"]=[];a1["projections"]=[];a2["requests"]=[];a2["decisions"]=[];a3["enforcement_requests"]=[];a3["consumptions"]=[]
  for k in ("freshness_sources","distribution_channels","status_histories","disclosure_attempts","decisions"):a4[k]=[]
  expected={"tool":"eigiib-disclosure-revocation-check","tool_version":"0.1.0","standard":"EIGIIB-E14-A4-1.0","structural_result":"conformant","upstream_binding_result":"conformant","revocation_freshness_result":"not-evaluated","distribution_withdrawal_result":"not-evaluated","anti_rollback_result":"not-evaluated","freshness_source_count":0,"distribution_channel_count":0,"status_history_count":0,"disclosure_attempt_count":0,"decision_count":0,"decision_counts":{"admissible":0,"held":0,"rejected":0,"unavailable":0},"findings":[]}
  self.assertEqual(self.run_case(a1,a2,a3,a4),expected)
 def test_valid_admissible(self):self.conformant(self.run_case(*self.base()))
 def test_source_revoked_rejected(self):
  a1,a2,a3,a4=self.base();a4["status_histories"][0]["state"]="revoked";h=self.reseal_history(a4,0);self.update_ref(a4,"source_head",h);a4["decisions"][0]=decision("rejected",source="revoked");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_projection_superseded_rejected(self):
  a1,a2,a3,a4=self.base();a4["status_histories"][1]["state"]="superseded";h=self.reseal_history(a4,1);self.update_ref(a4,"projection_head",h);a4["decisions"][0]=decision("rejected",projection_state="superseded");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_distribution_withdrawn_rejected(self):
  a1,a2,a3,a4=self.base();a4["status_histories"][2]["state"]="withdrawn";h=self.reseal_history(a4,2);self.update_ref(a4,"distribution_head",h);a4["decisions"][0]=decision("rejected",distribution_state="withdrawn");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_stale_status_rejected(self):
  a1,a2,a3,a4=self.base();a4["status_histories"][1]["valid_until_epoch"]=9;h=self.reseal_history(a4,1);self.update_ref(a4,"projection_head",h);a4["decisions"][0]=decision("rejected",fresh="stale");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_not_yet_effective_held(self):
  a1,a2,a3,a4=self.base();a4["status_histories"][1]["observed_epoch"]=11;a4["status_histories"][1]["valid_until_epoch"]=20;h=self.reseal_history(a4,1);self.update_ref(a4,"projection_head",h);a4["decisions"][0]=decision("held",fresh="not-yet-effective");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_old_head_rollback_rejected(self):
  a1,a2,a3,a4=self.base();old=a4["status_histories"][0];new=history("hs-2","source-record","rec-1","r1",H64,generation=2,predecessor={"id":old["id"],"commitment":old["commitment"]["digest"]},observed=7,valid=25);a4["status_histories"].append(new);a4["decisions"][0]=decision("rejected",rollback="rollback-detected");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_minimum_generation_rollback_rejected(self):
  a1,a2,a3,a4=self.base();a4["disclosure_attempts"][0]["source_head"]["minimum_generation"]=2;a4["decisions"][0]=decision("rejected",rollback="rollback-detected");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_authority_contested_held(self):
  a1,a2,a3,a4=self.base();a4["freshness_sources"][0]["state"]="contested";a4["decisions"][0]=decision("held",source="held",projection_state="held",distribution_state="held",fresh="held",rollback="held");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_authority_unavailable(self):
  a1,a2,a3,a4=self.base();a4["freshness_sources"][0]["state"]="unavailable";a4["decisions"][0]=decision("unavailable",source="unavailable",projection_state="unavailable",distribution_state="unavailable",fresh="unavailable",rollback="unavailable");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_authorization_deny_rejected(self):
  a1,a2,a3,a4=self.base();a2["decisions"][0]["state"]="deny";a4["decisions"][0]=decision("rejected",auth="deny");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_correlation_rejected(self):
  a1,a2,a3,a4=self.base();a3["consumptions"][0]["state"]="rejected";a4["decisions"][0]=decision("rejected",corr="rejected");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_negative_precedes_unavailable(self):
  a1,a2,a3,a4=self.base();a2["decisions"][0]["state"]="deny";a3["consumptions"][0]["state"]="unavailable";a4["decisions"][0]=decision("rejected",auth="deny",corr="unavailable");self.conformant(self.run_case(a1,a2,a3,a4))
 def test_generation_gap_structural_error(self):
  a1,a2,a3,a4=self.base();old=a4["status_histories"][0];a4["status_histories"].append(history("hs-3","source-record","rec-1","r1",H64,generation=3,predecessor={"id":old["id"],"commitment":old["commitment"]["digest"]}));self.assertEqual(self.run_case(a1,a2,a3,a4)["structural_result"],"non-conformant")
 def test_predecessor_mismatch_structural_error(self):
  a1,a2,a3,a4=self.base();a4["status_histories"].append(history("hs-2","source-record","rec-1","r1",H64,generation=2,predecessor={"id":"wrong","commitment":"f"*64}));self.assertEqual(self.run_case(a1,a2,a3,a4)["structural_result"],"non-conformant")
 def test_history_commitment_tamper_rejected(self):
  a1,a2,a3,a4=self.base();a4["status_histories"][0]["state"]="revoked";self.assertEqual(self.run_case(a1,a2,a3,a4)["structural_result"],"non-conformant")
 def test_exact_binding_mismatch_rejected(self):
  a1,a2,a3,a4=self.base();a4["disclosure_attempts"][0]["projection_commitment"]="f"*64;self.assertEqual(self.run_case(a1,a2,a3,a4)["structural_result"],"non-conformant")
 def test_evaluation_epoch_must_match_source(self):
  a1,a2,a3,a4=self.base();a4["disclosure_attempts"][0]["evaluation_epoch"]=9;self.assertEqual(self.run_case(a1,a2,a3,a4)["structural_result"],"non-conformant")
 def test_duplicate_decision_rejected(self):
  a1,a2,a3,a4=self.base();x=copy.deepcopy(a4["decisions"][0]);x["id"]="rd-2";a4["decisions"].append(x);self.assertEqual(self.run_case(a1,a2,a3,a4)["structural_result"],"non-conformant")

if __name__=="__main__":unittest.main()
