from __future__ import annotations
import copy, hashlib, importlib.util, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("e16check",SOURCE/"tools/eigiib_preservation_intent_check.py"); CHECK=importlib.util.module_from_spec(spec); sys.modules[spec.name]=CHECK; spec.loader.exec_module(CHECK)
def committed(v):
 v=copy.deepcopy(v);v["commitment"]={"algorithm":"sha256","digest":CHECK.commitment_for(v)};return v
class PreservationIntentTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.root=Path(self.t.name)
  for rel in CHECK.EXPECTED_FREEZE_PATHS|{"conformance/e16-a1-authority-freeze.json","conformance/e15-final-closure.json","conformance/publication-readback.json","conformance/e15-a5-authority-freeze.json"}:
   src=SOURCE/rel;dst=self.root/rel;dst.parent.mkdir(parents=True,exist_ok=True)
   if src.is_file():shutil.copyfile(src,dst)
   else:dst.write_text("fixture\n")
  for rel in ("EIGIIB.toml","conformance/extension-graph.json"):
   proc=subprocess.run(["git","show",f"7fd50a2009c6a437c7fe0b680407cf337b55cf4f:{rel}"],cwd=SOURCE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
   if proc.returncode: raise RuntimeError(proc.stderr.decode(errors="replace"))
   dst=self.root/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(proc.stdout)
  self.history=self.root/"history.json";self.history.write_text(json.dumps({"standard":CHECK.HISTORY_STANDARD,"source_commit":CHECK.SOURCE_M0_A7_HEAD,"overall_result":"conformant","e15_history_result":"conformant","e15_final_closure_result":"conformant","m0_a7_result":"conformant","m0_a7_tests_result":"conformant"}))
  self.refresh()
 def tearDown(self):self.t.cleanup()
 def refresh(self):
  entries=[]
  for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS):
   raw=(self.root/rel).read_bytes();entries.append({"path":rel,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
  (self.root/"conformance/e16-a1-authority-freeze.json").write_text(json.dumps({"standard":CHECK.FREEZE_STANDARD,"status":"frozen","source":{"e15_head_commit":CHECK.SOURCE_E15_HEAD,"m0_a7_head_commit":CHECK.SOURCE_M0_A7_HEAD},"profile_revision":CHECK.PROFILE_REVISION,"authorities":entries}))
 def checker(self):return CHECK.Checker(self.root,history_report=Path("history.json"))
 def test_empty_registry(self):
  r=self.checker().run();self.assertEqual(r["structural_result"],"conformant");self.assertEqual(r["preservation_intent_result"],"not-evaluated")
 def test_history_failure(self):
  d=json.loads(self.history.read_text());d["overall_result"]="non-conformant";self.history.write_text(json.dumps(d));self.assertEqual(self.checker().run()["historical_continuity_result"],"non-conformant")
 def test_source_substitution(self):
  p=self.root/"conformance/e16-a1-adoption-transition.json";d=json.loads(p.read_text());d["source"]["head_commit"]="0"*40;p.write_text(json.dumps(d));self.refresh();self.assertEqual(self.checker().run()["structural_result"],"non-conformant")
 def test_profile_without_e16(self):
  p=self.root/"EIGIIB.toml";p.write_text(p.read_text().replace(', "E16-1.0"',''));self.refresh();self.assertEqual(self.checker().run()["structural_result"],"non-conformant")
 def test_freeze_mutation(self):
  (self.root/"docs/E16-A1-HUMAN-MASTERY-GUIDE.md").write_text("changed\n");self.assertEqual(self.checker().run()["authority_freeze_result"],"non-conformant")
 def install_positive(self):
  digest="a"*64
  pub=committed({"id":"pub-1","revision":"1","publication_state":"positive","observed_event":"published","payload_sha256":digest,"payload_bytes":10})
  life=committed({"id":"life-1","revision":"1","publication":"pub-1","lifecycle_state":"independently-read-back"})
  up=json.loads((self.root/"conformance/publication-readback.json").read_text());up["external_publication_records"]=[pub];up["publication_lifecycle_decisions"]=[life];(self.root/"conformance/publication-readback.json").write_text(json.dumps(up))
  c=committed({"id":"c-1","revision":"1","principal_id":"principal","authority_scope":["preserve"],"service_boundary":"service","allowed_replica_kinds":["object-store"],"state":"active"})
  r=committed({"id":"r-1","revision":"1","custodian":"c-1","custodian_revision":"1","kind":"object-store","locator_class":"opaque-test","provider_id":"provider","account_id":"account","region_id":"region","implementation_id":"impl","storage_class":"archive","content_algorithms":["sha256"],"properties":["content-addressed"],"state":"active"})
  pol=committed({"id":"p-1","revision":"1","state":"active","allowed_custodians":["c-1"],"allowed_replicas":["r-1"],"allowed_purposes":["preserve"],"allowed_actions":[CHECK.ACTION],"required_replica_properties":["content-addressed"],"max_payload_bytes":100})
  i=committed({"id":"i-1","revision":"1","source_publication":"pub-1","source_publication_revision":"1","source_publication_commitment":pub["commitment"]["digest"],"source_lifecycle_decision":"life-1","source_lifecycle_decision_revision":"1","source_lifecycle_decision_commitment":life["commitment"]["digest"],"source_closure":"conformance/e15-final-closure.json","source_closure_revision":"EIGIIB-E15-1.0","custodian":"c-1","custodian_revision":"1","replica":"r-1","replica_revision":"1","policy":"p-1","policy_revision":"1","purpose":"preserve","action":CHECK.ACTION,"evaluation_context":{"id":"ctx","revision":"1"},"idempotency_key":"key-1","content_sha256":digest,"content_bytes":10,"requested_replica_properties":["content-addressed"]})
  b=committed({"id":"b-1","revision":"1","intent":"i-1","intent_revision":"1","custodian":"c-1","custodian_revision":"1","replica":"r-1","replica_revision":"1","content_sha256":digest,"content_bytes":10,"sequence":1,"state":"bound","evidence_refs":["repository-binding"]})
  d=committed({"id":"d-1","revision":"1","intent":"i-1","intent_revision":"1","binding":"b-1","binding_revision":"1","sequence":1,"source_result":"permit","custodian_result":"permit","replica_result":"permit","policy_result":"permit","idempotency_result":"permit","content_identity_result":"permit","state":"admissible","reasons":["all-gates-positive"],"evidence_refs":["repository-binding"]})
  reg=json.loads((self.root/"conformance/preservation-intent.json").read_text());reg.update({"custodian_profiles":[c],"replica_profiles":[r],"preservation_policies":[pol],"preservation_intents":[i],"replica_bindings":[b],"preservation_decisions":[d]});(self.root/"conformance/preservation-intent.json").write_text(json.dumps(reg));self.refresh()
 def test_positive_intent(self):
  self.install_positive();r=self.checker().run();self.assertEqual(r["preservation_intent_result"],"conformant");self.assertEqual(r["decision_state_counts"]["admissible"],1)
 def test_retired_replica_precedes_unavailable_custodian(self):
  self.install_positive();p=self.root/"conformance/preservation-intent.json";d=json.loads(p.read_text());d["custodian_profiles"][0]["state"]="unavailable";d["custodian_profiles"][0]=committed({k:v for k,v in d["custodian_profiles"][0].items() if k!="commitment"});d["replica_profiles"][0]["state"]="retired";d["replica_profiles"][0]=committed({k:v for k,v in d["replica_profiles"][0].items() if k!="commitment"});p.write_text(json.dumps(d));self.refresh();r=self.checker().run();self.assertTrue(any(f["code"]=="E16A1.DECISION.GATE" for f in r["findings"]))

 def test_source_closure_substitution_rejected(self):
  self.install_positive();p=self.root/"conformance/preservation-intent.json";d=json.loads(p.read_text());d["preservation_intents"][0]["source_closure"]="conformance/other-closure.json";d["preservation_intents"][0]=committed({k:v for k,v in d["preservation_intents"][0].items() if k!="commitment"});p.write_text(json.dumps(d));self.refresh();r=self.checker().run();self.assertTrue(any(f["code"]=="E16A1.DECISION.GATE" for f in r["findings"]))
 def test_duplicate_idempotency_rejected(self):
  self.install_positive();p=self.root/"conformance/preservation-intent.json";d=json.loads(p.read_text());second=copy.deepcopy(d["preservation_intents"][0]);second["id"]="i-2";second=committed({k:v for k,v in second.items() if k!="commitment"});d["preservation_intents"].append(second);p.write_text(json.dumps(d));self.refresh();self.assertEqual(self.checker().run()["structural_result"],"non-conformant")
if __name__=="__main__":unittest.main()
