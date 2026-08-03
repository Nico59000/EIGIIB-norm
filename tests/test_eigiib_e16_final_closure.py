from __future__ import annotations
import copy, hashlib, importlib.util, json, sys, tempfile, unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("e16a5closure",SOURCE/"tools/eigiib_e16_final_closure_check.py");CHECK=importlib.util.module_from_spec(spec);sys.modules[spec.name]=CHECK;spec.loader.exec_module(CHECK)
class ClosureTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  for rel in ["conformance/E16-A5-MANUAL-REVIEW.md", "conformance/e16-a5-adoption-transition.json", "conformance/e16-a5-authority-manifest.json", "conformance/e16-a5-verifier-matrix.json", "conformance/e16-final-closure.json", "docs/E16-A5-HUMAN-MASTERY-GUIDE.md", "docs/E16-FINAL-CLOSURE-REPORT.md", "extensions/E16-A5-INDEPENDENT-PRESERVATION-VERIFIER-MATRIX-DIFFERENTIAL-RESTORE-REPLAY-FINAL-FREEZE.md", "schemas/eigiib-e16-a5-adoption-transition.schema.json", "schemas/eigiib-e16-a5-authority-manifest.schema.json", "schemas/eigiib-e16-a5-authority-freeze.schema.json", "schemas/eigiib-e16-a5-verifier-matrix.schema.json", "schemas/eigiib-e16-a5-final-closure.schema.json", "tests/fixtures/e16-a5/expected-matrix-report.json", "tests/fixtures/e16-a5/expected-closure-report.json", "tests/test_eigiib_e16_verifier_matrix.py", "tests/test_eigiib_e16_final_closure.py", "tools/eigiib_e16_preservation_reference.py", "tools/eigiib_e16_preservation_independent.py", "tools/eigiib_e16_verifier_matrix.py", "tools/eigiib_historical_e16_a4_replay.py", "tools/eigiib_e16_final_closure_check.py"]:
   src=SOURCE/rel;dst=self.root/rel;dst.parent.mkdir(parents=True,exist_ok=True)
   if src.is_file():dst.write_bytes(src.read_bytes())
  (self.root/"historical-e16-a4-report.json").write_text(json.dumps({"standard":CHECK.HISTORY_STANDARD,"source_commit":CHECK.SOURCE_COMMIT,"overall_result":"conformant","ancestry_result":"conformant","e16_a3_history_result":"conformant","e16_a4_result":"conformant","e16_a4_tests_result":"conformant"}))
  (self.root/"e16-a5-matrix-report.json").write_bytes((SOURCE/"tests/fixtures/e16-a5/expected-matrix-report.json").read_bytes())
  self.profile();self.graph();self.fillers();self.freeze()
 def tearDown(self):self.temp.cleanup()
 def profile(self):
  keys={"e16_a5_contract":"extensions/E16-A5-INDEPENDENT-PRESERVATION-VERIFIER-MATRIX-DIFFERENTIAL-RESTORE-REPLAY-FINAL-FREEZE.md","e16_final_closure":"conformance/e16-final-closure.json","e16_a5_verifier_matrix":"conformance/e16-a5-verifier-matrix.json","e16_a5_transition":"conformance/e16-a5-adoption-transition.json","e16_a5_authority_manifest":"conformance/e16-a5-authority-manifest.json","e16_a5_authority_freeze":"conformance/e16-a5-authority-freeze.json","e16_a5_human_mastery":"docs/E16-A5-HUMAN-MASTERY-GUIDE.md","e16_final_closure_report":"docs/E16-FINAL-CLOSURE-REPORT.md"}
  text='standard="EIGIIB-1.0"\nextensions=["E16-1.0"]\nrevision="EIGIIB-E16-1.0"\nrequired_authorities='+json.dumps(list(keys))+'\n[authorities]\n'+''.join(f'{k}="{v}"\n' for k,v in keys.items())+'[[manual_gates]]\nid="e16-a5-final-closure-review"\nstatus="complete"\nauthority="e16_a5_contract"\nattestation="conformance/E16-A5-MANUAL-REVIEW.md"\n';(self.root/"EIGIIB.toml").write_text(text)
 def graph(self):
  (self.root/"conformance/extension-graph.json").write_text(json.dumps({"nodes":[{"id":"E16","checker":"tools/eigiib_e16_final_closure_check.py","registry":"conformance/e16-final-closure.json","hardening_profiles":["E16-A5"]}]}))
 def fillers(self):
  manifest=json.loads((self.root/"conformance/e16-a5-authority-manifest.json").read_text())
  for rel in manifest["authorities"].values():
   p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True)
   if not p.exists():p.write_text("fixture\n")
  for i in range(95-len({x for x in manifest["authorities"].values()}|{"EIGIIB.toml","conformance/extension-graph.json"})): (self.root/f"frozen/f{i:03d}.txt").parent.mkdir(parents=True,exist_ok=True);(self.root/f"frozen/f{i:03d}.txt").write_text("x\n")
 def freeze(self):
  paths=[]
  for p in self.root.rglob('*'):
   if p.is_file():
    rel=p.relative_to(self.root).as_posix()
    if rel not in {"conformance/e16-a5-authority-freeze.json","historical-e16-a4-report.json","e16-a5-matrix-report.json"}:paths.append(rel)
  paths=sorted(paths)[:95]
  while len(paths)<95:
   rel=f"extra/{len(paths):03d}.txt";p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text("x\n");paths.append(rel)
  items=[]
  for rel in sorted(paths):raw=(self.root/rel).read_bytes();items.append({"path":rel,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
  (self.root/"conformance/e16-a5-authority-freeze.json").write_text(json.dumps({"standard":CHECK.FREEZE_STANDARD,"status":"final-frozen","profile_revision":CHECK.PROFILE_REVISION,"source_e16_a4_commit":CHECK.SOURCE_COMMIT,"authority_count":95,"authorities":items}))
 def checker(self):return CHECK.Checker(self.root)
 def test_positive_closure(self):self.assertEqual(self.checker().run()["final_state"],"closed")
 def test_history_failure(self):
  p=self.root/"historical-e16-a4-report.json";d=json.loads(p.read_text());d["overall_result"]="non-conformant";p.write_text(json.dumps(d));self.assertEqual(self.checker().run()["final_state"],"open")
 def test_matrix_divergence(self):
  p=self.root/"e16-a5-matrix-report.json";d=json.loads(p.read_text());d["reports_byte_identical"]=False;p.write_text(json.dumps(d));self.assertEqual(self.checker().run()["matrix_result"],"non-conformant")
 def test_profile_downgrade(self):
  p=self.root/"EIGIIB.toml";p.write_text(p.read_text().replace("EIGIIB-E16-1.0","EIGIIB-E16-draft-1.0"));self.freeze();self.assertEqual(self.checker().run()["final_state"],"open")
 def test_freeze_mutation(self):
  p=next(x for x in self.root.rglob('*.md'));p.write_text(p.read_text()+"changed\n");self.assertEqual(self.checker().run()["authority_freeze_result"],"non-conformant")
 def test_source_substitution(self):
  p=self.root/"conformance/e16-a5-adoption-transition.json";d=json.loads(p.read_text());d["source"]["head_commit"]="0"*40;p.write_text(json.dumps(d));self.freeze();self.assertEqual(self.checker().run()["structural_result"],"non-conformant")
 def test_manifest_substitution(self):
  p=self.root/"conformance/e16-a5-authority-manifest.json";d=json.loads(p.read_text());d["authorities"]["contract"]="extensions/other.md";p.write_text(json.dumps(d));self.freeze();self.assertEqual(self.checker().run()["structural_result"],"non-conformant")
 def test_expected_fixture_shape(self):
  d=json.loads((SOURCE/"tests/fixtures/e16-a5/expected-closure-report.json").read_text());self.assertEqual(d["authority_count"],95);self.assertEqual(d["final_state"],"closed")
if __name__=="__main__":unittest.main()
