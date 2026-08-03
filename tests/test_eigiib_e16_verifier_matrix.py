from __future__ import annotations
import copy, importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]
def module(name,rel):
 spec=importlib.util.spec_from_file_location(name,SOURCE/rel);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
REF=module("e16a5_ref_test","tools/eigiib_e16_preservation_reference.py")
IND=module("e16a5_ind_test","tools/eigiib_e16_preservation_independent.py")
RUN=module("e16a5_matrix_test","tools/eigiib_e16_verifier_matrix.py")
class MatrixTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls): cls.catalog=json.loads((SOURCE/"conformance/e16-a5-verifier-matrix.json").read_text())
 def test_all_frozen_vectors_match_both_implementations(self):
  for case in self.catalog["cases"]:
   a=REF.verify(case);b=IND.evaluate(case);self.assertEqual(a,b);self.assertEqual(a["state"],case["expected_state"])
 def test_expected_state_distribution(self):
  states=[REF.verify(x)["state"] for x in self.catalog["cases"]];self.assertEqual({s:states.count(s) for s in set(states)},{"e16-preservation-closure-verified":4,"rejected":14,"held":1,"unavailable":1})
 def test_sources_are_distinct_and_non_importing(self):
  a=(SOURCE/self.catalog["reference_verifier"]).read_text();b=(SOURCE/self.catalog["independent_verifier"]).read_text();self.assertNotEqual(a,b);self.assertNotIn("eigiib_e16_preservation_independent",a);self.assertNotIn("eigiib_e16_preservation_reference",b)
 def test_negative_precedes_unavailable(self):
  case=next(x for x in self.catalog["cases"] if x["id"]=="negative-precedes-unavailable");self.assertEqual(REF.verify(case)["state"],"rejected")
 def test_route_content_mutation_rejected(self):
  case=copy.deepcopy(self.catalog["cases"][0]);case["inputs"]["restore_routes"][0]["content_sha256"]="0"*64;self.assertEqual(REF.verify(case)["state"],"rejected")
 def test_duplicate_domain_rejected(self):
  case=copy.deepcopy(self.catalog["cases"][0]);case["inputs"]["restore_routes"][1]["verifier_domain"]=case["inputs"]["restore_routes"][0]["verifier_domain"];self.assertEqual(IND.evaluate(case)["state"],"rejected")
 def test_one_case_separate_process_runner(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/"tools").mkdir();(root/"conformance").mkdir()
   for rel in [self.catalog["reference_verifier"],self.catalog["independent_verifier"]]: (root/rel).write_bytes((SOURCE/rel).read_bytes())
   cat=copy.deepcopy(self.catalog);cat["cases"]=[cat["cases"][0]];(root/"conformance/e16-a5-verifier-matrix.json").write_text(json.dumps(cat))
   report=RUN.run_matrix(root);self.assertEqual(report["overall_result"],"conformant");self.assertEqual(report["matched_case_count"],1)
 def test_fixture_matches_direct_report(self):
  fixture=json.loads((SOURCE/"tests/fixtures/e16-a5/expected-matrix-report.json").read_text());self.assertEqual(fixture["case_count"],len(self.catalog["cases"]));self.assertEqual(fixture["state_counts"],{"e16-preservation-closure-verified":4,"rejected":14,"held":1,"unavailable":1})
if __name__=="__main__":unittest.main()
