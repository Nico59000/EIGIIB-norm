from __future__ import annotations
import importlib.util,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("p1a5",ROOT/"tools/eigiib_verifier_matrix.py")
p1a5=importlib.util.module_from_spec(SPEC);assert SPEC.loader is not None;sys.modules[SPEC.name]=p1a5;SPEC.loader.exec_module(p1a5)
class P1A5MatrixTests(unittest.TestCase):
 def setUp(self):self.manifest=json.loads((ROOT/"tests/fixtures/p1-a5/matrix.json").read_text())
 def test_manifest_is_closed(self):
  path,expected=p1a5.validate_manifest(ROOT,self.manifest);self.assertTrue(path.is_file());self.assertEqual(expected["end_to_end_result"],"conformant")
 def test_duplicate_json_member_rejected(self):
  with self.assertRaises(ValueError):p1a5.strict_json_loads(b'{"a":1,"a":2}',"TEST")
 def test_route_substitution_rejected(self):
  m=json.loads(json.dumps(self.manifest));m["routes"][1]["entrypoint"]="tools/eigiib_interop_chain.py"
  with self.assertRaises(ValueError):p1a5.validate_manifest(ROOT,m)
 def test_platform_weakening_rejected(self):
  m=json.loads(json.dumps(self.manifest));m["platforms"]=m["platforms"][:1]
  with self.assertRaises(ValueError):p1a5.validate_manifest(ROOT,m)
 def test_expected_identity_mismatch_rejected(self):
  m=json.loads(json.dumps(self.manifest));m["expectedResult"]["identity"]["bytes"]+=1
  with self.assertRaises(ValueError):p1a5.validate_manifest(ROOT,m)
 def test_projection_detects_divergence(self):
  e=json.loads((ROOT/"tests/fixtures/p1-a5/expected-independent-result.json").read_text());c=json.loads(json.dumps(e));c["p1a2_replay_result"]="invalid";self.assertNotEqual(p1a5.projection(e),p1a5.projection(c))
if __name__=="__main__":unittest.main()
