import importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
try:
    import cryptography  # noqa: F401
except ModuleNotFoundError:
    raise unittest.SkipTest('cryptography is exercised by the dedicated IDP-A5 workflow')
def load(path,name):
    s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
A=load(ROOT/'tools/eigiib_idp_a5_check.py','a5check'); B=load(ROOT/'tools/eigiib_idp_a5_independent.py','a5ind')
class A5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a=json.loads((ROOT/'conformance/idp-a5-release-authority.json').read_text()); cls.pb=(ROOT/'conformance/idp-a5-public-projection.json').read_bytes()
    def test_reference_positive(self): self.assertEqual(A.evaluate(self.a,self.pb),[])
    def test_independent_positive(self): self.assertEqual(B.check(self.a,self.pb),[])
    def test_exact_projection_replay(self): self.assertTrue(A.evaluate(self.a,self.pb+b'\n'))
    def test_threshold_is_two(self): self.assertEqual(self.a['reviewPolicy']['threshold'],2)
    def test_private_keys_absent(self): self.assertNotIn('PRIVATE KEY',(ROOT/'conformance/idp-a5-release-authority.json').read_text())
if __name__=='__main__': unittest.main()
