from __future__ import annotations
import importlib.util, json, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
REF=load("a5ref",ROOT/"tools/eigiib_idp_a5_check.py")
IND=load("a5ind",ROOT/"tools/eigiib_idp_a5_independent.py")

class IDPA5Tests(unittest.TestCase):
    def setUp(self):
        self.pkg=json.loads((ROOT/"conformance/idp-a5-release-authorization.json").read_text(encoding="utf-8"))
        self.source=ROOT/"conformance/idp-a4-public-transparency.json"
        self.proj=ROOT/"conformance/idp-a5-public-projection.json"

    def test_positive_reference(self):
        self.assertEqual([],REF.evaluate(self.pkg,self.source,self.proj))

    def test_positive_independent(self):
        self.assertEqual([],IND.inspect(self.pkg,self.source,self.proj))

    def test_projection_is_byte_exact(self):
        self.assertEqual(self.source.read_bytes(),self.proj.read_bytes())

    def test_threshold_exactly_two(self):
        self.assertEqual(2,self.pkg["reviewPolicy"]["requiredApprovals"])
        self.assertEqual({"reviewer-alpha","reviewer-beta"},set(self.pkg["freeze"]["approvedBy"]))

    def test_structural_freeze_never_authorizes_publication(self):
        self.assertIs(self.pkg["freeze"]["publicationAuthorized"],False)
        self.assertEqual("not-published",self.pkg["freeze"]["publicationDisposition"])

    def test_authority_independence(self):
        auth=self.pkg["authorities"]
        for field in ("principalId","controlDomainId","identityRoot"):
            self.assertEqual(len(auth),len({a[field] for a in auth}))

if __name__=="__main__":
    unittest.main()
