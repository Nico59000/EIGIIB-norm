from __future__ import annotations
import importlib.util, json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(rel,name):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
REF=load('tools/eigiib_idp_check.py','idp_ref_test'); IND=load('tools/eigiib_idp_independent.py','idp_ind_test')
class IDPA1Tests(unittest.TestCase):
    def test_normative_registry(self):
        data=json.loads((ROOT/'conformance/idp-policy.json').read_text())
        self.assertEqual([],REF.validate(data)); self.assertEqual([],IND.validate(data))
    def test_matrix_cases(self):
        matrix=json.loads((ROOT/'conformance/idp-a1-verifier-matrix.json').read_text())
        for case in matrix['cases']:
            with self.subTest(case=case['id']):
                data=json.loads((ROOT/case['path']).read_text()); exp=sorted(case['expectedFindings'])
                self.assertEqual(exp,REF.validate(data)); self.assertEqual(exp,IND.validate(data))
    def test_public_classes_share_visibility_rank(self):
        data=json.loads((ROOT/'conformance/idp-policy.json').read_text())
        rank={c['id']:c['restrictionRank'] for c in data['classes']}
        self.assertEqual({0},{rank[x] for x in ('D0','D1','D2')})
if __name__=='__main__': unittest.main()
