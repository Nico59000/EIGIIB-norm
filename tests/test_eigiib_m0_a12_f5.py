import json,shutil,tempfile,unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
from eigiib_m0_a12_f5_check import evaluate
from eigiib_m0_a12_f5_replay import verify_case
class F5Tests(unittest.TestCase):
 def setUp(self):
  self.t=Path(tempfile.mkdtemp())
  for rel in ['conformance/m0-a12-f5-adoption-authority.json','conformance/m0-a12-f5-adoption-policy.json','conformance/m0-a12-f5-governance-convergence.json','conformance/m0-a12-f5-e17-adoption-matrix.json','conformance/m0-a12-f5-final-freeze.json','conformance/m0-a12-f5-ledger.json','conformance/m0-a12-f5-htnt-decision-protocol.json','conformance/m0-a12-f4-recovery-ledger.json']:
   p=ROOT/rel; (self.t/rel).parent.mkdir(parents=True,exist_ok=True); shutil.copy2(p,self.t/rel)
 def tearDown(self): shutil.rmtree(self.t)
 def case(self):
  caps=[f'c{i}' for i in range(12)]; approvals=[{'collegeId':f'g{i}','approvers':[f'a{i}{j}' for j in range(4)],'controlDomains':[f'd{i}{j}' for j in range(4)],'recordDigest':'r'} for i in range(3)]
  return {'f4Decision':'verified','capabilityEvidenceDigests':caps,'boundedClaims':['universal-interoperability','future-unregistered-runner-compatibility'],'collegeApprovals':approvals,'identicalRecordDigest':True,'freshEvidence':True,'adoptionCertificateValid':True,'freezeManifestValid':True,'independentFreezeReadbackValid':True}
 def test_baseline(self): self.assertEqual(evaluate(self.t)['htntLabel'],'NF')
 def test_premature_evidence_is_nt(self): (self.t/'evidence/m0-a12-f5').mkdir(parents=True); self.assertEqual(evaluate(self.t)['htntLabel'],'NT')
 def test_source_mutation_is_f(self):
  p=self.t/'conformance/m0-a12-f5-adoption-authority.json'; d=json.loads(p.read_text()); d['source']['m0A12F4Head']='0'*40; p.write_text(json.dumps(d)); self.assertEqual(evaluate(self.t)['htntLabel'],'F')
 def test_premature_matrix_adoption_is_f(self):
  p=self.t/'conformance/m0-a12-f5-e17-adoption-matrix.json'; d=json.loads(p.read_text()); d['matrixDecision']='adopted'; p.write_text(json.dumps(d)); self.assertEqual(evaluate(self.t)['htntLabel'],'F')
 def test_complete_synthetic_adoption(self): self.assertTrue(verify_case(self.case())['verified'])
 def test_requires_f4_t(self): c=self.case(); c['f4Decision']='not-verified'; self.assertIn('f4-not-T',verify_case(c)['errors'])
 def test_requires_twelve_rows(self): c=self.case(); c['capabilityEvidenceDigests']=c['capabilityEvidenceDigests'][:11]; self.assertIn('adoptable-evidence-incomplete',verify_case(c)['errors'])
 def test_requires_bounded_claims(self): c=self.case(); c['boundedClaims']=[]; self.assertIn('bounded-claims-missing',verify_case(c)['errors'])
 def test_requires_three_colleges(self): c=self.case(); c['collegeApprovals']=c['collegeApprovals'][:2]; self.assertIn('college-convergence-incomplete',verify_case(c)['errors'])
 def test_requires_four_approvers(self): c=self.case(); c['collegeApprovals'][0]['approvers']=c['collegeApprovals'][0]['approvers'][:3]; self.assertIn('college-threshold-not-met',verify_case(c)['errors'])
 def test_requires_four_domains(self): c=self.case(); c['collegeApprovals'][1]['controlDomains']=['same']*4; self.assertIn('college-control-domains-not-independent',verify_case(c)['errors'])
 def test_requires_identical_record(self): c=self.case(); c['identicalRecordDigest']=False; self.assertIn('college-record-divergence',verify_case(c)['errors'])
 def test_requires_fresh_evidence(self): c=self.case(); c['freshEvidence']=False; self.assertIn('stale-external-evidence',verify_case(c)['errors'])
 def test_requires_adoption_certificate(self): c=self.case(); c['adoptionCertificateValid']=False; self.assertIn('adoption-certificate-invalid',verify_case(c)['errors'])
 def test_requires_freeze_manifest(self): c=self.case(); c['freezeManifestValid']=False; self.assertIn('freeze-manifest-invalid',verify_case(c)['errors'])
 def test_requires_independent_readback(self): c=self.case(); c['independentFreezeReadbackValid']=False; self.assertIn('freeze-readback-invalid',verify_case(c)['errors'])
if __name__=='__main__': unittest.main()
