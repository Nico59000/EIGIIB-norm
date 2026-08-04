import json,shutil,tempfile,unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
from eigiib_m0_a12_f4_check import evaluate
from eigiib_m0_a12_f4_replay import verify_case
BUNDLE="96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
class F4Tests(unittest.TestCase):
 def setUp(self):
  self.t=Path(tempfile.mkdtemp())
  for rel in ['conformance/m0-a12-f4-emergency-recovery.json','conformance/m0-a12-f4-emergency-policy.json','conformance/m0-a12-f4-recovery-policy.json','conformance/m0-a12-f4-e17-evidence-matrix.json','conformance/m0-a12-f4-recovery-ledger.json','conformance/m0-a12-f4-htnt-decision-protocol.json','conformance/m0-a12-f3-replay-ledger.json']:
   p=ROOT/rel
   if p.exists(): (self.t/rel).parent.mkdir(parents=True,exist_ok=True); shutil.copy2(p,self.t/rel)
 def tearDown(self): shutil.rmtree(self.t)
 def case(self):
  return {'f3Decision':'verified','lostAuthorities':['a','b'],'approvals':[{'authorityId':f'a{i}','controlDomainId':f'd{i}'} for i in range(5)],'recoveryShares':[{'shareId':f's{i}','failureDomain':f'f{i}'} for i in range(3)],'recoveredArtifactSha256':BUNDLE,'freshChannels':[{'retentionLocked':True,'deletionDenied':True,'restoreExact':True},{'retentionLocked':True,'deletionDenied':True,'restoreExact':True}],'staleAuthorityReplay':'rejected','e17BlockingRows':0}
 def test_baseline(self): self.assertEqual(evaluate(self.t)['htntLabel'],'NF')
 def test_premature_evidence_is_nt(self): (self.t/'evidence/m0-a12-f4').mkdir(parents=True); self.assertEqual(evaluate(self.t)['htntLabel'],'NT')
 def test_source_mutation_is_f(self):
  p=self.t/'conformance/m0-a12-f4-emergency-recovery.json'; d=json.loads(p.read_text()); d['source']['m0A12F3Head']='0'*40; p.write_text(json.dumps(d)); self.assertEqual(evaluate(self.t)['htntLabel'],'F')
 def test_e17_promotion_is_f(self):
  p=self.t/'conformance/m0-a12-f4-e17-evidence-matrix.json'; d=json.loads(p.read_text()); d['matrixDecision']='ready-for-adoption'; p.write_text(json.dumps(d)); self.assertEqual(evaluate(self.t)['htntLabel'],'F')
 def test_complete_synthetic_replay(self): self.assertTrue(verify_case(self.case())['verified'])
 def test_requires_f3_t(self): c=self.case(); c['f3Decision']='not-verified'; self.assertIn('f3-not-T',verify_case(c)['errors'])
 def test_requires_two_losses(self): c=self.case(); c['lostAuthorities']=['a']; self.assertIn('insufficient-loss-declaration',verify_case(c)['errors'])
 def test_requires_five_approvals(self): c=self.case(); c['approvals']=c['approvals'][:4]; self.assertIn('emergency-quorum-not-met',verify_case(c)['errors'])
 def test_requires_independent_approval_domains(self): c=self.case(); [a.update(controlDomainId='same') for a in c['approvals']]; self.assertIn('approval-control-domains-not-independent',verify_case(c)['errors'])
 def test_requires_three_shares(self): c=self.case(); c['recoveryShares']=c['recoveryShares'][:2]; self.assertIn('recovery-threshold-not-met',verify_case(c)['errors'])
 def test_requires_three_failure_domains(self): c=self.case(); [s.update(failureDomain='same') for s in c['recoveryShares']]; self.assertIn('recovery-domains-not-independent',verify_case(c)['errors'])
 def test_digest_mismatch_rejected(self): c=self.case(); c['recoveredArtifactSha256']='0'*64; self.assertIn('recovered-artifact-mismatch',verify_case(c)['errors'])
 def test_channel_lock_required(self): c=self.case(); c['freshChannels'][0]['retentionLocked']=False; self.assertIn('fresh-channel-evidence-incomplete',verify_case(c)['errors'])
 def test_restore_required(self): c=self.case(); c['freshChannels'][1]['restoreExact']=False; self.assertIn('fresh-channel-evidence-incomplete',verify_case(c)['errors'])
 def test_stale_authority_rejected(self): c=self.case(); c['staleAuthorityReplay']='accepted'; self.assertIn('stale-authority-not-rejected',verify_case(c)['errors'])
 def test_matrix_must_close(self): c=self.case(); c['e17BlockingRows']=1; self.assertIn('e17-matrix-incomplete',verify_case(c)['errors'])
if __name__=='__main__': unittest.main()
