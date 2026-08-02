from __future__ import annotations
import copy, json, pathlib, tempfile, unittest
from tools import eigiib_p1_a18_common as c
class P1A18Tests(unittest.TestCase):
 def setUp(self): self.bundle=c.load(c.BUNDLE_PATH); self.valid=c.validate_bundle()
 def test_01_valid(self): self.assertEqual(c.report()['overallResult'],'conformant')
 def test_02_expected_report(self): self.assertEqual(c.canonical_line(c.report()),(c.FIX/'expected-report.json').read_bytes())
 def test_03_source_commit(self): self.assertEqual(self.valid['policy']['artifact']['sourceP1A17Commit'],c.SOURCE_COMMIT)
 def test_04_policy_signature(self): self.assertEqual(self.valid['policy']['policyId'],'eigiib-p1-a18-fixture-production-governance-v1')
 def test_05_request_signature(self): self.assertEqual(self.valid['request']['requesterKeyId'],'requester')
 def test_06_approval_signatures(self): self.assertEqual({x['approverKeyId'] for x in self.valid['approvals']},{'approver-a','approver-b'})
 def test_07_publisher_signature(self): self.assertEqual(self.valid['normalPromotion']['publisherKeyId'],'publisher')
 def test_08_controller_signature(self): self.assertEqual(self.valid['override']['controllerKeyId'],'emergency-controller')
 def test_09_auditor_signature(self): self.assertEqual(self.valid['review']['auditorKeyId'],'auditor')
 def test_10_threshold(self): self.assertEqual(self.valid['policy']['normalPath']['approvalThreshold'],2)
 def test_11_distinct_spki(self): self.assertEqual(len({x['spkiSha256'] for x in self.valid['policy']['roles'].values()}),7)
 def test_12_normal_accepted(self): self.assertEqual(c.portable_result(self.valid)['normalPromotionResult'],'accepted')
 def test_13_emergency_accepted(self): self.assertEqual(c.portable_result(self.valid)['emergencyPromotionResult'],'accepted-and-reviewed')
 def test_14_only_threshold_bypass(self): self.assertEqual(self.valid['override']['bypasses'],['approval-threshold-only'])
 def test_15_review_no_expansion(self): self.assertFalse(self.valid['review']['scopeExpanded'])
 def test_16_platform_sod_unclaimed(self): self.assertEqual(c.DECISIONS['platformEnforcedSeparationOfDuties'],'not-claimed')
 def test_17_live_production_unclaimed(self): self.assertEqual(c.DECISIONS['liveProductionDeployment'],'not-claimed')
 def test_18_environment_rules_unclaimed(self): self.assertEqual(c.DECISIONS['productionEnvironmentProtectionRules'],'not-claimed')
 def test_19_mutations_rejected(self): self.assertEqual(len(c.mutation_replay()),19)
 def test_20_bundle_hash(self): self.assertEqual(c.report()['governanceBundleSha256'],c.sha(c.canonical(self.bundle)))
 def test_21_policy_hash(self): self.assertEqual(c.report()['governancePolicySha256'],c.sha(c.canonical(self.valid['policy'])))
 def test_22_keyset_hash(self): self.assertEqual(c.report()['signingKeySetSha256'],c.key_set_sha(self.valid['policy']))
 def test_23_boundary(self): self.assertEqual(self.bundle['boundary'],c.BOUNDARY)
 def test_24_exact_artifact(self): self.assertEqual(self.valid['normalPromotion']['artifact'],c.expected_artifact())
 def test_25_exact_environment(self): self.assertEqual(self.valid['emergencyPromotion']['environment'],'p1-a18-fixture-production')
 def test_26_duplicate_json_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'x.json'; p.write_text('{"a":1,"a":2}')
   with self.assertRaises(c.ConformanceError): c.load(p)
 def test_27_signature_tamper_rejected(self):
  bad=copy.deepcopy(self.bundle); bad['normal']['request']['signature']['signatureBase64']='AA=='
  with self.assertRaises(c.ConformanceError): c.validate_bundle(bad)
 def test_28_payload_digest_tamper_rejected(self):
  bad=copy.deepcopy(self.bundle); bad['normal']['request']['signature']['payloadSha256']='0'*64
  with self.assertRaises(c.ConformanceError): c.validate_bundle(bad)
 def test_29_extra_top_level_key_rejected(self):
  bad=copy.deepcopy(self.bundle); bad['extra']=1
  with self.assertRaises(c.ConformanceError): c.validate_bundle(bad,do_crypto=False)
 def test_30_canonical_fixture(self):
  self.assertEqual(json.loads((c.FIX/'expected-report.json').read_bytes()),c.report())
if __name__=='__main__': unittest.main()
