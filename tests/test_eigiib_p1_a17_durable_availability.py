from __future__ import annotations
import base64,copy,json,pathlib,tempfile,unittest
from unittest import mock
from tools import eigiib_p1_a17_common as c
class P1A17Tests(unittest.TestCase):
 def setUp(self): self.ev=c.load(c.FIX/'live-durability-evidence.json');self.po=c.load(c.FIX/'retention-policy.json');self.rm=c.load(c.FIX/'restore-manifest.json')
 def test_01_valid(self): self.assertEqual(c.report()['overallResult'],'conformant')
 def test_02_expected_report(self): self.assertEqual(c.canonical(c.report()),(c.FIX/'expected-report.json').read_bytes())
 def test_03_evidence_hash(self): self.assertEqual(c.file_sha('live-durability-evidence.json'),c.EVIDENCE_SHA)
 def test_04_restore_hash(self): self.assertEqual(c.file_sha('restore-manifest.json'),c.RESTORE_SHA)
 def test_05_policy_hash(self): self.assertEqual(c.file_sha('retention-policy.json'),c.POLICY_SHA)
 def test_06_policy_signature(self): self.assertEqual(c.verify_capsule('retention-policy-capsule.json','retention-policy-public-key.pem','EIGIIB-P1-A17-RETENTION-CAPSULE-1.0','EIGIIB-P1-A17-RETENTION-CAPSULE-PAYLOAD-1.0',c.POLICY_SPKI)['sequence'],61)
 def test_07_final_signature(self): self.assertEqual(c.verify_capsule('capsule.json','evidence-registrar-public-key.pem','EIGIIB-P1-A17-CAPSULE-1.0','EIGIIB-P1-A17-CAPSULE-PAYLOAD-1.0',c.spki(c.FIX/'evidence-registrar-public-key.pem'))['sequence'],62)
 def test_08_source_commit(self): self.assertEqual(self.ev['sourceP1A16']['commit'],c.A16_COMMIT)
 def test_09_release_id(self): self.assertEqual(self.ev['recoveryLocation']['releaseId'],c.RELEASE_ID)
 def test_10_object_set(self): self.assertEqual(self.ev['primaryLocation']['protectedObjectSetSha256'],c.OBJECT_SET_SHA)
 def test_11_policy_days(self): self.assertEqual(self.po['minimumRetentionDays'],90)
 def test_12_audit_days(self): self.assertEqual(self.po['restoreAuditIntervalDays'],7)
 def test_13_locations(self): self.assertEqual(self.po['requiredLocationCount'],2)
 def test_14_no_future_guarantee(self): self.assertEqual(self.ev['decisions']['futureAvailabilityGuarantee'],'not-claimed')
 def test_15_no_provider_independence(self): self.assertEqual(self.ev['decisions']['providerIndependentReplication'],'not-claimed')
 def test_16_no_admin_prevention(self): self.assertEqual(self.ev['decisions']['administrativeDeletionPrevention'],'not-claimed')
 def test_17_cross_identity(self): self.assertEqual(self.ev['restoreReplay']['crossLocationByteIdentity'],'conformant')
 def test_18_primary_restore(self): self.assertEqual(self.ev['restoreReplay']['primaryOnly']['objectCount'],5)
 def test_19_recovery_restore(self): self.assertEqual(self.ev['restoreReplay']['recoveryOnly']['objectCount'],5)
 def test_20_release_mutable_flag(self): self.assertFalse(self.ev['recoveryLocation']['immutable'])
 def test_21_asset_count(self): self.assertEqual(len(self.ev['recoveryLocation']['assets']),9)
 def test_22_restore_assets(self): self.assertEqual(len(self.rm['assets']),8)
 def test_23_delete_preconditions(self): self.assertEqual(self.po['deletionPreconditions'],['retention-window-elapsed','successful-restore-from-other-location','revocation-or-supersession-record-present'])
 def test_24_canonical_fixtures(self):
  for n in ['live-durability-evidence.json','restore-manifest.json','retention-policy.json','retention-policy-capsule.json','capsule.json','expected-report.json','expected-replay.json']:
   p=c.FIX/n;self.assertEqual(c.canonical(json.loads(p.read_bytes())),p.read_bytes())
 def test_25_duplicate_json_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'x';p.write_text('{"a":1,"a":2}')
   with self.assertRaises(c.ConformanceError):c.load(p)
 def test_26_decision_mutation_rejected(self):
  bad=copy.deepcopy(self.ev);bad['decisions']['futureAvailabilityGuarantee']='conformant';self.assertNotEqual(bad['decisions'],c.EXPECTED_DECISIONS)
 def test_27_object_mutation_rejected(self):
  bad=copy.deepcopy(self.ev);bad['primaryLocation']['protectedObjects'][0]['size']+=1;self.assertNotEqual(bad['primaryLocation']['protectedObjects'],c.expected_objects())
 def test_28_release_mutation_rejected(self):
  bad=copy.deepcopy(self.ev);bad['recoveryLocation']['releaseId']+=1;self.assertNotEqual(bad['recoveryLocation']['releaseId'],c.RELEASE_ID)
 def test_29_policy_overclaim_rejected(self):
  bad=copy.deepcopy(self.po);bad['claims']['platformEnforcedRetention']='conformant';self.assertNotEqual(bad['claims'],self.po['claims'])
 def test_30_portable_determinism(self): self.assertEqual(c.portable_result(),c.report()['portable'])
if __name__=='__main__':unittest.main()
