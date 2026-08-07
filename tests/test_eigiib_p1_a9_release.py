from __future__ import annotations
import base64,copy,json,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from eigiib_p1_a9_common import canonical_json,identity
from eigiib_p1_a9_release_check import validate
from eigiib_p1_a9_f1_runner_succession import select_policy,validate_registry
CAP=ROOT/'tests/fixtures/p1-a9/capsule.json';REL=ROOT/'tests/fixtures/p1-a8/expected-release.json';RK=ROOT/'tests/fixtures/p1-a9/release-public-key.pem';TK=ROOT/'tests/fixtures/p1-a9/ts-public-key.pem';REGISTRY=ROOT/'tests/fixtures/p1-a9/a7.7-toolchain-policy-succession.json'
class P1A9Tests(unittest.TestCase):
 def test_positive(self): self.assertEqual(validate(ROOT,CAP,RK,TK)['overall_result'],'conformant')
 def mutate(self,fn):
  d=json.loads(CAP.read_text());fn(d)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'capsule.json';p.write_bytes(canonical_json(d))
   with self.assertRaises(ValueError):validate(ROOT,p,RK,TK)
 def test_registration_location(self): self.mutate(lambda d:d['transparency']['entries'][0]['registration'].__setitem__('location','https://example.invalid/entry'))
 def test_supersession_sequence(self):
  def f(d):
   raw=base64.b64decode(d['supersession']['payload']['data']);obj=json.loads(raw);obj['successor']['sequence']=2;new=canonical_json(obj);d['supersession']['payload']={'data':base64.b64encode(new).decode(),'identity':identity(new)}
  self.mutate(f)
 def test_release_envelope_signature(self):
  def f(d):
   raw=bytearray(base64.b64decode(d['releaseEnvelope']['data']));raw[-8]^=1;raw=bytes(raw);d['releaseEnvelope']['data']=base64.b64encode(raw).decode();d['releaseEnvelope']['identity']=identity(raw)
  self.mutate(f)
 def test_receipt_signature(self):
  def f(d):
   raw=bytearray(base64.b64decode(d['transparency']['entries'][1]['receipt']['data']));raw[-1]^=1;raw=bytes(raw);e=d['transparency']['entries'][1];e['receipt']['data']=base64.b64encode(raw).decode();e['receipt']['identity']=identity(raw)
  self.mutate(f)
 def test_inherited_toolchain_succession_is_append_only_and_bounded(self):
  validated=validate_registry(ROOT,REGISTRY);generations=validated['registry']['generations'];policies=[json.loads(path.read_text()) for _,path in validated['policies']]
  self.assertEqual([g['generation'] for g in generations],list(range(len(generations))))
  self.assertEqual([g['predecessor'] for g in generations],[None]+[g['id'] for g in generations[:-1]])
  self.assertEqual(generations[0]['changedFromPredecessor'],[])
  for previous,current,generation in zip(policies,policies[1:],generations[1:]):
   self.assertEqual(previous['standard'],current['standard']);self.assertEqual(previous['actions'],current['actions']);self.assertEqual(previous['common'],current['common'])
   self.assertEqual(previous['platforms']['ubuntu-24.04'],current['platforms']['ubuntu-24.04']);self.assertEqual(previous['platforms']['macos-15'],current['platforms']['macos-15'])
   changed={k for k in previous['platforms']['windows-2025'] if previous['platforms']['windows-2025'][k]!=current['platforms']['windows-2025'][k]}
   self.assertEqual(changed,set(generation['changedFromPredecessor']))
  self.assertEqual(generations[-1]['imageVersion'],'20260803.193.1');self.assertEqual(generations[-1]['git'],'git version 2.55.0.windows.3')
 def test_a8_offline_policy_selector_is_closed_over_registered_generations(self):
  validated=validate_registry(ROOT,REGISTRY)
  for entry,path in validated['policies']:
   self.assertEqual(select_policy(ROOT,REGISTRY,'windows-2025',entry['imageVersion'],entry['git']),path)
  self.assertEqual(select_policy(ROOT,REGISTRY,'ubuntu-24.04','',''),(ROOT/'tests/fixtures/p1-a7/a7.7-toolchain-policy.json').resolve())
  with self.assertRaises(ValueError):select_policy(ROOT,REGISTRY,'windows-2025','unregistered','git version unknown')
 def test_source_release_mismatch(self):
  with tempfile.TemporaryDirectory() as td:
   bad=Path(td)/'release.json';bad.write_bytes(REL.read_bytes()+b' ')
   d=json.loads(CAP.read_text());d['sourceRelease']['path']=str(bad)
   p=Path(td)/'capsule.json';p.write_bytes(canonical_json(d))
   with self.assertRaises(ValueError):validate(ROOT,p,RK,TK)
if __name__=='__main__':unittest.main()
