from __future__ import annotations
import base64,copy,json,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from eigiib_p1_a9_common import canonical_json,identity
from eigiib_p1_a9_release_check import validate
from eigiib_p1_a9_a8_compat_replay import OLD_WINDOWS_PAIR, NEW_WINDOWS_PAIR, policy_variant, validate_revision
CAP=ROOT/'tests/fixtures/p1-a9/capsule.json';REL=ROOT/'tests/fixtures/p1-a8/expected-release.json';RK=ROOT/'tests/fixtures/p1-a9/release-public-key.pem';TK=ROOT/'tests/fixtures/p1-a9/ts-public-key.pem'
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
 def test_inherited_toolchain_revision_is_additive(self):
  original=json.loads((ROOT/'tests/fixtures/p1-a7/a7.7-toolchain-policy.json').read_text())
  revision=json.loads((ROOT/'tests/fixtures/p1-a9/a7.7-toolchain-policy-revision.json').read_text())
  self.assertEqual(original['standard'],revision['standard'])
  self.assertEqual(original['actions'],revision['actions'])
  self.assertEqual(original['common'],revision['common'])
  self.assertEqual(original['platforms']['ubuntu-24.04'],revision['platforms']['ubuntu-24.04'])
  self.assertEqual(original['platforms']['macos-15'],revision['platforms']['macos-15'])
  changed={k for k in original['platforms']['windows-2025'] if original['platforms']['windows-2025'][k]!=revision['platforms']['windows-2025'][k]}
  self.assertEqual(changed,{'git','imageVersion'})
  self.assertEqual(revision['platforms']['windows-2025']['git'],'git version 2.55.0.windows.3')
  self.assertEqual(revision['platforms']['windows-2025']['imageVersion'],'20260728.188.1')
  allowed={(original['platforms']['windows-2025']['imageVersion'],original['platforms']['windows-2025']['git']),(revision['platforms']['windows-2025']['imageVersion'],revision['platforms']['windows-2025']['git'])}
  self.assertEqual(allowed,{('20260714.173.1','git version 2.55.0.windows.2'),('20260728.188.1','git version 2.55.0.windows.3')})
 def test_a8_offline_policy_selector_is_closed(self):
  original=json.loads((ROOT/'tests/fixtures/p1-a7/a7.7-toolchain-policy.json').read_text())
  revision=json.loads((ROOT/'tests/fixtures/p1-a9/a7.7-toolchain-policy-revision.json').read_text())
  validate_revision(original,revision)
  self.assertEqual(policy_variant('ubuntu-24.04','',''),'original')
  self.assertEqual(policy_variant('windows-2025',*OLD_WINDOWS_PAIR),'original')
  self.assertEqual(policy_variant('windows-2025',*NEW_WINDOWS_PAIR),'revision')
  with self.assertRaises(ValueError):policy_variant('windows-2025','unregistered','git version unknown')
 def test_source_release_mismatch(self):
  with tempfile.TemporaryDirectory() as td:
   bad=Path(td)/'release.json';bad.write_bytes(REL.read_bytes()+b' ')
   d=json.loads(CAP.read_text());d['sourceRelease']['path']=str(bad)
   p=Path(td)/'capsule.json';p.write_bytes(canonical_json(d))
   with self.assertRaises(ValueError):validate(ROOT,p,RK,TK)
if __name__=='__main__':unittest.main()
