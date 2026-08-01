from __future__ import annotations
import base64, copy, hashlib, json, tempfile, unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from eigiib_p1_a13_common import identity
from eigiib_p1_a13_revocation_check import evaluate

CAPSULE=ROOT/"tests/fixtures/p1-a13/capsule.json"

def write_capsule(value: dict) -> Path:
    tmp=tempfile.NamedTemporaryFile("w",encoding="utf-8",suffix=".json",delete=False)
    json.dump(value,tmp,sort_keys=True,separators=(",",":"),ensure_ascii=False); tmp.write("\n"); tmp.close()
    return Path(tmp.name)

def mutate_carrier(carrier: dict) -> None:
    raw=bytearray(base64.b64decode(carrier["data"])); raw[-1]^=1; changed=bytes(raw)
    carrier["data"]=base64.b64encode(changed).decode("ascii"); carrier["identity"]=identity(changed)

class P1A13Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.base=json.loads(CAPSULE.read_text(encoding="utf-8"))
    def check_rejected(self, mutate):
        value=copy.deepcopy(self.base); mutate(value); path=write_capsule(value)
        try:
            with self.assertRaises((ValueError,KeyError,TypeError)): evaluate(ROOT,path)
        finally: path.unlink(missing_ok=True)
    def test_positive(self): self.assertEqual(evaluate(ROOT,CAPSULE)["overall_result"],"conformant")
    def test_source_identity_mutation(self): self.check_rejected(lambda v:v["sourceAuthority"].__setitem__("transparencyReportSha256","0"*64))
    def test_release_descriptor_mutation(self): self.check_rejected(lambda v:v["sourceAuthority"].__setitem__("releaseDescriptorSha256","1"*64))
    def test_policy_signature_mutation(self): self.check_rejected(lambda v:mutate_carrier(v["policy"]["envelope"]))
    def test_revocation_payload_mutation(self): self.check_rejected(lambda v:mutate_carrier(v["revocation"]["payload"]))
    def test_revocation_signature_mutation(self): self.check_rejected(lambda v:mutate_carrier(v["revocation"]["envelope"]))
    def test_withdrawal_channel_mutation(self):
        def m(v):
            raw=json.loads(base64.b64decode(v["withdrawals"][0]["payload"]["data"])); raw["channel"]["channelId"]="fixture-mirror"; data=(json.dumps(raw,sort_keys=True,separators=(",",":"))+"\n").encode(); v["withdrawals"][0]["payload"]={"data":base64.b64encode(data).decode(),"identity":identity(data)}
        self.check_rejected(m)
    def test_withdrawal_signature_mutation(self): self.check_rejected(lambda v:mutate_carrier(v["withdrawals"][1]["envelope"]))
    def test_replay_decision_mutation(self): self.check_rejected(lambda v:v["replays"][0].__setitem__("expectedDecision","conformant"))
    def test_replay_sequence_mutation(self): self.check_rejected(lambda v:mutate_carrier(v["replays"][2]["observation"]["payload"]))
    def test_claim_boundary_mutation(self): self.check_rejected(lambda v:v["claimBoundary"].pop())
    def test_channel_key_substitution(self): self.check_rejected(lambda v:v["channels"][0].__setitem__("spki",v["channels"][1]["spki"]))
if __name__=="__main__": unittest.main()
