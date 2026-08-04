from __future__ import annotations
import base64, hashlib, json, shutil, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    CRYPTO=True
except Exception:
    CRYPTO=False
ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT/"tools"))
from eigiib_m0_a12_f2_canonical import digest_document
from eigiib_m0_a12_f2_check import evaluate
from eigiib_m0_a12_f2_ledger import NAMESPACE

F1_HEAD="eaa64be6c27d30ceba7762ecf1ec7f93fe805745"
CAMPAIGN="eigiib-m0-a11-external-preservation-observation-v1"
BUNDLE="96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"

def dump(path:Path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8",newline="\n")

def copy_surface(dst:Path):
    for rel in [
      ".github/workflows/m0-a12-f2-observation-continuity.yml",
      "conformance/M0-A12-F2-MANUAL-REVIEW.md",
      "conformance/m0-a12-f2-authority-freeze.json",
      "conformance/m0-a12-f2-continuity.json",
      "conformance/m0-a12-f2-accumulation-policy.json",
      "conformance/m0-a12-f2-continuity-ledger.json",
      "conformance/m0-a12-f2-htnt-decision-protocol.json",
      "docs/M0-A12-F2-INDEPENDENT-OBSERVATION-CONTINUITY-LAPSE-DETECTION-AND-LONG-HORIZON-PRESERVATION-ACCUMULATION.md",
      "docs/M0-A12-F2-OPERATOR-RUNBOOK.md",
      "schemas/eigiib-m0-a12-f2-observation.schema.json",
      "schemas/eigiib-m0-a12-f2-lapse-event.schema.json",
      "schemas/eigiib-m0-a12-f2-continuity-certificate.schema.json",
      "tests/fixtures/m0-a12-f2/expected-baseline-report.json",
      "tests/test_eigiib_m0_a12_f2.py",
      "tools/eigiib_m0_a12_f2_canonical.py",
      "tools/eigiib_m0_a12_f2_ledger.py",
      "tools/eigiib_m0_a12_f2_check.py",
    ]:
        src=ROOT/rel; target=dst/rel
        target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,target)
    dump(dst/"conformance/m0-a12-f1-bound-ingress.json",{"standard":"EIGIIB-M0-A12-F1-1.0","naturalSuccessor":{"id":"M0-A12-F2"}})
    dump(dst/"conformance/m0-a12-f1-closure-ledger.json",{"standard":"EIGIIB-M0-A12-F1-CLOSURE-LEDGER-1.0","closureDecision":"not-closed","closureCertificateDigest":None})

def sign(path:Path,key):
    data=path.read_bytes()
    raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    sig=key.sign(b"EIGIIB-M0-A12-SIGNATURE-v1\0"+NAMESPACE.encode()+b"\0"+data)
    env={"standard":"EIGIIB-M0-A12-DETACHED-SIGNATURE-1.0","signedPayloadPath":path.as_posix(),"signedPayloadDigest":hashlib.sha256(data).hexdigest(),"signatureAlgorithm":"ed25519","signatureNamespace":NAMESPACE,"signerIdentity":"independent-observer-primary","signerKeyId":"observer-key-1","publicKeyDigest":hashlib.sha256(raw).hexdigest(),"signatureValue":base64.b64encode(sig).decode(),"allowedSignersPath":"evidence/m0-a12/keys/allowed_signers.json","signedAt":"2026-08-04T00:00:00Z"}
    dump(Path(str(path)+".sig"),env)

def close_f1(root:Path):
    dump(root/"conformance/m0-a12-f1-closure-ledger.json",{"standard":"EIGIIB-M0-A12-F1-CLOSURE-LEDGER-1.0","closureDecision":"point-in-time-activation-closed","closureCertificateDigest":"a"*64})
    dump(root/"evidence/m0-a12-f1/closure-certificate.json",{"certificateDigest":"a"*64})

def make_evidence(root:Path,gap=86400,bad_checkpoint=False):
    key=Ed25519PrivateKey.generate()
    raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    dump(root/"evidence/m0-a12/keys/allowed_signers.json",{"standard":"EIGIIB-M0-A12-ALLOWED-SIGNERS-1.0","signers":[{"identity":"independent-observer-primary","keyId":"observer-key-1","publicKeyRawBase64":base64.b64encode(raw).decode()}]})
    start=datetime(2026,8,1,tzinfo=timezone.utc)
    first={"standard":"EIGIIB-M0-A12-OBSERVATION-1.0","sequence":1,"observedAt":start.isoformat().replace("+00:00","Z"),"observationDigest":"1"*64}
    dump(root/"evidence/m0-a12/observations/000001.json",first)
    prev=first["observationDigest"]; t=start
    for seq in range(2,31):
        t+=timedelta(seconds=gap)
        doc={"standard":"EIGIIB-M0-A12-F2-OBSERVATION-1.0","campaignId":CAMPAIGN,"sequence":seq,"observedAt":t.isoformat().replace("+00:00","Z"),"previousObservationDigest":prev,"observerDomainId":"independent-observer-primary","observerKeyId":"observer-key-1","channels":[
          {"channelId":"immutable-channel-primary","readbackSha256":BUNDLE,"retentionState":"applied-and-readback-verified","result":"exact-and-retained","evidenceRefs":[f"primary-{seq}"]},
          {"channelId":"immutable-channel-secondary","readbackSha256":BUNDLE,"retentionState":"applied-and-readback-verified","result":"exact-and-retained","evidenceRefs":[f"secondary-{seq}"]}]}
        if seq in {7,14,21,28}:
            ok=not(bad_checkpoint and seq==7)
            doc["checkpoint"]={"channels":[
              {"channelId":"immutable-channel-primary","retentionPolicyReadbackVerified":ok,"retentionAttributedDeletionDenialVerified":True,"exactRestoreReadbackVerified":True,"evidenceRefs":[f"pcp-{seq}"]},
              {"channelId":"immutable-channel-secondary","retentionPolicyReadbackVerified":True,"retentionAttributedDeletionDenialVerified":True,"exactRestoreReadbackVerified":True,"evidenceRefs":[f"scp-{seq}"]}]}
        doc["observationDigest"]=digest_document(doc,"observationDigest")
        path=root/f"evidence/m0-a12-f2/observations/{seq:06d}.json"; dump(path,doc); sign(path,key)
        prev=doc["observationDigest"]
    cert={"standard":"EIGIIB-M0-A12-F2-CONTINUITY-CERTIFICATE-1.0","sourceF1Head":F1_HEAD,"campaignId":CAMPAIGN,"firstObservationDigest":first["observationDigest"],"lastObservationDigest":prev,"firstObservedAt":first["observedAt"],"lastObservedAt":t.isoformat().replace("+00:00","Z"),"totalObservationCount":30,"continuationObservationCount":29,"elapsedSeconds":29*gap,"overdueCount":0 if gap<=108000 else 29,"lapseCount":0,"lapseState":"current","decision":"bounded-long-horizon-preservation-accumulation-verified","claimBoundary":"bounded-observed-window-not-future-guarantee"}
    cert["certificateDigest"]=digest_document(cert,"certificateDigest")
    dump(root/"evidence/m0-a12-f2/continuity-certificate.json",cert)
    return t

class Baseline(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); copy_surface(self.root)
    def tearDown(self): self.tmp.cleanup()
    def test_canonical_baseline(self):
        expected=json.loads((ROOT/"tests/fixtures/m0-a12-f2/expected-baseline-report.json").read_text())
        self.assertEqual(evaluate(self.root),expected)
    def test_require_state_is_not_t(self): self.assertEqual(evaluate(self.root)["htntLabel"],"NF")
    def test_premature_evidence_is_nt(self):
        (self.root/"evidence/m0-a12-f2").mkdir(parents=True)
        self.assertEqual(evaluate(self.root)["htntLabel"],"NT")
    def test_freeze_mutation_is_f(self):
        p=self.root/"conformance/m0-a12-f2-continuity.json"; p.write_text(p.read_text()+" ")
        self.assertEqual(evaluate(self.root)["htntLabel"],"F")
    def test_e17_never_promoted(self): self.assertEqual(evaluate(self.root)["summary"]["e17Decision"],"not-ready-for-adoption")

@unittest.skipUnless(CRYPTO,"cryptography unavailable")
class Evidence(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); copy_surface(self.root); close_f1(self.root)
    def tearDown(self): self.tmp.cleanup()
    def test_closed_f1_without_continuity_is_nf(self): self.assertEqual(evaluate(self.root)["continuity_result"],"continuity-evidence-pending")
    def test_complete_window_reaches_t(self):
        last=make_evidence(self.root); self.assertEqual(evaluate(self.root,last+timedelta(hours=12))["htntLabel"],"T")
    def test_missing_sequence_is_nt(self):
        last=make_evidence(self.root); (self.root/"evidence/m0-a12-f2/observations/000010.json").unlink()
        self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_digest_substitution_is_nt(self):
        last=make_evidence(self.root); p=self.root/"evidence/m0-a12-f2/observations/000020.json"; d=json.loads(p.read_text()); d["channels"][0]["result"]="wrong"; dump(p,d)
        self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_signature_substitution_is_nt(self):
        last=make_evidence(self.root); p=self.root/"evidence/m0-a12-f2/observations/000015.json.sig"; d=json.loads(p.read_text()); d["signatureValue"]="AA=="; dump(p,d)
        self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_checkpoint_missing_is_nt(self):
        last=make_evidence(self.root,bad_checkpoint=True); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_channel_missing_is_nt(self):
        last=make_evidence(self.root); p=self.root/"evidence/m0-a12-f2/observations/000012.json"; d=json.loads(p.read_text()); d["channels"]=d["channels"][:1]; d["observationDigest"]=digest_document(d,"observationDigest"); dump(p,d)
        self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_overdue_gap_is_nt(self):
        last=make_evidence(self.root,gap=110000); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_certificate_mutation_is_nt(self):
        last=make_evidence(self.root); p=self.root/"evidence/m0-a12-f2/continuity-certificate.json"; d=json.loads(p.read_text()); d["elapsedSeconds"]-=1; dump(p,d)
        self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_future_overdue_is_nt(self):
        last=make_evidence(self.root); self.assertEqual(evaluate(self.root,last+timedelta(seconds=86400+21601))["htntLabel"],"NT")
    def test_future_lapse_is_nt(self):
        last=make_evidence(self.root); self.assertEqual(evaluate(self.root,last+timedelta(seconds=86400+172800))["htntLabel"],"NT")

if __name__=="__main__": unittest.main()
