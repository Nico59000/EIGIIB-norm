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
from eigiib_m0_a12_f3_canonical import canonical_bytes, digest_document
from eigiib_m0_a12_f3_check import evaluate
from eigiib_m0_a12_f3_replay import OBS_NAMESPACE, MATRIX_NAMESPACE, SUCCESSION_NAMESPACE

F2_HEAD="597ba0931d3510b01136d8ca6c6075ee106a7f19"
CAMPAIGN="eigiib-m0-a11-external-preservation-observation-v1"
BUNDLE="96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
OBSERVERS=["independent-observer-primary","independent-observer-secondary"]
SLUGS={"independent-observer-primary":"observer-primary","independent-observer-secondary":"observer-secondary","external-preservation-primary":"predecessor","external-preservation-primary-successor":"successor","external-preservation-secondary":"anchor-custodian"}

def dump(path:Path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8",newline="\n")

def copy_surface(dst:Path):
    rels=[
      ".github/workflows/m0-a12-f3-multi-observer-succession.yml",
      "conformance/M0-A12-F3-MANUAL-REVIEW.md",
      "conformance/m0-a12-f3-authority-freeze.json",
      "conformance/m0-a12-f3-differential-continuity.json",
      "conformance/m0-a12-f3-observer-registry.json",
      "conformance/m0-a12-f3-differential-policy.json",
      "conformance/m0-a12-f3-succession-policy.json",
      "conformance/m0-a12-f3-replay-ledger.json",
      "conformance/m0-a12-f3-htnt-decision-protocol.json",
      "docs/M0-A12-F3-INDEPENDENT-MULTI-OBSERVER-DIFFERENTIAL-CONTINUITY-AND-CUSTODIAN-SUCCESSION-REPLAY.md",
      "docs/M0-A12-F3-OPERATOR-RUNBOOK.md",
      "schemas/eigiib-m0-a12-f3-differential-observation.schema.json",
      "schemas/eigiib-m0-a12-f3-observer-independence.schema.json",
      "schemas/eigiib-m0-a12-f3-succession-record.schema.json",
      "schemas/eigiib-m0-a12-f3-differential-succession-certificate.schema.json",
      "tests/fixtures/m0-a12-f3/expected-baseline-report.json",
      "tests/test_eigiib_m0_a12_f3.py",
      "tools/eigiib_m0_a12_f3_canonical.py","tools/eigiib_m0_a12_f3_replay.py","tools/eigiib_m0_a12_f3_check.py"]
    for rel in rels:
        src=ROOT/rel; target=dst/rel; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,target)
    dump(dst/"conformance/m0-a12-f2-continuity.json",{"standard":"EIGIIB-M0-A12-F2-1.0","naturalSuccessor":{"id":"M0-A12-F3"}})
    dump(dst/"conformance/m0-a12-f2-continuity-ledger.json",{"standard":"EIGIIB-M0-A12-F2-CONTINUITY-LEDGER-1.0","accumulationDecision":"not-accumulated","continuityCertificateDigest":None})

def close_f2(root:Path,anchor_time:datetime):
    anchor_digest="3"*64
    dump(root/"conformance/m0-a12-f2-continuity-ledger.json",{"standard":"EIGIIB-M0-A12-F2-CONTINUITY-LEDGER-1.0","accumulationDecision":"bounded-long-horizon-preservation-accumulation-verified","continuityCertificateDigest":"4"*64})
    dump(root/"evidence/m0-a12-f2/continuity-certificate.json",{"standard":"EIGIIB-M0-A12-F2-CONTINUITY-CERTIFICATE-1.0","lastObservationDigest":anchor_digest,"lastObservedAt":anchor_time.isoformat().replace("+00:00","Z"),"certificateDigest":"4"*64})
    return anchor_digest

def sign(path:Path,key,identity,key_id,namespace):
    payload=path.read_bytes(); raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    sig=key.sign(b"EIGIIB-M0-A12-SIGNATURE-v1\0"+namespace.encode()+b"\0"+payload)
    env={"standard":"EIGIIB-M0-A12-DETACHED-SIGNATURE-1.0","signedPayloadPath":path.as_posix(),"signedPayloadDigest":hashlib.sha256(payload).hexdigest(),"signatureAlgorithm":"ed25519","signatureNamespace":namespace,"signerIdentity":identity,"signerKeyId":key_id,"publicKeyDigest":hashlib.sha256(raw).hexdigest(),"signatureValue":base64.b64encode(sig).decode(),"allowedSignersPath":"evidence/m0-a12-f3/keys/allowed_signers.json","signedAt":"2026-09-01T00:00:00Z"}
    dump(Path(str(path)+".sig"),env)

def facts(doc):
    channels=[{"channelId":c["channelId"],"custodianDomainId":c["custodianDomainId"],"objectVersionId":c["objectVersionId"],"readbackSha256":c["readbackSha256"],"retentionState":c["retentionState"],"result":c["result"]} for c in doc["channels"]]
    channels.sort(key=lambda x:x["channelId"])
    return {"campaignId":doc["campaignId"],"sequence":doc["sequence"],"custodyEpoch":doc["custodyEpoch"],"channels":channels}

def make_evidence(root:Path, shared_dimension=False, fact_mismatch=False, missing_signer=False, stale_accepted=False, retention_false=False, wrong_cutover=False):
    identities=["independent-observer-primary","independent-observer-secondary","external-preservation-primary","external-preservation-primary-successor","external-preservation-secondary"]
    keys={identity:Ed25519PrivateKey.generate() for identity in identities}
    signers=[]
    for identity,key in keys.items():
        raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        signers.append({"identity":identity,"keyId":f"{SLUGS[identity]}-key-1","publicKeyRawBase64":base64.b64encode(raw).decode()})
    dump(root/"evidence/m0-a12-f3/keys/allowed_signers.json",{"standard":"EIGIIB-M0-A12-ALLOWED-SIGNERS-1.0","signers":signers})
    matrix={"standard":"EIGIIB-M0-A12-F3-OBSERVER-INDEPENDENCE-1.0","observers":OBSERVERS,"dimensions":{d:"distinct" for d in ["provider-operator","tenant-account","identity-root","privileged-administrator","credential-store","execution-plane","audit-log-custody"]},"evidenceRefs":["observer-control-attestation-primary","observer-control-attestation-secondary"]}
    if shared_dimension: matrix["dimensions"]["credential-store"]="shared"
    matrix["matrixDigest"]=digest_document(matrix,"matrixDigest")
    mp=root/"evidence/m0-a12-f3/observer-independence.json"; dump(mp,matrix)
    for observer in OBSERVERS: sign(mp,keys[observer],observer,f"{SLUGS[observer]}-key-1",MATRIX_NAMESPACE); (Path(str(mp)+".sig")).rename(Path(str(mp)+f".{SLUGS[observer]}.sig"))
    anchor_time=datetime(2026,9,1,tzinfo=timezone.utc); anchor=close_f2(root,anchor_time)
    prev={o:anchor for o in OBSERVERS}; last_time=None
    for seq in range(31,38):
        base_time=anchor_time+timedelta(days=seq-30)
        epoch="pre-succession" if seq<34 else "post-succession"
        channel1=("immutable-channel-primary","external-preservation-primary") if seq<34 else ("immutable-channel-primary-successor","external-preservation-primary-successor")
        for idx,observer in enumerate(OBSERVERS):
            observed=base_time+timedelta(minutes=5*idx)
            channels=[{"channelId":channel1[0],"custodianDomainId":channel1[1],"objectVersionId":f"{channel1[0]}-v{seq}","readbackSha256":BUNDLE,"retentionState":"applied-and-readback-verified","result":"exact-and-retained","evidenceRefs":[f"{SLUGS[observer]}-{seq}-primary"]},{"channelId":"immutable-channel-secondary","custodianDomainId":"external-preservation-secondary","objectVersionId":f"secondary-v{seq}","readbackSha256":BUNDLE,"retentionState":"applied-and-readback-verified","result":"exact-and-retained","evidenceRefs":[f"{SLUGS[observer]}-{seq}-secondary"]}]
            if fact_mismatch and seq==35 and observer==OBSERVERS[1]: channels[1]["objectVersionId"]="secondary-v35-divergent"
            doc={"standard":"EIGIIB-M0-A12-F3-DIFFERENTIAL-OBSERVATION-1.0","campaignId":CAMPAIGN,"sequence":seq,"observedAt":observed.isoformat().replace("+00:00","Z"),"previousObservationDigest":prev[observer],"observerDomainId":observer,"observerKeyId":f"{SLUGS[observer]}-key-1","custodyEpoch":epoch,"channels":channels}
            doc["factSetDigest"]=hashlib.sha256(canonical_bytes(facts(doc))).hexdigest(); doc["observationDigest"]=digest_document(doc,"observationDigest")
            path=root/f"evidence/m0-a12-f3/observations/{seq:06d}.{SLUGS[observer]}.json"; dump(path,doc); sign(path,keys[observer],observer,f"{SLUGS[observer]}-key-1",OBS_NAMESPACE)
            prev[observer]=doc["observationDigest"]; last_time=observed
    cutover=35 if wrong_cutover else 34
    effective=anchor_time+timedelta(days=3,hours=12)
    record={"standard":"EIGIIB-M0-A12-F3-SUCCESSION-RECORD-1.0","sourceF2Head":F2_HEAD,"campaignId":CAMPAIGN,"cutoverSequence":cutover,"effectiveAt":effective.isoformat().replace("+00:00","Z"),"predecessorDomainId":"external-preservation-primary","successorDomainId":"external-preservation-primary-successor","anchorCustodianDomainId":"external-preservation-secondary","successorChannelId":"immutable-channel-primary-successor","stableBundleSha256":BUNDLE,"successorRetentionState":"not-verified" if retention_false else "applied-and-readback-verified","successorDeletionDenialVerified":True,"successorRestoreReadbackVerified":True,"successorCustodyAccepted":True,"predecessorDisposition":"quarantined-nonauthoritative","staleAuthorityReplayDecision":"accepted" if stale_accepted else "rejected","evidenceRefs":["successor-custody-acceptance","successor-retention-readback","successor-delete-denial","successor-restore-readback","predecessor-quarantine"]}
    record["recordDigest"]=digest_document(record,"recordDigest"); rp=root/"evidence/m0-a12-f3/succession/succession-record.json"; dump(rp,record)
    required=identities if not missing_signer else identities[:-1]
    for identity in required:
        sign(rp,keys[identity],identity,f"{SLUGS[identity]}-key-1",SUCCESSION_NAMESPACE); Path(str(rp)+".sig").rename(Path(str(rp)+f".{SLUGS[identity]}.sig"))
    return last_time

def make_certificate(root:Path,as_of:datetime):
    from eigiib_m0_a12_f3_replay import evaluate_replay
    policy=json.loads((root/"conformance/m0-a12-f3-differential-policy.json").read_text())
    replay=evaluate_replay(root,policy,as_of)
    cert={"standard":"EIGIIB-M0-A12-F3-DIFFERENTIAL-SUCCESSION-CERTIFICATE-1.0","sourceF2Head":F2_HEAD,**replay,"decision":"independent-multi-observer-differential-continuity-and-custodian-succession-replay-verified","claimBoundary":"bounded-differential-window-and-single-succession-only"}
    cert["certificateDigest"]=digest_document(cert,"certificateDigest"); dump(root/"evidence/m0-a12-f3/differential-succession-certificate.json",cert)

class Baseline(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); copy_surface(self.root)
    def tearDown(self): self.tmp.cleanup()
    def test_canonical_baseline(self): self.assertEqual(evaluate(self.root),json.loads((ROOT/"tests/fixtures/m0-a12-f3/expected-baseline-report.json").read_text()))
    def test_prerequisite_is_not_t(self): self.assertEqual(evaluate(self.root)["htntLabel"],"NF")
    def test_premature_evidence_is_nt(self): (self.root/"evidence/m0-a12-f3").mkdir(parents=True); self.assertEqual(evaluate(self.root)["htntLabel"],"NT")
    def test_freeze_mutation_is_f(self): p=self.root/"conformance/m0-a12-f3-differential-continuity.json"; p.write_text(p.read_text()+" "); self.assertEqual(evaluate(self.root)["htntLabel"],"F")
    def test_e17_never_promoted(self): self.assertEqual(evaluate(self.root)["summary"]["e17Decision"],"not-ready-for-adoption")

@unittest.skipUnless(CRYPTO,"cryptography unavailable")
class Evidence(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name); copy_surface(self.root)
    def tearDown(self): self.tmp.cleanup()
    def test_closed_f2_without_f3_evidence_is_nf(self): close_f2(self.root,datetime(2026,9,1,tzinfo=timezone.utc)); self.assertEqual(evaluate(self.root)["replay_result"],"differential-and-succession-evidence-pending")
    def test_complete_replay_reaches_t(self): last=make_evidence(self.root); make_certificate(self.root,last+timedelta(hours=12)); self.assertEqual(evaluate(self.root,last+timedelta(hours=12))["htntLabel"],"T")
    def test_missing_paired_observation_is_nt(self): last=make_evidence(self.root); (self.root/"evidence/m0-a12-f3/observations/000035.observer-secondary.json").unlink(); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_differential_fact_mismatch_is_nt(self): last=make_evidence(self.root,fact_mismatch=True); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_signature_substitution_is_nt(self): last=make_evidence(self.root); p=self.root/"evidence/m0-a12-f3/observations/000036.observer-primary.json.sig"; d=json.loads(p.read_text()); d["signatureValue"]="AA=="; dump(p,d); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_shared_observer_control_dimension_is_nt(self): last=make_evidence(self.root,shared_dimension=True); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_missing_succession_signer_is_nt(self): last=make_evidence(self.root,missing_signer=True); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_stale_predecessor_authority_is_nt(self): last=make_evidence(self.root,stale_accepted=True); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_successor_retention_not_verified_is_nt(self): last=make_evidence(self.root,retention_false=True); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_wrong_cutover_sequence_is_nt(self): last=make_evidence(self.root,wrong_cutover=True); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_certificate_mutation_is_nt(self): last=make_evidence(self.root); make_certificate(self.root,last); p=self.root/"evidence/m0-a12-f3/differential-succession-certificate.json"; d=json.loads(p.read_text()); d["pairedRoundCount"]=6; dump(p,d); self.assertEqual(evaluate(self.root,last)["htntLabel"],"NT")
    def test_future_lapse_is_nt(self): last=make_evidence(self.root); make_certificate(self.root,last); self.assertEqual(evaluate(self.root,last+timedelta(seconds=86400+172800))["htntLabel"],"NT")

if __name__=="__main__": unittest.main()
