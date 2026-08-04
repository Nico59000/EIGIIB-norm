#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from eigiib_m0_a12_f2_canonical import digest_document, load_json, parse_time

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    InvalidSignature = Exception
    Ed25519PublicKey = None

NAMESPACE="eigiib-m0-a12-f2-continuity@eigiib.example"
SIGNATURE_STANDARD="EIGIIB-M0-A12-DETACHED-SIGNATURE-1.0"
ALLOWED_SIGNERS_STANDARD="EIGIIB-M0-A12-ALLOWED-SIGNERS-1.0"

class ContinuityError(RuntimeError):
    pass

def _message(payload: bytes) -> bytes:
    return b"EIGIIB-M0-A12-SIGNATURE-v1\0"+NAMESPACE.encode("utf-8")+b"\0"+payload

def verify_signature(payload:Path,signature:Path,allowed_signers:Path,identity:str)->None:
    if Ed25519PublicKey is None:
        raise ContinuityError("cryptography dependency unavailable")
    envelope=load_json(signature)
    if envelope.get("standard")!=SIGNATURE_STANDARD or envelope.get("signatureAlgorithm")!="ed25519":
        raise ContinuityError("invalid signature envelope")
    if envelope.get("signatureNamespace")!=NAMESPACE or envelope.get("signerIdentity")!=identity:
        raise ContinuityError("signature identity or namespace mismatch")
    data=payload.read_bytes()
    if envelope.get("signedPayloadDigest")!=hashlib.sha256(data).hexdigest():
        raise ContinuityError("signed payload digest mismatch")
    allowed=load_json(allowed_signers)
    if allowed.get("standard")!=ALLOWED_SIGNERS_STANDARD:
        raise ContinuityError("invalid allowed signers authority")
    signer=next((x for x in allowed.get("signers",[]) if x.get("identity")==identity),None)
    if not signer or signer.get("keyId")!=envelope.get("signerKeyId"):
        raise ContinuityError("signer not authorized")
    try:
        public_raw=base64.b64decode(signer["publicKeyRawBase64"],validate=True)
        signature_raw=base64.b64decode(envelope["signatureValue"],validate=True)
    except Exception as exc:
        raise ContinuityError("invalid signature encoding") from exc
    if hashlib.sha256(public_raw).hexdigest()!=envelope.get("publicKeyDigest"):
        raise ContinuityError("public key digest mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw,_message(data))
    except (ValueError,InvalidSignature) as exc:
        raise ContinuityError("signature verification failed") from exc

def lapse_state(last_observed_at:datetime,as_of:datetime,cadence:int,grace:int,lapse_after:int)->str:
    due=last_observed_at+timedelta(seconds=cadence)
    if as_of<=due: return "current"
    if as_of<=due+timedelta(seconds=grace): return "grace"
    if as_of<due+timedelta(seconds=lapse_after): return "overdue"
    return "lapsed"

def observation_files(root:Path)->list[Path]:
    path=root/"evidence/m0-a12-f2/observations"
    return sorted(path.glob("*.json")) if path.is_dir() else []

def evaluate_chain(root:Path,policy:dict[str,Any],as_of:datetime)->dict[str,Any]:
    allowed=root/"evidence/m0-a12/keys/allowed_signers.json"
    first=load_json(root/"evidence/m0-a12/observations/000001.json")
    previous_digest=first.get("observationDigest")
    previous_time=parse_time(first.get("observedAt"))
    if not previous_digest:
        raise ContinuityError("missing sequence-1 digest")
    schedule=policy["schedule"]; threshold=policy["threshold"]
    checkpoints=set(policy["checkpointPolicy"]["sequences"])
    files=observation_files(root)
    expected=list(range(2,threshold["lastSequence"]+1))
    actual=[]; overdue=0; last_digest=previous_digest; last_time=previous_time
    last_observed_text=first["observedAt"]
    for path in files:
        doc=load_json(path); seq=doc.get("sequence"); actual.append(seq)
        if doc.get("standard")!="EIGIIB-M0-A12-F2-OBSERVATION-1.0":
            raise ContinuityError("invalid observation standard")
        if doc.get("campaignId")!=policy["campaignId"] or doc.get("observerDomainId")!="independent-observer-primary":
            raise ContinuityError("campaign or observer mismatch")
        if doc.get("previousObservationDigest")!=last_digest:
            raise ContinuityError("observation chain mismatch")
        observed_at=parse_time(doc.get("observedAt"))
        delta=(observed_at-last_time).total_seconds()
        if delta<=0: raise ContinuityError("observation time not increasing")
        if delta>schedule["cadenceSeconds"]+schedule["graceSeconds"]: overdue+=1
        if delta>=schedule["cadenceSeconds"]+schedule["lapseAfterSeconds"]:
            raise ContinuityError("recorded lapse in chain")
        channels=doc.get("channels",[])
        if [x.get("channelId") for x in channels]!=policy["channelPolicy"]["requiredChannels"]:
            raise ContinuityError("channel set mismatch")
        for item in channels:
            if (item.get("readbackSha256")!=policy["channelPolicy"]["requiredArtifactSha256"]
                or item.get("retentionState")!=policy["channelPolicy"]["requiredRetentionState"]
                or item.get("result")!=policy["channelPolicy"]["requiredResult"]
                or not item.get("evidenceRefs")):
                raise ContinuityError("invalid channel continuity claim")
        if seq in checkpoints:
            cp=doc.get("checkpoint",{}).get("channels",[])
            if [x.get("channelId") for x in cp]!=policy["channelPolicy"]["requiredChannels"]:
                raise ContinuityError("checkpoint channel set mismatch")
            for item in cp:
                if (item.get("retentionPolicyReadbackVerified") is not True
                    or item.get("retentionAttributedDeletionDenialVerified") is not True
                    or item.get("exactRestoreReadbackVerified") is not True
                    or not item.get("evidenceRefs")):
                    raise ContinuityError("checkpoint incomplete")
        if doc.get("observationDigest")!=digest_document(doc,"observationDigest"):
            raise ContinuityError("observation digest mismatch")
        verify_signature(path,Path(str(path)+".sig"),allowed,"independent-observer-primary")
        last_digest=doc["observationDigest"]; last_time=observed_at; last_observed_text=doc["observedAt"]
    if actual!=expected:
        raise ContinuityError("observation sequence set mismatch")
    state=lapse_state(last_time,as_of,schedule["cadenceSeconds"],schedule["graceSeconds"],schedule["lapseAfterSeconds"])
    return {"firstObservationDigest":previous_digest,"lastObservationDigest":last_digest,
      "firstObservedAt":first["observedAt"],"lastObservedAt":last_observed_text,
      "totalObservationCount":1+len(files),"continuationObservationCount":len(files),
      "elapsedSeconds":int((last_time-previous_time).total_seconds()),"overdueCount":overdue,
      "lapseCount":1 if state=="lapsed" else 0,"lapseState":state}
