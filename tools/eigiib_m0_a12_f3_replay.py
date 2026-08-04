#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from eigiib_m0_a12_f3_canonical import canonical_bytes, digest_document, load_json, parse_time

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    InvalidSignature = Exception
    Ed25519PublicKey = None

OBS_NAMESPACE="eigiib-m0-a12-f3-differential-observation@eigiib.example"
MATRIX_NAMESPACE="eigiib-m0-a12-f3-observer-independence@eigiib.example"
SUCCESSION_NAMESPACE="eigiib-m0-a12-f3-custodian-succession@eigiib.example"
SIGNATURE_STANDARD="EIGIIB-M0-A12-DETACHED-SIGNATURE-1.0"
ALLOWED_SIGNERS_STANDARD="EIGIIB-M0-A12-ALLOWED-SIGNERS-1.0"

class ReplayError(RuntimeError):
    pass

def _message(namespace: str, payload: bytes) -> bytes:
    return b"EIGIIB-M0-A12-SIGNATURE-v1\0" + namespace.encode("utf-8") + b"\0" + payload

def _load_signers(root: Path) -> dict[tuple[str,str], tuple[bytes,str]]:
    path=root/"evidence/m0-a12-f3/keys/allowed_signers.json"
    document=load_json(path)
    if document.get("standard") != ALLOWED_SIGNERS_STANDARD:
        raise ReplayError("allowed signer registry standard mismatch")
    result={}
    for item in document.get("signers",[]):
        identity=item.get("identity"); key_id=item.get("keyId")
        try: raw=base64.b64decode(item.get("publicKeyRawBase64",""),validate=True)
        except Exception as exc: raise ReplayError("invalid public key encoding") from exc
        if len(raw)!=32 or not identity or not key_id or (identity,key_id) in result:
            raise ReplayError("invalid or duplicate signer")
        result[(identity,key_id)]=(raw,hashlib.sha256(raw).hexdigest())
    return result

def verify_signature(payload_path: Path, signature_path: Path, signers: dict, namespace: str, expected_identity: str) -> None:
    if Ed25519PublicKey is None:
        raise ReplayError("cryptography dependency unavailable")
    envelope=load_json(signature_path); payload=payload_path.read_bytes()
    if envelope.get("standard")!=SIGNATURE_STANDARD: raise ReplayError("signature standard mismatch")
    if envelope.get("signedPayloadDigest")!=hashlib.sha256(payload).hexdigest(): raise ReplayError("signed payload digest mismatch")
    if envelope.get("signatureAlgorithm")!="ed25519" or envelope.get("signatureNamespace")!=namespace: raise ReplayError("signature context mismatch")
    identity=envelope.get("signerIdentity"); key_id=envelope.get("signerKeyId")
    if identity!=expected_identity: raise ReplayError("unexpected signer identity")
    key=signers.get((identity,key_id))
    if key is None: raise ReplayError("unregistered signer key")
    raw,key_digest=key
    if envelope.get("publicKeyDigest")!=key_digest: raise ReplayError("public key digest mismatch")
    try: signature=base64.b64decode(envelope.get("signatureValue",""),validate=True)
    except Exception as exc: raise ReplayError("invalid signature encoding") from exc
    try: Ed25519PublicKey.from_public_bytes(raw).verify(signature,_message(namespace,payload))
    except InvalidSignature as exc: raise ReplayError("invalid detached signature") from exc

def _fact_payload(document: dict[str,Any]) -> dict[str,Any]:
    channels=[]
    for channel in document.get("channels",[]):
        channels.append({
          "channelId":channel.get("channelId"),
          "custodianDomainId":channel.get("custodianDomainId"),
          "objectVersionId":channel.get("objectVersionId"),
          "readbackSha256":channel.get("readbackSha256"),
          "retentionState":channel.get("retentionState"),
          "result":channel.get("result"),
        })
    channels.sort(key=lambda x:x["channelId"] or "")
    return {"campaignId":document.get("campaignId"),"sequence":document.get("sequence"),"custodyEpoch":document.get("custodyEpoch"),"channels":channels}

def _verify_channel_set(document: dict[str,Any], policy: dict[str,Any], sequence: int) -> None:
    cutover=policy["succession"]["cutoverSequence"]
    epoch="pre-succession" if sequence<cutover else "post-succession"
    if document.get("custodyEpoch")!=epoch: raise ReplayError("custody epoch mismatch")
    expected=policy["channelEpochs"][epoch]
    channels=document.get("channels")
    if not isinstance(channels,list) or len(channels)!=2: raise ReplayError("channel cardinality mismatch")
    by_id={c.get("channelId"):c for c in channels}
    if set(by_id)!=set(expected): raise ReplayError("channel set mismatch")
    for channel_id,custodian in expected.items():
        channel=by_id[channel_id]
        if channel.get("custodianDomainId")!=custodian: raise ReplayError("custodian binding mismatch")
        if channel.get("readbackSha256")!=policy["stableBundleSha256"]: raise ReplayError("stable bundle digest mismatch")
        if channel.get("retentionState")!="applied-and-readback-verified" or channel.get("result")!="exact-and-retained": raise ReplayError("channel preservation state mismatch")
        if not channel.get("objectVersionId") or not channel.get("evidenceRefs"): raise ReplayError("channel evidence incomplete")

def _verify_independence(root:Path,signers:dict,policy:dict)->str:
    path=root/"evidence/m0-a12-f3/observer-independence.json"
    document=load_json(path)
    if document.get("standard")!="EIGIIB-M0-A12-F3-OBSERVER-INDEPENDENCE-1.0": raise ReplayError("observer independence standard mismatch")
    if document.get("observers")!=policy["observers"]: raise ReplayError("observer identity set mismatch")
    dimensions=document.get("dimensions",{})
    if set(dimensions)!=set(policy["observerIndependenceDimensions"]): raise ReplayError("observer independence dimension set mismatch")
    if any(dimensions.get(d)!="distinct" for d in policy["observerIndependenceDimensions"]): raise ReplayError("observer control domains are not independent")
    if not document.get("evidenceRefs"): raise ReplayError("observer independence evidence absent")
    if document.get("matrixDigest")!=digest_document(document,"matrixDigest"): raise ReplayError("observer independence digest mismatch")
    for observer in policy["observers"]:
        slug=policy["observerSlugs"][observer]
        verify_signature(path,Path(str(path)+f".{slug}.sig"),signers,MATRIX_NAMESPACE,observer)
    return document["matrixDigest"]

def _verify_succession(root:Path,signers:dict,policy:dict,seq33_latest:datetime,seq34_earliest:datetime)->tuple[str,datetime]:
    path=root/"evidence/m0-a12-f3/succession/succession-record.json"
    document=load_json(path); succession=policy["succession"]
    checks={
      "standard":"EIGIIB-M0-A12-F3-SUCCESSION-RECORD-1.0",
      "sourceF2Head":policy["sourceF2Head"],
      "campaignId":policy["campaignId"],
      "cutoverSequence":succession["cutoverSequence"],
      "predecessorDomainId":succession["predecessorDomainId"],
      "successorDomainId":succession["successorDomainId"],
      "anchorCustodianDomainId":succession["anchorCustodianDomainId"],
      "successorChannelId":succession["successorChannelId"],
      "stableBundleSha256":policy["stableBundleSha256"],
      "successorRetentionState":"applied-and-readback-verified",
      "predecessorDisposition":"quarantined-nonauthoritative",
      "staleAuthorityReplayDecision":"rejected",
    }
    for key,value in checks.items():
        if document.get(key)!=value: raise ReplayError(f"succession field mismatch: {key}")
    if document.get("successorDeletionDenialVerified") is not True or document.get("successorRestoreReadbackVerified") is not True or document.get("successorCustodyAccepted") is not True:
        raise ReplayError("successor custody evidence incomplete")
    if not document.get("evidenceRefs"): raise ReplayError("succession evidence absent")
    effective=parse_time(document.get("effectiveAt"))
    if not (seq33_latest < effective <= seq34_earliest): raise ReplayError("succession effective time outside cutover boundary")
    if document.get("recordDigest")!=digest_document(document,"recordDigest"): raise ReplayError("succession record digest mismatch")
    for identity in succession["requiredSigners"]:
        slug=policy["signerSlugs"][identity]
        verify_signature(path,Path(str(path)+f".{slug}.sig"),signers,SUCCESSION_NAMESPACE,identity)
    return document["recordDigest"],effective

def evaluate_replay(root:Path,policy:dict[str,Any],as_of:datetime)->dict[str,Any]:
    signers=_load_signers(root)
    matrix_digest=_verify_independence(root,signers,policy)
    f2cert=load_json(root/"evidence/m0-a12-f2/continuity-certificate.json")
    anchor=f2cert.get("lastObservationDigest"); anchor_time=parse_time(f2cert.get("lastObservedAt"))
    if not isinstance(anchor,str) or len(anchor)!=64: raise ReplayError("invalid F2 anchor digest")
    observers=policy["observers"]; first=policy["window"]["firstSequence"]; last=policy["window"]["lastSequence"]
    previous={observer:anchor for observer in observers}; previous_time={observer:anchor_time for observer in observers}
    last_digest={}; pair_times={}; signed_count=0; mismatch_count=0
    for sequence in range(first,last+1):
        pair=[]
        for observer in observers:
            slug=policy["observerSlugs"][observer]
            path=root/f"evidence/m0-a12-f3/observations/{sequence:06d}.{slug}.json"
            document=load_json(path)
            if document.get("standard")!="EIGIIB-M0-A12-F3-DIFFERENTIAL-OBSERVATION-1.0": raise ReplayError("observation standard mismatch")
            if document.get("campaignId")!=policy["campaignId"] or document.get("sequence")!=sequence: raise ReplayError("observation identity mismatch")
            if document.get("observerDomainId")!=observer or not document.get("observerKeyId"): raise ReplayError("observer binding mismatch")
            if document.get("previousObservationDigest")!=previous[observer]: raise ReplayError("observer digest chain mismatch")
            observed=parse_time(document.get("observedAt")); delta=(observed-previous_time[observer]).total_seconds()
            if delta<policy["timing"]["minimumGapSeconds"] or delta>policy["timing"]["cadenceSeconds"]+policy["timing"]["graceSeconds"]:
                raise ReplayError("observer cadence outside admitted window")
            _verify_channel_set(document,policy,sequence)
            expected_fact=hashlib.sha256(canonical_bytes(_fact_payload(document))).hexdigest()
            if document.get("factSetDigest")!=expected_fact: raise ReplayError("fact-set digest mismatch")
            if document.get("observationDigest")!=digest_document(document,"observationDigest"): raise ReplayError("observation digest mismatch")
            verify_signature(path,Path(str(path)+".sig"),signers,OBS_NAMESPACE,observer)
            previous[observer]=document["observationDigest"]; previous_time[observer]=observed; last_digest[observer]=document["observationDigest"]
            pair.append((document,observed)); signed_count+=1
        if pair[0][0]["factSetDigest"]!=pair[1][0]["factSetDigest"]: mismatch_count+=1
        skew=abs((pair[0][1]-pair[1][1]).total_seconds())
        if skew>policy["timing"]["maximumObserverSkewSeconds"]: raise ReplayError("observer time skew exceeds bound")
        pair_times[sequence]=(min(pair[0][1],pair[1][1]),max(pair[0][1],pair[1][1]))
    succession_digest,effective=_verify_succession(root,signers,policy,pair_times[33][1],pair_times[34][0])
    latest=max(previous_time.values()); due=latest+timedelta(seconds=policy["timing"]["cadenceSeconds"])
    if as_of<=due: state="current"
    elif as_of<=due+timedelta(seconds=policy["timing"]["graceSeconds"]): state="grace"
    elif as_of<due+timedelta(seconds=policy["timing"]["lapseAfterSeconds"]): state="overdue"
    else: state="lapsed"
    return {
      "f2AnchorDigest":anchor,
      "observerIndependenceDigest":matrix_digest,
      "firstSequence":first,"lastSequence":last,
      "pairedRoundCount":last-first+1,"signedObservationCount":signed_count,
      "differentialMismatchCount":mismatch_count,
      "primaryLastDigest":last_digest[observers[0]],"secondaryLastDigest":last_digest[observers[1]],
      "successionRecordDigest":succession_digest,"cutoverSequence":policy["succession"]["cutoverSequence"],
      "successionEffectiveAt":effective.isoformat().replace("+00:00","Z"),
      "lastObservedAt":latest.isoformat().replace("+00:00","Z"),
      "elapsedSeconds":int((latest-anchor_time).total_seconds()),"lapseState":state,
    }
