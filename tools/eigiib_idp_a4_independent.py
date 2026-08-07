#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path

H=re.compile(r"[0-9a-f]{64}\Z")
DOMAIN=b"EIGIIB-IDP-A4-COMMITMENT-1.0\x00"
PUBLIC_ALLOWED={"standard","commitmentProfile","records","withdrawals","claimBoundary"}
RECORD_ALLOWED={"recordId","recordType","publicationClass","publicHandle","commitment","subjectDisclosure","verificationState","publishedAt","state","withdrawalId"}
WITHDRAW_ALLOWED={"withdrawalId","recordId","effectiveAt","reasonClass"}
LEAK_NAMES={"internalArtifactId","payloadDigest","salt","endpoint","bridgeEndpoint","grantId","institutionId","subjectId","privateKey","keyMaterial"}
BOUNDARY_EST={"public-existence-and-bounded-status-without-opening-material","salted-opaque-commitment-construction-and-binding","append-only-public-withdrawal","public-handle-and-salt-non-reuse-in-declared-registry"}
BOUNDARY_LIM={"public-access-to-restricted-payload","public-knowledge-of-internal-artifact-identity","public-knowledge-of-internal-classification","public-verification-without-opening-material","absence-or-existence-of-unlisted-restricted-artifacts","production-salt-or-handle-entropy","universal-unlinkability-against-timing-traffic-or-semantic-side-channels"}


def load(path):
    def hook(pairs):
        out={}
        for key,value in pairs:
            if key in out: raise RuntimeError("duplicate-member")
            out[key]=value
        return out
    value=json.loads(Path(path).read_text(encoding="utf-8"),object_pairs_hook=hook)
    if type(value) is not dict: raise RuntimeError("root-not-object")
    return value


def leak(value):
    if type(value) is dict:
        if LEAK_NAMES.intersection(value): return True
        return any(leak(v) for v in value.values())
    if type(value) is list: return any(leak(v) for v in value)
    return False


def digest(record_id,salt,payload):
    return hashlib.sha256(DOMAIN+record_id.encode("utf-8")+b"\0"+bytes.fromhex(salt)+bytes.fromhex(payload)).hexdigest()


def when(value):
    if type(value) is not str or not value.endswith("Z"): raise RuntimeError("timestamp")
    try: parsed=datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError as exc: raise RuntimeError("timestamp") from exc
    if parsed.tzinfo != timezone.utc: raise RuntimeError("timestamp")
    return parsed


def decide(public,private):
    if set(public)!=PUBLIC_ALLOWED or public.get("standard")!="EIGIIB-IDP-A4-PUBLIC-TRANSPARENCY-1.0" or leak(public): return False,"public-boundary"
    boundary=public.get("claimBoundary")
    if type(boundary) is not dict or set(boundary)!={"establishes","doesNotImply"} or set(boundary.get("establishes",[]))!=BOUNDARY_EST or set(boundary.get("doesNotImply",[]))!=BOUNDARY_LIM: return False,"claim-boundary"
    profile=public.get("commitmentProfile")
    if profile!={"algorithm":"sha256","domainSeparator":"EIGIIB-IDP-A4-COMMITMENT-1.0","saltBytes":32,"saltPolicy":"fresh-per-public-record","openingMaterialPublic":False}: return False,"profile"
    records=public.get("records"); withdrawals=public.get("withdrawals")
    if type(records) is not list or not records or type(withdrawals) is not list: return False,"collections"
    by_id={}; handles=set(); commitments=set()
    for record in records:
        if type(record) is not dict or set(record)!=RECORD_ALLOWED: return False,"record-shape"
        rid=record.get("recordId")
        if type(rid) is not str or rid in by_id: return False,"record-id"
        if record.get("recordType")!="restricted-state-announcement" or record.get("publicationClass")!="D0" or record.get("subjectDisclosure")!="restricted-nonpublic": return False,"record-disclosure"
        if record.get("state") not in ("active","withdrawn"): return False,"record-state"
        if record.get("verificationState") not in ("verified-within-declared-boundary","not-verified"): return False,"verification-state"
        try: when(record.get("publishedAt"))
        except RuntimeError: return False,"published-at"
        for key,bucket in (("publicHandle",handles),("commitment",commitments)):
            value=record.get(key)
            if type(value) is not str or not H.fullmatch(value) or value in bucket: return False,key
            bucket.add(value)
        if (record["state"]=="active") != (record["withdrawalId"] is None): return False,"withdrawal-field"
        by_id[rid]=record
    events={key:[] for key in by_id}; event_ids=set()
    for withdrawal in withdrawals:
        if type(withdrawal) is not dict or set(withdrawal)!=WITHDRAW_ALLOWED: return False,"withdraw-shape"
        if withdrawal.get("withdrawalId") in event_ids: return False,"withdraw-id"
        event_ids.add(withdrawal.get("withdrawalId"))
        if withdrawal.get("recordId") not in by_id: return False,"withdraw-target"
        try:
            if when(withdrawal.get("effectiveAt")) < when(by_id[withdrawal["recordId"]]["publishedAt"]): return False,"withdraw-time"
        except RuntimeError: return False,"withdraw-time"
        events[withdrawal["recordId"]].append(withdrawal)
        record=by_id[withdrawal["recordId"]]
        if record["state"]!="withdrawn" or record["withdrawalId"]!=withdrawal["withdrawalId"]: return False,"withdraw-binding"
    for rid,record in by_id.items():
        if (record["state"]=="withdrawn" and len(events[rid])!=1) or (record["state"]=="active" and events[rid]): return False,"withdraw-cardinality"
    if set(private)!={"standard","synthetic","witnesses"} or private.get("standard")!="EIGIIB-IDP-A4-SYNTHETIC-PRIVATE-WITNESS-1.0" or private.get("synthetic") is not True: return False,"fixture-boundary"
    witnesses=private.get("witnesses")
    if type(witnesses) is not list or len(witnesses)!=len(records): return False,"witness-count"
    salts=set(); seen=set(); by_payload={}
    for witness in witnesses:
        if type(witness) is not dict or set(witness)!={"recordId","internalArtifactId","internalClassification","payloadDigest","salt"}: return False,"witness-shape"
        rid=witness.get("recordId")
        if rid not in by_id or rid in seen: return False,"witness-record"
        seen.add(rid)
        if witness.get("internalClassification") not in ("D3","D4"): return False,"witness-class"
        salt=witness.get("salt"); payload=witness.get("payloadDigest")
        if type(salt) is not str or not H.fullmatch(salt) or int(salt,16)==0 or salt in salts: return False,"salt"
        if type(payload) is not str or not H.fullmatch(payload): return False,"payload"
        salts.add(salt)
        if digest(rid,salt,payload)!=by_id[rid]["commitment"]: return False,"commitment"
        by_payload.setdefault(payload,set()).add(by_id[rid]["commitment"])
    for payload,values in by_payload.items():
        count=sum(1 for witness in witnesses if witness["payloadDigest"]==payload)
        if len(values)!=count: return False,"correlation"
    return True,"ok"


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--public",required=True); parser.add_argument("--private",dest="private_path",required=True); parser.add_argument("--json",action="store_true"); args=parser.parse_args()
    try: ok,reason=decide(load(args.public),load(args.private_path))
    except Exception as exc: ok,reason=False,str(exc)
    out={"standard":"EIGIIB-IDP-A4-PUBLIC-TRANSPARENCY-1.0","result":"conformant" if ok else "nonconformant","reason":reason,"tool":"eigiib-idp-a4-independent"}
    print(json.dumps(out,sort_keys=True,separators=(",",":")) if args.json else out["result"])
    return 0 if ok else 2


if __name__=="__main__": raise SystemExit(main())
