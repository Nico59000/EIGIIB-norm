#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STANDARD="EIGIIB-IDP-A4-PUBLIC-TRANSPARENCY-1.0"
PRIVATE_STANDARD="EIGIIB-IDP-A4-SYNTHETIC-PRIVATE-WITNESS-1.0"
DOMAIN=b"EIGIIB-IDP-A4-COMMITMENT-1.0\x00"
HEX64=re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN={"internalArtifactId","payloadDigest","salt","endpoint","bridgeEndpoint","grantId","institutionId","subjectId","privateKey","keyMaterial"}
REC_KEYS={"recordId","recordType","publicationClass","publicHandle","commitment","subjectDisclosure","verificationState","publishedAt","state","withdrawalId"}
WD_KEYS={"withdrawalId","recordId","effectiveAt","reasonClass"}
TOP_KEYS={"standard","commitmentProfile","records","withdrawals","claimBoundary"}
PROFILE_KEYS={"algorithm","domainSeparator","saltBytes","saltPolicy","openingMaterialPublic"}
BOUNDARY_KEYS={"establishes","doesNotImply"}
EXPECTED_ESTABLISHES={
    "public-existence-and-bounded-status-without-opening-material",
    "salted-opaque-commitment-construction-and-binding",
    "append-only-public-withdrawal",
    "public-handle-and-salt-non-reuse-in-declared-registry",
}
EXPECTED_LIMITS={
    "public-access-to-restricted-payload",
    "public-knowledge-of-internal-artifact-identity",
    "public-knowledge-of-internal-classification",
    "public-verification-without-opening-material",
    "absence-or-existence-of-unlisted-restricted-artifacts",
    "production-salt-or-handle-entropy",
    "universal-unlinkability-against-timing-traffic-or-semantic-side-channels",
}


def strict(path:Path)->dict[str,Any]:
    def hook(pairs):
        d={}
        for k,v in pairs:
            if k in d: raise ValueError(f"duplicate JSON member: {k}")
            d[k]=v
        return d
    x=json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=hook)
    if not isinstance(x,dict): raise ValueError("root must be object")
    return x


def _forbidden(x:Any,path="$"):
    if isinstance(x,dict):
        for k,v in x.items():
            if k in FORBIDDEN: raise ValueError(f"forbidden public field {k} at {path}")
            _forbidden(v,path+"."+k)
    elif isinstance(x,list):
        for i,v in enumerate(x): _forbidden(v,f"{path}[{i}]")


def commitment(record_id:str,salt:str,digest:str)->str:
    return hashlib.sha256(DOMAIN+record_id.encode()+b"\x00"+bytes.fromhex(salt)+bytes.fromhex(digest)).hexdigest()


def instant(value:str)->datetime:
    if not isinstance(value,str) or not value.endswith("Z"):
        raise ValueError("timestamp must be RFC3339 UTC Z")
    try:
        dt=datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError as exc:
        raise ValueError("timestamp invalid") from exc
    if dt.tzinfo != timezone.utc:
        raise ValueError("timestamp must be UTC")
    return dt


def evaluate(public:dict[str,Any],private:dict[str,Any])->list[str]:
    findings=[]
    try:
        if set(public)!=TOP_KEYS: raise ValueError("public top-level fields are not closed")
        if public.get("standard")!=STANDARD: raise ValueError("wrong public standard")
        profile=public.get("commitmentProfile")
        if not isinstance(profile,dict) or set(profile)!=PROFILE_KEYS: raise ValueError("commitment profile not closed")
        expected={"algorithm":"sha256","domainSeparator":"EIGIIB-IDP-A4-COMMITMENT-1.0","saltBytes":32,"saltPolicy":"fresh-per-public-record","openingMaterialPublic":False}
        if profile!=expected: raise ValueError("commitment profile mismatch")
        boundary=public.get("claimBoundary")
        if not isinstance(boundary,dict) or set(boundary)!=BOUNDARY_KEYS: raise ValueError("claim boundary not closed")
        if set(boundary.get("establishes",[]))!=EXPECTED_ESTABLISHES or set(boundary.get("doesNotImply",[]))!=EXPECTED_LIMITS: raise ValueError("claim boundary mismatch")
        _forbidden(public)
        records=public.get("records"); withdrawals=public.get("withdrawals")
        if not isinstance(records,list) or not records: raise ValueError("records missing")
        if not isinstance(withdrawals,list): raise ValueError("withdrawals malformed")
        ids=set(); handles=set(); commits=set(); byid={}
        for record in records:
            if not isinstance(record,dict) or set(record)!=REC_KEYS: raise ValueError("record fields not closed")
            rid=record["recordId"]
            if not isinstance(rid,str) or not rid.startswith("pub-") or rid in ids: raise ValueError("record id invalid or duplicate")
            ids.add(rid); byid[rid]=record
            if record["recordType"]!="restricted-state-announcement" or record["publicationClass"]!="D0" or record["subjectDisclosure"]!="restricted-nonpublic": raise ValueError("public disclosure class mismatch")
            if record["state"] not in {"active","withdrawn"}: raise ValueError("record state invalid")
            if record["verificationState"] not in {"verified-within-declared-boundary","not-verified"}: raise ValueError("verification state invalid")
            instant(record["publishedAt"])
            for field,bucket in (("publicHandle",handles),("commitment",commits)):
                val=record[field]
                if not isinstance(val,str) or not HEX64.fullmatch(val) or val in bucket: raise ValueError(f"{field} invalid or reused")
                bucket.add(val)
            if record["state"]=="active" and record["withdrawalId"] is not None: raise ValueError("active record cannot claim withdrawal")
            if record["state"]=="withdrawn" and not isinstance(record["withdrawalId"],str): raise ValueError("withdrawn record needs withdrawal id")
        withdrawal_ids=set(); target_count={rid:0 for rid in ids}
        for withdrawal in withdrawals:
            if not isinstance(withdrawal,dict) or set(withdrawal)!=WD_KEYS: raise ValueError("withdrawal fields not closed")
            if withdrawal["withdrawalId"] in withdrawal_ids: raise ValueError("withdrawal id reused")
            withdrawal_ids.add(withdrawal["withdrawalId"])
            if withdrawal["recordId"] not in byid: raise ValueError("withdrawal target missing")
            if withdrawal["reasonClass"] not in {"policy-change","superseded","claim-retracted","publication-error"}: raise ValueError("withdrawal reason invalid")
            if instant(withdrawal["effectiveAt"]) < instant(byid[withdrawal["recordId"]]["publishedAt"]): raise ValueError("withdrawal precedes publication")
            target_count[withdrawal["recordId"]]+=1
            record=byid[withdrawal["recordId"]]
            if record["state"]!="withdrawn" or record["withdrawalId"]!=withdrawal["withdrawalId"]: raise ValueError("withdrawal state binding mismatch")
        for rid,record in byid.items():
            if record["state"]=="withdrawn" and target_count[rid]!=1: raise ValueError("withdrawn record needs exactly one event")
            if record["state"]=="active" and target_count[rid]!=0: raise ValueError("active record cannot have withdrawal event")

        if set(private)!={"standard","synthetic","witnesses"} or private.get("standard")!=PRIVATE_STANDARD or private.get("synthetic") is not True: raise ValueError("private fixture boundary invalid")
        witnesses=private.get("witnesses")
        if not isinstance(witnesses,list) or len(witnesses)!=len(records): raise ValueError("witness count mismatch")
        seen_record=set(); salts=set(); grouped={}
        for witness in witnesses:
            if not isinstance(witness,dict) or set(witness)!={"recordId","internalArtifactId","internalClassification","payloadDigest","salt"}: raise ValueError("private witness fields not closed")
            rid=witness["recordId"]
            if rid not in byid or rid in seen_record: raise ValueError("private witness record binding invalid")
            seen_record.add(rid)
            if witness["internalClassification"] not in {"D3","D4"}: raise ValueError("fixture classification outside restricted classes")
            salt=witness["salt"]; digest=witness["payloadDigest"]
            if not isinstance(salt,str) or not HEX64.fullmatch(salt) or int(salt,16)==0 or salt in salts: raise ValueError("salt invalid, zero, or reused")
            salts.add(salt)
            if not isinstance(digest,str) or not HEX64.fullmatch(digest): raise ValueError("payload digest invalid")
            if commitment(rid,salt,digest)!=byid[rid]["commitment"]: raise ValueError("opaque commitment mismatch")
            grouped.setdefault(digest,[]).append(byid[rid]["commitment"])
        for values in grouped.values():
            if len(values)>1 and len(set(values))!=len(values): raise ValueError("same payload correlated by repeated commitment")
    except (KeyError,TypeError,ValueError) as exc:
        findings.append(str(exc))
    return findings


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--public",type=Path,required=True); parser.add_argument("--private",dest="private_path",type=Path,required=True); parser.add_argument("--json",action="store_true"); args=parser.parse_args()
    try:
        public=strict(args.public); private=strict(args.private_path); findings=evaluate(public,private)
    except Exception as exc:
        findings=[str(exc)]
    out={"standard":STANDARD,"result":"conformant" if not findings else "nonconformant","findings":findings,"tool":"eigiib-idp-a4-check"}
    print(json.dumps(out,sort_keys=True,separators=(",",":")) if args.json else out["result"])
    return 0 if not findings else 2


if __name__=="__main__": raise SystemExit(main())
