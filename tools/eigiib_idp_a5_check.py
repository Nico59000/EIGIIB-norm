#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STANDARD="EIGIIB-IDP-A5-DISCLOSURE-RELEASE-AUTHORITY-1.0"
EXPECTED_A4_HEAD="353c854ddce61207d8a053d61be9e3d4ffdfc2e4"
EXPECTED_SOURCE_PATH="conformance/idp-a4-public-transparency.json"
EXPECTED_PROJECTION_PATH="conformance/idp-a5-public-projection.json"
HEX40=re.compile(r"^[0-9a-f]{40}$")
HEX64=re.compile(r"^[0-9a-f]{64}$")
TOP={"standard","source","projection","reviewPolicy","authorities","authoritySetDigest","reviews","reviewSetDigest","freeze","claimBoundary"}
SOURCE={"slice","head","registryPath","registrySha256","registryCanonicalSha256"}
PROJECTION={"path","sha256","canonicalSha256","replayMode"}
POLICY={"requiredApprovals","totalAuthorities","decisionVocabulary","independenceFields","approvalBinding"}
AUTH={"authorityId","principalId","role","controlDomainId","identityRoot","implementation"}
REVIEW={"reviewId","authorityId","projectionDigest","decision","reviewedAt","findings"}
FREEZE={"freezeId","projectionDigest","approvedBy","frozenAt","state","publicationAuthorized","publicationDisposition"}
BOUNDARY={"establishes","doesNotImply"}
EXPECTED_ESTABLISHES={
    "independent-disclosure-review-against-exact-projection",
    "two-of-three-multi-authority-structural-approval",
    "byte-exact-public-projection-replay",
    "post-review-structural-selective-transparency-freeze",
}
EXPECTED_LIMITS={
    "production-publication-authorization",
    "production-reviewer-identity-or-key-control",
    "external-registry-or-endpoint-publication",
    "production-opening-material-custody",
    "universal-unlinkability-or-side-channel-resistance",
    "merge-of-predecessor-pull-requests",
}

def strict_json(path:Path)->dict[str,Any]:
    def hook(pairs):
        out={}
        for k,v in pairs:
            if k in out:
                raise ValueError(f"duplicate JSON member: {k}")
            out[k]=v
        return out
    value=json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=hook)
    if not isinstance(value,dict):
        raise ValueError("JSON root must be object")
    return value

def canonical_digest(value:Any)->str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")).hexdigest()

def raw_digest(path:Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def utc(value:Any)->datetime:
    if not isinstance(value,str) or not value.endswith("Z"):
        raise ValueError("timestamp must be RFC3339 UTC Z")
    try:
        dt=datetime.fromisoformat(value[:-1]+"+00:00")
    except ValueError as exc:
        raise ValueError("timestamp invalid") from exc
    if dt.tzinfo != timezone.utc:
        raise ValueError("timestamp must be UTC")
    return dt

def evaluate(package:dict[str,Any], source_path:Path, projection_path:Path)->list[str]:
    findings=[]
    try:
        if set(package)!=TOP: raise ValueError("top-level fields not closed")
        if package["standard"]!=STANDARD: raise ValueError("wrong standard")

        source=package["source"]; projection=package["projection"]; policy=package["reviewPolicy"]
        freeze=package["freeze"]; boundary=package["claimBoundary"]
        if not isinstance(source,dict) or set(source)!=SOURCE: raise ValueError("source not closed")
        if not isinstance(projection,dict) or set(projection)!=PROJECTION: raise ValueError("projection not closed")
        if not isinstance(policy,dict) or set(policy)!=POLICY: raise ValueError("review policy not closed")
        if not isinstance(freeze,dict) or set(freeze)!=FREEZE: raise ValueError("freeze not closed")
        if not isinstance(boundary,dict) or set(boundary)!=BOUNDARY: raise ValueError("claim boundary not closed")
        if source["slice"]!="IDP-A4" or source["head"]!=EXPECTED_A4_HEAD or not HEX40.fullmatch(source["head"]):
            raise ValueError("source predecessor mismatch")
        if source["registryPath"]!=EXPECTED_SOURCE_PATH: raise ValueError("source registry path mismatch")
        if projection["path"]!=EXPECTED_PROJECTION_PATH or projection["replayMode"]!="byte-exact-copy":
            raise ValueError("projection declaration mismatch")

        source_bytes=source_path.read_bytes(); projection_bytes=projection_path.read_bytes()
        source_json=strict_json(source_path); projection_json=strict_json(projection_path)
        sraw=hashlib.sha256(source_bytes).hexdigest(); praw=hashlib.sha256(projection_bytes).hexdigest()
        scan=canonical_digest(source_json); pcan=canonical_digest(projection_json)
        if source_bytes!=projection_bytes: raise ValueError("projection is not byte-exact source replay")
        if source_json!=projection_json: raise ValueError("projection semantic replay mismatch")
        if source["registrySha256"]!=sraw or projection["sha256"]!=praw or source["registrySha256"]!=projection["sha256"]:
            raise ValueError("raw projection digest mismatch")
        if source["registryCanonicalSha256"]!=scan or projection["canonicalSha256"]!=pcan or scan!=pcan:
            raise ValueError("canonical projection digest mismatch")

        expected_policy={
            "requiredApprovals":2,
            "totalAuthorities":3,
            "decisionVocabulary":["approve","reject"],
            "independenceFields":["principalId","controlDomainId","identityRoot"],
            "approvalBinding":"exact-projection-sha256",
        }
        if policy!=expected_policy: raise ValueError("review policy mismatch")

        authorities=package["authorities"]
        if not isinstance(authorities,list) or len(authorities)!=3: raise ValueError("authority cardinality mismatch")
        byid={}
        for a in authorities:
            if not isinstance(a,dict) or set(a)!=AUTH: raise ValueError("authority fields not closed")
            if a["role"]!="disclosure-reviewer": raise ValueError("authority role mismatch")
            aid=a["authorityId"]
            if not isinstance(aid,str) or not aid or aid in byid: raise ValueError("authority id invalid or duplicate")
            byid[aid]=a
        for field in ("principalId","controlDomainId","identityRoot"):
            vals=[a[field] for a in authorities]
            if any(not isinstance(v,str) or not v for v in vals) or len(set(vals))!=len(vals):
                raise ValueError(f"authority independence collision: {field}")
        if package["authoritySetDigest"]!=canonical_digest(authorities):
            raise ValueError("authority set digest mismatch")

        reviews=package["reviews"]
        if not isinstance(reviews,list) or not (1<=len(reviews)<=3): raise ValueError("review cardinality invalid")
        review_ids=set(); review_authorities=set(); approving=set(); latest=None
        frozen_at=utc(freeze["frozenAt"])
        for review in reviews:
            if not isinstance(review,dict) or set(review)!=REVIEW: raise ValueError("review fields not closed")
            rid=review["reviewId"]; aid=review["authorityId"]
            if not isinstance(rid,str) or not rid or rid in review_ids: raise ValueError("review id invalid or duplicate")
            review_ids.add(rid)
            if aid not in byid: raise ValueError("review authority unknown")
            if aid in review_authorities: raise ValueError("duplicate review authority")
            review_authorities.add(aid)
            if review["projectionDigest"]!=praw: raise ValueError("review projection digest mismatch")
            if review["decision"] not in {"approve","reject"}: raise ValueError("review decision invalid")
            if not isinstance(review["findings"],list) or any(not isinstance(x,str) for x in review["findings"]): raise ValueError("review findings malformed")
            t=utc(review["reviewedAt"])
            if t>frozen_at: raise ValueError("review occurs after freeze")
            latest=t if latest is None or t>latest else latest
            if review["decision"]=="approve":
                if review["findings"]: raise ValueError("approval cannot carry unresolved findings")
                approving.add(aid)
        if package["reviewSetDigest"]!=canonical_digest(reviews): raise ValueError("review set digest mismatch")
        if len(approving)<policy["requiredApprovals"]: raise ValueError("insufficient approvals")

        if freeze["projectionDigest"]!=praw: raise ValueError("freeze projection digest mismatch")
        if freeze["state"]!="structural-frozen": raise ValueError("freeze state mismatch")
        if freeze["publicationAuthorized"] is not False: raise ValueError("structural corpus cannot authorize publication")
        if freeze["publicationDisposition"]!="not-published": raise ValueError("structural corpus publication disposition mismatch")
        approved=freeze["approvedBy"]
        if not isinstance(approved,list) or len(approved)!=len(set(approved)): raise ValueError("approvedBy malformed or duplicate")
        if set(approved)!=approving: raise ValueError("approvedBy does not exactly match approving reviews")
        if latest is not None and frozen_at<latest: raise ValueError("freeze precedes counted reviews")

        if set(boundary["establishes"])!=EXPECTED_ESTABLISHES or set(boundary["doesNotImply"])!=EXPECTED_LIMITS:
            raise ValueError("claim boundary mismatch")
    except (KeyError,TypeError,ValueError,OSError,json.JSONDecodeError) as exc:
        findings.append(str(exc))
    return findings

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--package",type=Path,required=True)
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--projection",type=Path,required=True)
    p.add_argument("--require-conformant",action="store_true")
    p.add_argument("--json",action="store_true")
    args=p.parse_args()
    try:
        package=strict_json(args.package)
        findings=evaluate(package,args.source,args.projection)
    except Exception as exc:
        findings=[str(exc)]
    result="conformant" if not findings else "nonconformant"
    out={"standard":STANDARD,"result":result,"findings":findings,"tool":"eigiib-idp-a5-check"}
    print(json.dumps(out,sort_keys=True,separators=(",",":")) if args.json else result)
    return 0 if not findings else 2

if __name__=="__main__":
    raise SystemExit(main())
