#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime
from pathlib import Path

A4="353c854ddce61207d8a053d61be9e3d4ffdfc2e4"
STANDARD="EIGIIB-IDP-A5-DISCLOSURE-RELEASE-AUTHORITY-1.0"

def h(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()

def c(obj)->str:
    return h(json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())

def when(s):
    if type(s) is not str or not s.endswith("Z"): return None
    try: return datetime.fromisoformat(s[:-1]+"+00:00")
    except ValueError: return None

def inspect(pkg, source_file:Path, projection_file:Path):
    e=[]
    required={"standard","source","projection","reviewPolicy","authorities","authoritySetDigest","reviews","reviewSetDigest","freeze","claimBoundary"}
    if type(pkg) is not dict or set(pkg)!=required: return ["package shape"]
    if pkg.get("standard")!=STANDARD: e.append("standard")
    s=pkg.get("source",{}); p=pkg.get("projection",{}); pol=pkg.get("reviewPolicy",{}); f=pkg.get("freeze",{})
    if s.get("slice")!="IDP-A4" or s.get("head")!=A4: e.append("source authority")
    if s.get("registryPath")!="conformance/idp-a4-public-transparency.json": e.append("source path")
    if p.get("path")!="conformance/idp-a5-public-projection.json" or p.get("replayMode")!="byte-exact-copy": e.append("projection declaration")
    try:
        sb=source_file.read_bytes(); pb=projection_file.read_bytes()
        sj=json.loads(sb.decode()); pj=json.loads(pb.decode())
    except Exception:
        return e+["projection parse"]
    sr=h(sb); pr=h(pb); sc=c(sj); pc=c(pj)
    if sb!=pb or sj!=pj: e.append("exact replay")
    if [s.get("registrySha256"),p.get("sha256")] != [sr,pr] or sr!=pr: e.append("raw binding")
    if [s.get("registryCanonicalSha256"),p.get("canonicalSha256")] != [sc,pc] or sc!=pc: e.append("canonical binding")
    if pol != {
        "requiredApprovals":2,"totalAuthorities":3,
        "decisionVocabulary":["approve","reject"],
        "independenceFields":["principalId","controlDomainId","identityRoot"],
        "approvalBinding":"exact-projection-sha256"
    }: e.append("policy")
    auth=pkg.get("authorities")
    if type(auth) is not list or len(auth)!=3: e.append("authority count"); auth=[] if type(auth) is not list else auth
    ids=[]
    for a in auth:
        if type(a) is not dict or set(a)!={"authorityId","principalId","role","controlDomainId","identityRoot","implementation"}:
            e.append("authority shape"); continue
        if a.get("role")!="disclosure-reviewer": e.append("authority role")
        ids.append(a.get("authorityId"))
    if len(ids)!=len(set(ids)) or None in ids: e.append("authority ids")
    for fld in ("principalId","controlDomainId","identityRoot"):
        vals=[a.get(fld) for a in auth if type(a) is dict]
        if len(vals)!=3 or None in vals or len(vals)!=len(set(vals)): e.append("independence "+fld)
    if pkg.get("authoritySetDigest")!=c(auth): e.append("authority digest")
    rev=pkg.get("reviews")
    if type(rev) is not list: e.append("reviews"); rev=[]
    seen=set(); approves=set()
    ft=when(f.get("frozenAt"))
    for r in rev:
        if type(r) is not dict or set(r)!={"reviewId","authorityId","projectionDigest","decision","reviewedAt","findings"}:
            e.append("review shape"); continue
        aid=r.get("authorityId")
        if aid not in ids: e.append("unknown reviewer")
        if aid in seen: e.append("duplicate reviewer")
        seen.add(aid)
        if r.get("projectionDigest")!=pr: e.append("review binding")
        rt=when(r.get("reviewedAt"))
        if rt is None or ft is None or rt>ft: e.append("review time")
        if r.get("decision")=="approve":
            if r.get("findings") != []: e.append("approval findings")
            approves.add(aid)
        elif r.get("decision")!="reject": e.append("review decision")
    if pkg.get("reviewSetDigest")!=c(rev): e.append("review digest")
    if len(approves)<2: e.append("threshold")
    if f.get("projectionDigest")!=pr: e.append("freeze binding")
    if f.get("state")!="structural-frozen": e.append("freeze state")
    if f.get("publicationAuthorized") is not False or f.get("publicationDisposition")!="not-published": e.append("publication boundary")
    approved=f.get("approvedBy")
    if type(approved) is not list or len(approved)!=len(set(approved)) or set(approved)!=approves: e.append("approvedBy")
    boundary=pkg.get("claimBoundary",{})
    if set(boundary.get("establishes",[])) != {
        "independent-disclosure-review-against-exact-projection",
        "two-of-three-multi-authority-structural-approval",
        "byte-exact-public-projection-replay",
        "post-review-structural-selective-transparency-freeze"
    }: e.append("establishes boundary")
    if set(boundary.get("doesNotImply",[])) != {
        "production-publication-authorization",
        "production-reviewer-identity-or-key-control",
        "external-registry-or-endpoint-publication",
        "production-opening-material-custody",
        "universal-unlinkability-or-side-channel-resistance",
        "merge-of-predecessor-pull-requests"
    }: e.append("limit boundary")
    return e

def main():
    q=argparse.ArgumentParser()
    q.add_argument("--package",type=Path,required=True)
    q.add_argument("--source",type=Path,required=True)
    q.add_argument("--projection",type=Path,required=True)
    q.add_argument("--require-conformant",action="store_true")
    q.add_argument("--json",action="store_true")
    a=q.parse_args()
    try: pkg=json.loads(a.package.read_text(encoding="utf-8")); errors=inspect(pkg,a.source,a.projection)
    except Exception as ex: errors=[str(ex)]
    result="conformant" if not errors else "nonconformant"
    out={"standard":STANDARD,"result":result,"findings":errors,"tool":"eigiib-idp-a5-independent"}
    print(json.dumps(out,sort_keys=True,separators=(",",":")) if a.json else result)
    return 0 if not errors else 2

if __name__=="__main__":
    raise SystemExit(main())
