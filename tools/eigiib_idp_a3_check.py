#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
from datetime import datetime

STD="EIGIIB-IDP-A3-0.1"
SRC="d2def5458da677fa061e38ed91a6d718b9cc8d2a"
BLOB="c00b26da424d483e394ee2b6375e773e10284465"
REQ_ROLES={
"l0-local-authority":"root-authority",
"idp-access-authority":"access-grant-authority",
"idp-eligibility-authority":"institutional-eligibility-authority",
"idp-revocation-authority":"revocation-authority",
"idp-quarantine-promotion-authority":"local-promotion-authority",
}
def dt(s):
    if not isinstance(s,str) or not s.endswith("Z"): raise ValueError(s)
    return datetime.fromisoformat(s[:-1]+"+00:00")
def add(f,c,d=None): f.append(c if d is None else f"{c}:{d}")
def unique(items,key,f,code):
    out={}
    for x in items if isinstance(items,list) else []:
        if not isinstance(x,dict): add(f,code,"shape"); continue
        k=x.get(key)
        if k in out: add(f,code,k)
        out[k]=x
    return out
def active_window(obj,t):
    try:return dt(obj["notBefore"])<=t<dt(obj["notAfter"])
    except Exception:return False
def validate(data,evaluation_at):
    f=[]
    try: now=dt(evaluation_at)
    except Exception: return ["evaluation-at-invalid"]
    if data.get("standard")!=STD:add(f,"standard")
    if data.get("registryScope") not in {"structural-only","operational"}:add(f,"registry-scope")
    tm=data.get("timeModel",{})
    if tm!={"evaluationSource":"explicit-caller-supplied","hostClockForbidden":True,"intervalSemantics":"notBefore<=t<notAfter","revocationSemantics":"effectiveAt<=t"}:add(f,"time-model")
    src=data.get("sourceA2",{})
    if src.get("head")!=SRC or src.get("bindingBlobSha")!=BLOB or src.get("bindingPath")!="conformance/idp-a2-bridge-binding.json":add(f,"source-a2")
    auth=unique(data.get("authorities"),"id",f,"authority-duplicate")
    for aid,role in REQ_ROLES.items():
        if auth.get(aid,{}).get("role")!=role:add(f,"authority-role",aid)
    roots=[k for k,v in auth.items() if v.get("role")=="root-authority"]
    if roots!=["l0-local-authority"]:add(f,"root-authority")
    inst=unique(data.get("institutions"),"id",f,"institution-duplicate")
    subs=unique(data.get("subjects"),"id",f,"subject-duplicate")
    aud=unique(data.get("audiences"),"id",f,"audience-duplicate")
    grants=unique(data.get("grants"),"id",f,"grant-duplicate")
    revs=unique(data.get("revocations"),"id",f,"revocation-duplicate")
    qrs=unique(data.get("quarantineRecords"),"id",f,"quarantine-duplicate")
    pds=unique(data.get("promotionDecisions"),"id",f,"promotion-duplicate")
    if data.get("registryScope")=="structural-only":
        for kind,m in [("institution",inst),("subject",subs),("grant",grants),("revocation",revs),("quarantine",qrs),("promotion",pds)]:
            for k,v in m.items():
                if v.get("synthetic") is not True:add(f,"non-synthetic-structural",f"{kind}/{k}")
        for s in subs.values():
            if s.get("identityState")!="synthetic":add(f,"proofed-identity-in-structural",s.get("id"))
    for i in inst.values():
        if auth.get(i.get("eligibilityAuthorityId"),{}).get("role")!="institutional-eligibility-authority":add(f,"eligibility-authority",i.get("id"))
        try:
            if dt(i["notBefore"])>=dt(i["notAfter"]):add(f,"eligibility-window",i.get("id"))
        except Exception:add(f,"eligibility-time",i.get("id"))
        if "D5" in i.get("eligibleClasses",[]):add(f,"d5-eligibility-forbidden",i.get("id"))
    for s in subs.values():
        if s.get("institutionId") not in inst:add(f,"subject-institution",s.get("id"))
    expected_channel={"restricted-review":"restricted-review","return-quarantine-review":"private-bridge-return","controlled-engineering":"private-bridge-out"}
    for a in aud.values():
        if a.get("purpose") in expected_channel and a.get("channelId")!=expected_channel[a.get("purpose")]:add(f,"audience-channel",a.get("id"))
        for sid in a.get("namedSubjectIds",[]):
            if sid not in subs:add(f,"audience-subject",a.get("id"))
        for iid in a.get("allowedInstitutionIds",[]):
            if iid not in inst:add(f,"audience-institution",a.get("id"))
    rev_by_grant={}
    for r in revs.values():
        if r.get("grantId") not in grants:add(f,"revocation-grant",r.get("id"))
        if auth.get(r.get("authorityId"),{}).get("role")!="revocation-authority":add(f,"revocation-authority",r.get("id"))
        rev_by_grant.setdefault(r.get("grantId"),[]).append(r)
    def grant_structural(g):
        gid=g.get("id")
        s=subs.get(g.get("subjectId")); i=inst.get(g.get("institutionId")); a=aud.get(g.get("audienceId"))
        if not s or not i or not a:return False
        ok=True
        if s.get("institutionId")!=g.get("institutionId"):add(f,"grant-subject-institution",gid);ok=False
        if g.get("subjectId") not in a.get("namedSubjectIds",[]):add(f,"grant-audience-subject",gid);ok=False
        if g.get("institutionId") not in a.get("allowedInstitutionIds",[]):add(f,"grant-audience-institution",gid);ok=False
        if g.get("classification")!=a.get("classification") or g.get("channelId")!=a.get("channelId"):add(f,"grant-audience-binding",gid);ok=False
        if g.get("classification")=="D5":add(f,"d5-grant-forbidden",gid);ok=False
        if g.get("classification") not in i.get("eligibleClasses",[]):add(f,"grant-institution-class",gid);ok=False
        if auth.get(g.get("issuerAuthorityId"),{}).get("role")!="access-grant-authority":add(f,"grant-issuer-authority",gid);ok=False
        try:
            if not (dt(g["issuedAt"])<=dt(g["notBefore"])<dt(g["notAfter"])):add(f,"grant-window",gid);ok=False
        except Exception:add(f,"grant-time",gid);ok=False
        return ok
    for g in grants.values():grant_structural(g)
    def grant_usable(gid,t):
        g=grants.get(gid)
        if not g or g.get("state")!="active" or not active_window(g,t):return False
        i=inst.get(g.get("institutionId"))
        if not i or i.get("state")!="eligible" or not active_window(i,t):return False
        for r in rev_by_grant.get(gid,[]):
            try:
                if dt(r["effectiveAt"])<=t:return False
            except Exception:return False
        return True
    for q in qrs.values():
        if q.get("channelId")!="private-bridge-return" or q.get("sourceBindingId")!="bridge-return-binding":add(f,"quarantine-source",q.get("id"))
        if q.get("state")!="quarantined":add(f,"return-not-quarantined",q.get("id"))
        if q.get("classification")=="D5":add(f,"d5-return-forbidden",q.get("id"))
    for p in pds.values():
        pid=p.get("id"); q=qrs.get(p.get("quarantineRecordId")); g=grants.get(p.get("reviewerGrantId"))
        if not q:add(f,"promotion-quarantine-missing",pid);continue
        if not g:add(f,"promotion-grant-missing",pid);continue
        if auth.get(p.get("authorityId"),{}).get("role")!="local-promotion-authority":add(f,"promotion-authority",pid)
        if p.get("targetDisposition")!="local-review-staging":add(f,"promotion-target",pid)
        if p.get("mergeAuthorityClaim") is not False:add(f,"promotion-merge-claim",pid)
        if p.get("reclassificationClaim") is not False:add(f,"promotion-reclass-claim",pid)
        try:t=dt(p["decidedAt"])
        except Exception:add(f,"promotion-time",pid);continue
        if not grant_usable(g.get("id"),t):add(f,"promotion-grant-not-usable",pid)
        a=aud.get(g.get("audienceId"),{})
        if a.get("purpose")!="return-quarantine-review" or g.get("channelId")!="private-bridge-return":add(f,"promotion-grant-purpose",pid)
        if g.get("classification")!=q.get("classification"):add(f,"promotion-class-binding",pid)
        try:
            if dt(q["receivedAt"])>t:add(f,"promotion-before-receipt",pid)
        except Exception:add(f,"quarantine-time",q.get("id"))
    checks=unique(data.get("accessChecks"),"id",f,"access-check-duplicate")
    for c in checks.values():
        gid=c.get("grantId")
        if gid not in grants:
            add(f,"access-check-grant",c.get("id")); continue
        actual="authorized" if grant_usable(gid,now) else "denied"
        if actual!=c.get("expected"):add(f,"access-check-result",c.get("id"))
    return sorted(set(f))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("registry");ap.add_argument("--evaluation-at",required=True);ap.add_argument("--json",action="store_true");ap.add_argument("--require-conformant",action="store_true")
    ns=ap.parse_args();data=json.loads(Path(ns.registry).read_text(encoding="utf-8"));findings=validate(data,ns.evaluation_at)
    out={"standard":STD,"evaluationAt":ns.evaluation_at,"result":"CONFORMANT" if not findings else "NON_CONFORMANT","findings":findings}
    print(json.dumps(out,sort_keys=True) if ns.json else out["result"]+("\n"+"\n".join(findings) if findings else ""))
    return 1 if ns.require_conformant and findings else 0
if __name__=="__main__":raise SystemExit(main())
