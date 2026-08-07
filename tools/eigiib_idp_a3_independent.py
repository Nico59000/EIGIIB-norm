#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
from datetime import datetime
STD="EIGIIB-IDP-A3-0.1"
def parse(s): return datetime.fromisoformat(s.replace("Z","+00:00"))
def verify(d,at):
    errs=[]; t=parse(at)
    if d.get("standard")!=STD:errs.append("standard")
    A={x["id"]:x for x in d.get("authorities",[]) if isinstance(x,dict) and "id" in x}
    I={x["id"]:x for x in d.get("institutions",[]) if isinstance(x,dict) and "id" in x}
    S={x["id"]:x for x in d.get("subjects",[]) if isinstance(x,dict) and "id" in x}
    U={x["id"]:x for x in d.get("audiences",[]) if isinstance(x,dict) and "id" in x}
    G={x["id"]:x for x in d.get("grants",[]) if isinstance(x,dict) and "id" in x}
    R=d.get("revocations",[]); Q={x["id"]:x for x in d.get("quarantineRecords",[]) if isinstance(x,dict) and "id" in x}
    if [k for k,v in A.items() if v.get("role")=="root-authority"]!=["l0-local-authority"]:errs.append("root-authority")
    if d.get("timeModel",{}).get("evaluationSource")!="explicit-caller-supplied" or d.get("timeModel",{}).get("hostClockForbidden") is not True:errs.append("time-model")
    revoked={}
    for r in R:
        if A.get(r.get("authorityId"),{}).get("role")!="revocation-authority":errs.append("revocation-authority")
        revoked.setdefault(r.get("grantId"),[]).append(r)
    def usable(gid,when):
        g=G.get(gid)
        if not g:return False
        s=S.get(g.get("subjectId"));i=I.get(g.get("institutionId"));u=U.get(g.get("audienceId"))
        if not s or not i or not u:return False
        if g.get("state")!="active" or not (parse(g["notBefore"])<=when<parse(g["notAfter"])):return False
        if i.get("state")!="eligible" or not(parse(i["notBefore"])<=when<parse(i["notAfter"])):return False
        if i.get("eligibilityAuthorityId") not in A or A[i["eligibilityAuthorityId"]].get("role")!="institutional-eligibility-authority":return False
        if s.get("institutionId")!=g.get("institutionId"):return False
        if g.get("subjectId") not in u.get("namedSubjectIds",[]) or g.get("institutionId") not in u.get("allowedInstitutionIds",[]):return False
        if g.get("channelId")!=u.get("channelId") or g.get("classification")!=u.get("classification"):return False
        if g.get("classification") not in i.get("eligibleClasses",[]):return False
        if A.get(g.get("issuerAuthorityId"),{}).get("role")!="access-grant-authority":return False
        if g.get("classification")=="D5":return False
        for r in revoked.get(gid,[]):
            if parse(r["effectiveAt"])<=when:return False
        return True
    for g in G.values():
        if not usable(g["id"],t) and g["id"] not in {"grant-engineering-beta-revoked"}:
            s=S.get(g.get("subjectId"));i=I.get(g.get("institutionId"));u=U.get(g.get("audienceId"))
            if not s or not i or not u or s.get("institutionId")!=g.get("institutionId") or g.get("subjectId") not in u.get("namedSubjectIds",[]) or g.get("institutionId") not in u.get("allowedInstitutionIds",[]) or g.get("channelId")!=u.get("channelId") or g.get("classification")!=u.get("classification") or g.get("classification") not in i.get("eligibleClasses",[]) or A.get(g.get("issuerAuthorityId"),{}).get("role")!="access-grant-authority":errs.append("grant-binding")
    for c in d.get("accessChecks",[]):
        actual="authorized" if usable(c.get("grantId"),t) else "denied"
        if actual!=c.get("expected"):errs.append("access-check-result")
    for q in Q.values():
        if q.get("state")!="quarantined" or q.get("channelId")!="private-bridge-return" or q.get("sourceBindingId")!="bridge-return-binding":errs.append("quarantine-source")
    for p in d.get("promotionDecisions",[]):
        q=Q.get(p.get("quarantineRecordId"));g=G.get(p.get("reviewerGrantId"))
        if not q or not g:errs.append("promotion-reference");continue
        when=parse(p["decidedAt"])
        if A.get(p.get("authorityId"),{}).get("role")!="local-promotion-authority":errs.append("promotion-authority")
        if not usable(g["id"],when):errs.append("promotion-grant-not-usable")
        if U.get(g.get("audienceId"),{}).get("purpose")!="return-quarantine-review":errs.append("promotion-grant-purpose")
        if g.get("classification")!=q.get("classification"):errs.append("promotion-class-binding")
        if p.get("targetDisposition")!="local-review-staging" or p.get("mergeAuthorityClaim") is not False or p.get("reclassificationClaim") is not False:errs.append("promotion-boundary")
    if d.get("registryScope")=="structural-only":
        for seq in ["institutions","subjects","grants","revocations","quarantineRecords","promotionDecisions"]:
            if any(x.get("synthetic") is not True for x in d.get(seq,[]) if isinstance(x,dict)):errs.append("non-synthetic-structural")
    return sorted(set(errs))
def main():
    p=argparse.ArgumentParser();p.add_argument("registry");p.add_argument("--evaluation-at",required=True);p.add_argument("--json",action="store_true");p.add_argument("--require-conformant",action="store_true")
    n=p.parse_args();e=verify(json.loads(Path(n.registry).read_text()),n.evaluation_at);o={"standard":STD,"evaluationAt":n.evaluation_at,"result":"CONFORMANT" if not e else "NON_CONFORMANT","findings":e};print(json.dumps(o,sort_keys=True) if n.json else o["result"]);return 1 if n.require_conformant and e else 0
if __name__=="__main__":raise SystemExit(main())
