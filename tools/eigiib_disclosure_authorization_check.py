#!/usr/bin/env python3
"""Static EIGIIB-E14-A2 disclosure authorization checker."""
from __future__ import annotations
import argparse, json, tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E14-A2-1.0"
UPSTREAM_STANDARD="EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0+E14-1.0"
ACTION="eigiib:e14:disclose-projection"
CLASSIFICATIONS={"restricted","confidential","highly-confidential"}
DECISION_STATES={"permit","deny","held","unavailable"}

@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str

class Checker:
    def __init__(self,root:Path,registry:Path=Path("conformance/disclosure-authorization.json"),upstream:Path=Path("conformance/confidential-evidence.json")):
        self.root=root.resolve(); self.registry_path=registry; self.upstream_path=upstream
        self.findings:list[Finding]=[]; self.records={}; self.projections={}; self.audiences={}; self.policies={}; self.contexts={}; self.requests={}; self.decisions={}
        self.valid_requests:set[str]=set(); self.valid_decisions:set[str]=set(); self.derived={}
    @staticmethod
    def ne(v): return isinstance(v,str) and bool(v)
    def add(self,s,c,m,p=""): self.findings.append(Finding(s,c,p,m))
    def bad(self,p): return any(f.severity=="error" and (f.path==p or f.path.startswith(p+".")) for f in self.findings)
    def confined(self,rel,code,must=False):
        if not self.ne(rel) or Path(rel).is_absolute(): self.add("error",f"{code}.PATH","path must be non-empty and repository-relative",str(rel)); return None
        p=(self.root/rel).resolve(strict=False)
        try:p.relative_to(self.root)
        except ValueError:self.add("error",f"{code}.PATH","path escapes repository root",rel);return None
        if must and not p.is_file():self.add("error",f"{code}.MISSING","referenced file is missing",rel);return None
        return p
    def load(self,rel,code):
        p=self.confined(str(rel),code,True)
        if p is None:return None
        try:o=json.loads(p.read_text(encoding="utf-8"),parse_constant=lambda x:(_ for _ in()).throw(ValueError(x)))
        except Exception as e:self.add("error",f"{code}.PARSE",str(e),str(rel));return None
        if not isinstance(o,dict):self.add("error",f"{code}.TYPE","JSON root must be an object",str(rel));return None
        return o
    def index(self,o,k,code):
        xs=o.get(k)
        if not isinstance(xs,list):self.add("error",f"{code}.TYPE",f"{k} must be an array",k);return {}
        out={}
        for i,x in enumerate(xs):
            loc=f"{k}[{i}]"
            if not isinstance(x,dict):self.add("error",f"{code}.ITEM","item must be an object",loc);continue
            ident=x.get("id")
            if not self.ne(ident):self.add("error",f"{code}.ID","id must be a non-empty string",loc);continue
            if ident in out:self.add("error",f"{code}.DUPLICATE",f"duplicate id {ident}",loc);continue
            out[ident]=x
        return out
    def sl(self,v,loc,code,empty=False,allowed=None):
        if not isinstance(v,list) or (not empty and not v) or any(not self.ne(x) for x in v) or len(v)!=len(set(v)):
            self.add("error",code,"must be a unique array of non-empty strings",loc);return []
        if allowed is not None and any(x not in allowed for x in v):self.add("error",code,"array contains unsupported value",loc)
        return v
    def profile(self):
        try:p=tomllib.loads((self.root/"EIGIIB.toml").read_text(encoding="utf-8"))
        except Exception as e:self.add("error","E14A2.PROFILE.PARSE",str(e),"EIGIIB.toml");return
        if "E14-1.0" not in p.get("extensions",[]):self.add("error","E14A2.PROFILE.ADOPTION","E14-1.0 must be adopted","EIGIIB.toml")
        if p.get("revision") not in {"EIGIIB-E14-draft-1.0","EIGIIB-E14-1.0"}:self.add("error","E14A2.PROFILE.REVISION","revision must be an E14 1.0 draft or final revision","EIGIIB.toml")
        exp={"confidential_evidence":"conformance/confidential-evidence.json","e14_a2_contract":"extensions/E14-A2-DISCLOSURE-AUTHORIZATION-AUDIENCE-ELIGIBILITY-CONTEXT-REVALIDATION.md","disclosure_authorization":"conformance/disclosure-authorization.json","e14_a2_human_mastery":"docs/E14-A2-HUMAN-MASTERY-GUIDE.md"}
        auth=p.get("authorities",{}); req=p.get("required_authorities",[])
        for k,v in exp.items():
            if not isinstance(auth,dict) or auth.get(k)!=v:self.add("error","E14A2.PROFILE.AUTHORITY",f"authority {k} must bind {v}","EIGIIB.toml")
            else:self.confined(v,"E14A2.PROFILE",True)
            if not isinstance(req,list) or k not in req:self.add("error","E14A2.PROFILE.REQUIRED",f"required authority missing: {k}","EIGIIB.toml")
        gs=p.get("manual_gates",[]); ms=[g for g in gs if isinstance(g,dict) and g.get("id")=="e14-a2-disclosure-authorization-boundary-review"] if isinstance(gs,list) else []
        exact=("complete","e14_a2_contract","conformance/E14-A2-MANUAL-REVIEW.md")
        if len(ms)!=1:self.add("error","E14A2.PROFILE.GATE","E14-A2 manual gate missing or duplicated","EIGIIB.toml")
        elif (ms[0].get("status"),ms[0].get("authority"),ms[0].get("attestation"))!=exact:self.add("error","E14A2.PROFILE.GATE","E14-A2 manual gate is not exact","EIGIIB.toml")
        else:self.confined(ms[0]["attestation"],"E14A2.PROFILE",True)
    def upstream(self,o):
        loc=str(self.upstream_path)
        if o.get("standard")!=UPSTREAM_STANDARD:self.add("error","E14A2.UPSTREAM.STANDARD","unexpected E14-A1 registry standard",loc)
        self.records=self.index(o,"records","E14A2.UPSTREAM.RECORD"); self.projections=self.index(o,"projections","E14A2.UPSTREAM.PROJECTION")
        for rid,r in self.records.items():
            p=f"upstream-record:{rid}"
            for k in ("revision","subject"):
                if not self.ne(r.get(k)):self.add("error","E14A2.UPSTREAM.RECORD.FIELD",f"{k} must be non-empty",p)
            if r.get("classification") not in CLASSIFICATIONS:self.add("error","E14A2.UPSTREAM.RECORD.CLASSIFICATION","unsupported classification",p)
            if r.get("revocation_state") not in {"active","revoked","withdrawn","unavailable"}:self.add("error","E14A2.UPSTREAM.RECORD.REVOCATION","unsupported revocation state",p)
            c=r.get("commitment")
            if not isinstance(c,dict) or c.get("algorithm")!="sha256" or not self.ne(c.get("digest")):self.add("error","E14A2.UPSTREAM.RECORD.COMMITMENT","record commitment is missing",p)
        for pid,q in self.projections.items():
            p=f"upstream-projection:{pid}"
            for k in ("revision","source_record","source_revision","source_commitment"):
                if not self.ne(q.get(k)):self.add("error","E14A2.UPSTREAM.PROJECTION.FIELD",f"{k} must be non-empty",p)
            if q.get("state") not in {"prepared","sealed"}:self.add("error","E14A2.UPSTREAM.PROJECTION.STATE","unsupported projection state",p)
            c=q.get("commitment")
            if not isinstance(c,dict) or c.get("algorithm")!="sha256" or not self.ne(c.get("digest")):self.add("error","E14A2.UPSTREAM.PROJECTION.COMMITMENT","projection commitment is missing",p)
            for k in ("authorized_audience","disclosure_policy","evaluation_context"):
                v=q.get(k)
                if not isinstance(v,dict) or not self.ne(v.get("id")) or not self.ne(v.get("revision")):self.add("error","E14A2.UPSTREAM.PROJECTION.BINDING",f"{k} identity is missing",p)
            self.sl(q.get("correlation_controls"),p,"E14A2.UPSTREAM.PROJECTION.CORRELATION")
            if not isinstance(q.get("claims"),list):self.add("error","E14A2.UPSTREAM.PROJECTION.CLAIMS","claims must be an array",p)
    def objects(self):
        for aid,a in self.audiences.items():
            p=f"audience:{aid}"
            if not self.ne(a.get("revision")):self.add("error","E14A2.AUDIENCE.REVISION","revision must be non-empty",p)
            if a.get("state") not in {"active","retired","contested","unavailable"}:self.add("error","E14A2.AUDIENCE.STATE","unsupported audience state",p)
            self.sl(a.get("subjects"),p,"E14A2.AUDIENCE.SUBJECTS"); self.sl(a.get("classifications"),p,"E14A2.AUDIENCE.CLASSIFICATIONS",allowed=CLASSIFICATIONS); self.sl(a.get("purposes"),p,"E14A2.AUDIENCE.PURPOSES")
            if not self.ne(a.get("required_authentication")):self.add("error","E14A2.AUDIENCE.AUTHENTICATION","required_authentication must be non-empty",p)
        for pid,a in self.policies.items():
            p=f"policy:{pid}"
            if not self.ne(a.get("revision")):self.add("error","E14A2.POLICY.REVISION","revision must be non-empty",p)
            if a.get("state") not in {"active","revoked","contested","unavailable"}:self.add("error","E14A2.POLICY.STATE","unsupported policy state",p)
            for k,c in (("allowed_audiences","AUDIENCES"),("allowed_purposes","PURPOSES"),("allowed_claim_types","CLAIM_TYPES"),("allowed_predicates","PREDICATES")):self.sl(a.get(k),p,f"E14A2.POLICY.{c}")
            self.sl(a.get("allowed_classifications"),p,"E14A2.POLICY.CLASSIFICATIONS",allowed=CLASSIFICATIONS); self.sl(a.get("required_correlation_controls"),p,"E14A2.POLICY.CORRELATION",empty=True)
            m=a.get("max_assurance"); n=a.get("max_claims")
            if not isinstance(m,int) or isinstance(m,bool) or not 0<=m<=4:self.add("error","E14A2.POLICY.ASSURANCE","max_assurance must be integer 0..4",p)
            if not isinstance(n,int) or isinstance(n,bool) or n<0:self.add("error","E14A2.POLICY.CLAIM_COUNT","max_claims must be a non-negative integer",p)
            if not isinstance(a.get("allow_empty_projection"),bool):self.add("error","E14A2.POLICY.EMPTY","allow_empty_projection must be boolean",p)
        for cid,a in self.contexts.items():
            p=f"context:{cid}"
            for k in ("revision","purpose","operation","subject"):
                if not self.ne(a.get(k)):self.add("error","E14A2.CONTEXT.FIELD",f"{k} must be non-empty",p)
            if a.get("state") not in {"active","closed","contested","unavailable"}:self.add("error","E14A2.CONTEXT.STATE","unsupported context state",p)
            if a.get("action")!=ACTION:self.add("error","E14A2.CONTEXT.ACTION",f"action must be {ACTION}",p)
    def check_requests(self):
        for rid,r in self.requests.items():
            p=f"request:{rid}"
            for k in ("revision","projection","projection_revision","projection_commitment","source_record","source_revision","source_commitment","audience","audience_revision","policy","policy_revision","context","context_revision","purpose","operation"):
                if not self.ne(r.get(k)):self.add("error","E14A2.REQUEST.FIELD",f"{k} must be non-empty",p)
            if r.get("action")!=ACTION:self.add("error","E14A2.REQUEST.ACTION",f"action must be {ACTION}",p)
            q=self.projections.get(r.get("projection")); s=self.records.get(r.get("source_record")); a=self.audiences.get(r.get("audience")); y=self.policies.get(r.get("policy")); c=self.contexts.get(r.get("context"))
            for obj,code,msg in ((q,"PROJECTION","projection"),(s,"RECORD","source record"),(a,"AUDIENCE","audience"),(y,"POLICY","policy"),(c,"CONTEXT","context")):
                if obj is None:self.add("error",f"E14A2.REQUEST.{code}",f"{msg} does not resolve",p)
            if q:
                if r.get("projection_revision")!=q.get("revision"):self.add("error","E14A2.REQUEST.PROJECTION_REVISION","projection revision is stale",p)
                if r.get("projection_commitment")!=q.get("commitment",{}).get("digest"):self.add("error","E14A2.REQUEST.PROJECTION_COMMITMENT","projection commitment mismatch",p)
                for k in ("source_record","source_revision","source_commitment"):
                    if r.get(k)!=q.get(k):self.add("error",f"E14A2.REQUEST.{k.upper()}",f"request {k} differs from projection",p)
                for rk,qk in (("audience","authorized_audience"),("policy","disclosure_policy"),("context","evaluation_context")):
                    v=q.get(qk,{})
                    if r.get(rk)!=v.get("id") or r.get(rk+"_revision")!=v.get("revision"):self.add("error","E14A2.REQUEST.PROJECTION_BINDING",f"{rk} differs from sealed projection binding",p)
            if s:
                if r.get("source_revision")!=s.get("revision"):self.add("error","E14A2.REQUEST.RECORD_REVISION","source record revision is stale",p)
                if r.get("source_commitment")!=s.get("commitment",{}).get("digest"):self.add("error","E14A2.REQUEST.RECORD_COMMITMENT","source record commitment mismatch",p)
            for obj,k,code in ((a,"audience","AUDIENCE"),(y,"policy","POLICY"),(c,"context","CONTEXT")):
                if obj and r.get(k+"_revision")!=obj.get("revision"):self.add("error",f"E14A2.REQUEST.{code}_REVISION",f"{k} revision is stale",p)
            if not self.bad(p):self.valid_requests.add(rid)
    @staticmethod
    def projection_result(q,s):
        z=s.get("revocation_state")
        if z in {"revoked","withdrawn"}:return "denied"
        if z=="unavailable":return "unavailable"
        return "admissible" if q.get("state")=="sealed" else "held"
    @staticmethod
    def audience_result(a,s,r):
        z=a.get("state")
        if z=="retired":return "ineligible"
        if z=="contested":return "held"
        if z=="unavailable":return "unavailable"
        ok=s.get("subject") in a.get("subjects",[]) and s.get("classification") in a.get("classifications",[]) and r.get("purpose") in a.get("purposes",[])
        return "eligible" if ok else "ineligible"
    @staticmethod
    def policy_result(a,q,s,r):
        z=a.get("state")
        if z=="revoked":return "deny"
        if z=="contested":return "held"
        if z=="unavailable":return "unavailable"
        cs=q.get("claims",[]) if isinstance(q.get("claims"),list) else []
        ok=r.get("audience") in a.get("allowed_audiences",[]) and s.get("classification") in a.get("allowed_classifications",[]) and r.get("purpose") in a.get("allowed_purposes",[]) and len(cs)<=a.get("max_claims",-1) and (bool(cs) or a.get("allow_empty_projection") is True) and set(a.get("required_correlation_controls",[]))<=set(q.get("correlation_controls",[]))
        for x in cs:
            ok=ok and isinstance(x,dict) and x.get("type") in a.get("allowed_claim_types",[]) and x.get("predicate") in a.get("allowed_predicates",[]) and isinstance(x.get("assurance"),int) and not isinstance(x.get("assurance"),bool) and x.get("assurance")<=a.get("max_assurance",-1)
        return "permit" if ok else "deny"
    @staticmethod
    def context_result(a,s,r):
        z=a.get("state")
        if z=="closed":return "inadmissible"
        if z=="contested":return "held"
        if z=="unavailable":return "unavailable"
        ok=a.get("purpose")==r.get("purpose") and a.get("action")==r.get("action") and a.get("operation")==r.get("operation") and a.get("subject")==s.get("subject")
        return "admissible" if ok else "inadmissible"
    @staticmethod
    def final(rs):
        if any(v in {"denied","ineligible","deny","inadmissible"} for v in rs.values()):return "deny"
        if "unavailable" in rs.values():return "unavailable"
        if "held" in rs.values():return "held"
        return "permit"
    def check_decisions(self):
        per={}
        for did,d in self.decisions.items():
            p=f"decision:{did}"; rid=d.get("request"); r=self.requests.get(rid); per[rid]=per.get(rid,0)+1
            if r is None:self.add("error","E14A2.DECISION.REQUEST","request does not resolve",p);continue
            if rid not in self.valid_requests:self.add("error","E14A2.DECISION.REQUEST_INVALID","request boundary is structurally invalid",p);continue
            if d.get("request_revision")!=r.get("revision"):self.add("error","E14A2.DECISION.REQUEST_REVISION","request revision is stale",p)
            if d.get("state") not in DECISION_STATES:self.add("error","E14A2.DECISION.STATE","unsupported decision state",p)
            if not self.ne(d.get("evaluator")):self.add("error","E14A2.DECISION.EVALUATOR","evaluator must be non-empty",p)
            reasons=self.sl(d.get("reasons"),p,"E14A2.DECISION.REASONS"); evidence=self.sl(d.get("evidence"),p,"E14A2.DECISION.EVIDENCE",empty=True)
            q=self.projections[r["projection"]]; s=self.records[r["source_record"]]
            rs={"projection_result":self.projection_result(q,s),"audience_result":self.audience_result(self.audiences[r["audience"]],s,r),"policy_result":self.policy_result(self.policies[r["policy"]],q,s,r),"context_result":self.context_result(self.contexts[r["context"]],s,r)}; state=self.final(rs)
            for k,v in rs.items():
                if d.get(k)!=v:self.add("error","E14A2.DECISION.COMPONENT",f"{k} must be {v}",p)
            if d.get("state")!=state:self.add("error","E14A2.DECISION.DERIVATION",f"decision state must be {state}",p)
            if state in {"permit","deny"} and not evidence:self.add("error","E14A2.DECISION.MATERIAL_EVIDENCE","permit and deny require material evidence",p)
            if not reasons:self.add("error","E14A2.DECISION.REASON","at least one reason is required",p)
            self.derived[did]={**rs,"state":state}
            if not self.bad(p):self.valid_decisions.add(did)
        for rid,n in per.items():
            if n>1:self.add("error","E14A2.DECISION.DUPLICATE","more than one decision exists for one request",f"request:{rid}")
    def run(self):
        self.profile(); up=self.load(self.upstream_path,"E14A2.UPSTREAM"); reg=self.load(self.registry_path,"E14A2.REGISTRY")
        if up:self.upstream(up)
        if reg:
            if reg.get("standard")!=STANDARD:self.add("error","E14A2.REGISTRY.STANDARD","unexpected registry standard",str(self.registry_path))
            if reg.get("status")!="structural-only":self.add("error","E14A2.REGISTRY.STATUS","registry must be structural-only",str(self.registry_path))
            if reg.get("upstream_registry")!=str(self.upstream_path):self.add("error","E14A2.REGISTRY.UPSTREAM","upstream registry path mismatch",str(self.registry_path))
            self.audiences=self.index(reg,"audiences","E14A2.AUDIENCE"); self.policies=self.index(reg,"disclosure_policies","E14A2.POLICY"); self.contexts=self.index(reg,"evaluation_contexts","E14A2.CONTEXT"); self.requests=self.index(reg,"requests","E14A2.REQUEST"); self.decisions=self.index(reg,"decisions","E14A2.DECISION")
            self.objects()
            if up:self.check_requests();self.check_decisions()
        errors=any(f.severity=="error" for f in self.findings); ar="not-evaluated" if not self.decisions else ("conformant" if len(self.valid_decisions)==len(self.decisions) and not errors else "non-conformant")
        states=[x.get("state") for x in self.derived.values()]; comp="not-evaluated" if not self.decisions else ar; ue=any(f.severity=="error" and f.code.startswith("E14A2.UPSTREAM") for f in self.findings)
        return {"tool":"eigiib-disclosure-authorization-check","tool_version":TOOL_VERSION,"standard":STANDARD,"structural_result":"non-conformant" if errors else "conformant","upstream_binding_result":"non-conformant" if ue else "conformant","authorization_result":ar,"audience_eligibility_result":comp,"policy_evaluation_result":comp,"context_revalidation_result":comp,"request_count":len(self.requests),"decision_count":len(self.decisions),"decision_counts":{s:states.count(s) for s in sorted(DECISION_STATES)},"findings":[asdict(f) for f in sorted(self.findings)]}

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--registry",default="conformance/disclosure-authorization.json");p.add_argument("--upstream",default="conformance/confidential-evidence.json");p.add_argument("--json",action="store_true");a=p.parse_args(argv)
    r=Checker(Path(a.root),Path(a.registry),Path(a.upstream)).run();print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["structural_result"]=="conformant" else 1
if __name__=="__main__":raise SystemExit(main())
