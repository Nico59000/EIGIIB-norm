#!/usr/bin/env python3
"""Static EIGIIB-E14-A1 confidential-record and projection checker."""
from __future__ import annotations
import argparse, hashlib, json, tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION="0.1.0"
STANDARD="EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0+E14-1.0"
TRANSITION_STANDARD="EIGIIB-E14-A1-TRANSITION-1.0"
SOURCE_HEAD="a547e0f94af1b256200c12836a1539c4d5b28716"
EXPECTED_INPUTS=["authorized_audience","correlation_controls","cryptographic_commitment","disclosable_projection","disclosure_policy","evaluation_context","full_evidence_artifact","revocation_state"]
CLASSIFICATIONS={"restricted","confidential","highly-confidential"}
REVOCATION_STATES={"active","revoked","withdrawn","unavailable"}
PROJECTION_STATES={"prepared","sealed"}

@dataclass(order=True)
class Finding:
    severity:str; code:str; path:str; message:str

def canonical_bytes(value:Any)->bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()

def commitment_for(value:dict[str,Any])->str:
    return hashlib.sha256(canonical_bytes({k:v for k,v in value.items() if k!="commitment"})).hexdigest()

class Checker:
    def __init__(self,root:Path,registry:Path=Path("conformance/confidential-evidence.json"),transition:Path=Path("conformance/e14-a1-adoption-transition.json")):
        self.root=root.resolve(); self.registry_path=registry; self.transition_path=transition
        self.findings:list[Finding]=[]; self.records={}; self.projections={}; self.valid_records=set(); self.valid_projections=set()
    def add(self,s,c,m,p=""): self.findings.append(Finding(s,c,p,m))
    @staticmethod
    def nonempty(v): return isinstance(v,str) and bool(v)
    def bad_at(self,p): return any(f.severity=="error" and (f.path==p or f.path.startswith(p+".")) for f in self.findings)
    def confined(self,rel,code,must=False):
        if not self.nonempty(rel) or Path(rel).is_absolute(): self.add("error",f"{code}.PATH","path must be non-empty and repository-relative",str(rel)); return None
        p=(self.root/rel).resolve(strict=False)
        try: p.relative_to(self.root)
        except ValueError: self.add("error",f"{code}.PATH","path escapes repository root",rel); return None
        if must and not p.is_file(): self.add("error",f"{code}.MISSING","referenced file is missing",rel); return None
        return p
    def load(self,rel,code):
        p=self.confined(str(rel),code,True)
        if p is None:return None
        try: obj=json.loads(p.read_text(encoding="utf-8"),parse_constant=lambda x:(_ for _ in()).throw(ValueError(x)))
        except Exception as e:self.add("error",f"{code}.PARSE",str(e),str(rel));return None
        if not isinstance(obj,dict):self.add("error",f"{code}.TYPE","JSON root must be an object",str(rel));return None
        return obj
    def index(self,obj,field,code):
        xs=obj.get(field)
        if not isinstance(xs,list):self.add("error",f"{code}.TYPE",f"{field} must be an array",field);return {}
        out={}
        for i,x in enumerate(xs):
            loc=f"{field}[{i}]"
            if not isinstance(x,dict):self.add("error",f"{code}.ITEM","item must be an object",loc);continue
            ident=x.get("id")
            if not self.nonempty(ident):self.add("error",f"{code}.ID","id must be a non-empty string",loc);continue
            if ident in out:self.add("error",f"{code}.DUPLICATE",f"duplicate id {ident}",loc);continue
            out[ident]=x
        return out
    def string_list(self,v,loc,code,empty=False):
        if not isinstance(v,list) or (not empty and not v) or any(not self.nonempty(x) for x in v) or len(v)!=len(set(v)):
            self.add("error",code,"must be a unique array of non-empty strings",loc);return []
        return v
    def check_profile(self):
        try:p=tomllib.loads((self.root/"EIGIIB.toml").read_text(encoding="utf-8"))
        except Exception as e:self.add("error","E14.PROFILE.PARSE",str(e),"EIGIIB.toml");return
        if "E14-1.0" not in p.get("extensions",[]):self.add("error","E14.PROFILE.ADOPTION","E14-1.0 must be adopted","EIGIIB.toml")
        if p.get("revision")!="EIGIIB-E14-draft-1.0":self.add("error","E14.PROFILE.REVISION","revision must be EIGIIB-E14-draft-1.0","EIGIIB.toml")
        expected={"e14":"extensions/E14-CONFIDENTIAL-EVIDENCE-SELECTIVE-DISCLOSURE-INFORMATION-MINIMIZATION.md","confidential_evidence":"conformance/confidential-evidence.json","e14_a1_transition":"conformance/e14-a1-adoption-transition.json","e14_a1_human_mastery":"docs/E14-A1-HUMAN-MASTERY-GUIDE.md"}
        auth=p.get("authorities",{}); required=p.get("required_authorities",[])
        for k,v in expected.items():
            if not isinstance(auth,dict) or auth.get(k)!=v:self.add("error","E14.PROFILE.AUTHORITY",f"authority {k} must bind {v}","EIGIIB.toml")
            else:self.confined(v,"E14.PROFILE",True)
            if not isinstance(required,list) or k not in required:self.add("error","E14.PROFILE.REQUIRED",f"required authority missing: {k}","EIGIIB.toml")
        gs=p.get("manual_gates",[]); ms=[g for g in gs if isinstance(g,dict) and g.get("id")=="e14-a1-confidential-evidence-boundary-review"] if isinstance(gs,list) else []
        if len(ms)!=1:self.add("error","E14.PROFILE.GATE","E14-A1 manual gate missing or duplicated","EIGIIB.toml")
        elif (ms[0].get("status"),ms[0].get("authority"),ms[0].get("attestation"))!=("complete","e14","conformance/E14-A1-MANUAL-REVIEW.md"):self.add("error","E14.PROFILE.GATE","E14-A1 manual gate is not exact","EIGIIB.toml")
        else:self.confined(ms[0]["attestation"],"E14.PROFILE",True)
    def check_transition(self,t):
        loc=str(self.transition_path)
        if t.get("standard")!=TRANSITION_STANDARD:self.add("error","E14.TRANSITION.STANDARD","unexpected transition standard",loc)
        if t.get("status")!="adopted-e14-a1":self.add("error","E14.TRANSITION.STATUS","transition must be adopted-e14-a1",loc)
        s=t.get("source")
        if not isinstance(s,dict):self.add("error","E14.TRANSITION.SOURCE","source must be an object",loc)
        else:
            if s.get("head_commit")!=SOURCE_HEAD:self.add("error","E14.TRANSITION.HEAD","M0-A5-F1 source head mismatch",loc)
            for k,v in {"handoff_authority":"conformance/m0-a5-e14-handoff.json","freeze_authority":"conformance/m0-a5-f1-authority-freeze.json"}.items():
                if s.get(k)!=v:self.add("error","E14.TRANSITION.AUTHORITY",f"{k} mismatch",loc)
                else:self.confined(v,"E14.TRANSITION",True)
        target=t.get("target")
        if not isinstance(target,dict) or (target.get("extension"),target.get("slice"),target.get("adoption_state"))!=("E14-1.0","E14-A1","adopted"):self.add("error","E14.TRANSITION.TARGET","E14-A1 target adoption is not exact",loc)
        inputs=t.get("consumed_inputs")
        if not isinstance(inputs,dict) or list(inputs)!=EXPECTED_INPUTS:self.add("error","E14.TRANSITION.INPUTS","consumed input set or order mismatch",loc)
        elif any(not self.nonempty(x) for x in inputs.values()):self.add("error","E14.TRANSITION.INPUT","input mapping is empty",loc)
        h=t.get("historical_preservation")
        if not isinstance(h,dict) or h.get("m0_a5_report_rewritten") is not False or h.get("pre_adoption_finding_preserved") is not True:self.add("error","E14.TRANSITION.HISTORY","M0-A5 historical preservation is not explicit",loc)
    def check_claim(self,c,loc):
        for k in ("id","type","subject","predicate"):
            if not self.nonempty(c.get(k)):self.add("error","E14.RECORD.CLAIM.FIELD",f"{k} must be non-empty",loc)
        if "object" not in c:self.add("error","E14.RECORD.CLAIM.FIELD","object is required",loc)
        self.string_list(c.get("scope"),loc,"E14.RECORD.CLAIM.SCOPE")
        a=c.get("assurance")
        if not isinstance(a,int) or isinstance(a,bool) or not 0<=a<=4:self.add("error","E14.RECORD.CLAIM.ASSURANCE","assurance must be integer 0..4",loc)
        self.string_list(c.get("evidence"),loc,"E14.RECORD.CLAIM.EVIDENCE",True)
    def check_records(self):
        for rid,r in self.records.items():
            loc=f"record:{rid}"
            for k in ("revision","subject","source_authority"):
                if not self.nonempty(r.get(k)):self.add("error","E14.RECORD.FIELD",f"{k} must be non-empty",loc)
            if r.get("classification") not in CLASSIFICATIONS:self.add("error","E14.RECORD.CLASSIFICATION","unsupported classification",loc)
            if r.get("revocation_state") not in REVOCATION_STATES:self.add("error","E14.RECORD.REVOCATION","unsupported revocation state",loc)
            a=r.get("artifact")
            if not isinstance(a,dict):self.add("error","E14.RECORD.ARTIFACT","artifact must be an object",loc)
            else:
                p=self.confined(a.get("path"),"E14.RECORD.ARTIFACT",True)
                if a.get("algorithm")!="sha256":self.add("error","E14.RECORD.ARTIFACT.ALGORITHM","artifact algorithm must be sha256",loc)
                if p:
                    raw=p.read_bytes()
                    if a.get("bytes")!=len(raw):self.add("error","E14.RECORD.ARTIFACT.BYTES","artifact byte length mismatch",loc)
                    if a.get("digest")!=hashlib.sha256(raw).hexdigest():self.add("error","E14.RECORD.ARTIFACT.DIGEST","artifact digest mismatch",loc)
            cs=r.get("claims")
            if not isinstance(cs,list) or not cs:self.add("error","E14.RECORD.CLAIMS","claims must be a non-empty array",loc)
            else:
                seen=set()
                for i,c in enumerate(cs):
                    cl=f"{loc}.claims[{i}]"
                    if not isinstance(c,dict):self.add("error","E14.RECORD.CLAIM.TYPE","claim must be an object",cl);continue
                    if c.get("id") in seen:self.add("error","E14.RECORD.CLAIM.DUPLICATE","duplicate claim id",cl)
                    if isinstance(c.get("id"),str):seen.add(c["id"])
                    self.check_claim(c,cl)
            cm=r.get("commitment")
            if not isinstance(cm,dict) or cm.get("algorithm")!="sha256" or cm.get("digest")!=commitment_for(r):self.add("error","E14.RECORD.COMMITMENT","record commitment mismatch",loc)
            if not self.bad_at(loc):self.valid_records.add(rid)
    def check_projected_claim(self,c,s,loc):
        if any(c.get(k)!=s.get(k) for k in ("type","subject","predicate","object")):self.add("error","E14.PROJECTION.CLAIM.SEMANTIC_DRIFT","semantic field differs from source claim",loc)
        scope=self.string_list(c.get("scope"),loc,"E14.PROJECTION.CLAIM.SCOPE")
        if scope and not set(scope)<=set(s.get("scope",[])):self.add("error","E14.PROJECTION.CLAIM.SCOPE_BROADENED","projection scope exceeds source scope",loc)
        a=c.get("assurance")
        if not isinstance(a,int) or isinstance(a,bool) or a<0 or a>s.get("assurance",-1):self.add("error","E14.PROJECTION.CLAIM.ASSURANCE_STRENGTHENED","projection assurance exceeds source assurance",loc)
        ev=self.string_list(c.get("evidence"),loc,"E14.PROJECTION.CLAIM.EVIDENCE",True)
        if not set(ev)<=set(s.get("evidence",[])):self.add("error","E14.PROJECTION.CLAIM.EVIDENCE_ADDED","projection adds evidence",loc)
    def check_projections(self):
        for pid,p in self.projections.items():
            loc=f"projection:{pid}"
            for k in ("revision","source_record","source_revision","source_artifact_digest","source_commitment"):
                if not self.nonempty(p.get(k)):self.add("error","E14.PROJECTION.FIELD",f"{k} must be non-empty",loc)
            if p.get("state") not in PROJECTION_STATES:self.add("error","E14.PROJECTION.STATE","state must be prepared or sealed",loc)
            src=self.records.get(p.get("source_record"))
            if src is None:self.add("error","E14.PROJECTION.SOURCE","source record does not resolve",loc);continue
            if p.get("source_record") not in self.valid_records:self.add("error","E14.PROJECTION.SOURCE_INVALID","source record is not valid",loc)
            if src.get("revocation_state")!="active":self.add("error","E14.PROJECTION.SOURCE_REVOKED","projection cannot use non-active source",loc)
            if p.get("source_revision")!=src.get("revision"):self.add("error","E14.PROJECTION.SOURCE_REVISION","source revision mismatch",loc)
            if p.get("source_artifact_digest")!=src.get("artifact",{}).get("digest"):self.add("error","E14.PROJECTION.SOURCE_ARTIFACT","source artifact digest mismatch",loc)
            if p.get("source_commitment")!=src.get("commitment",{}).get("digest"):self.add("error","E14.PROJECTION.SOURCE_COMMITMENT","source commitment mismatch",loc)
            for k in ("authorized_audience","disclosure_policy","evaluation_context"):
                v=p.get(k)
                if not isinstance(v,dict) or not self.nonempty(v.get("id")) or not self.nonempty(v.get("revision")):self.add("error","E14.PROJECTION.BINDING",f"{k} requires id and revision",loc)
            self.string_list(p.get("correlation_controls"),loc,"E14.PROJECTION.CORRELATION")
            source_claims={c.get("id"):c for c in src.get("claims",[]) if isinstance(c,dict) and self.nonempty(c.get("id"))}
            cs=p.get("claims"); selected=set()
            if not isinstance(cs,list):self.add("error","E14.PROJECTION.CLAIMS","projection claims must be an array",loc);cs=[]
            for i,c in enumerate(cs):
                cl=f"{loc}.claims[{i}]"
                if not isinstance(c,dict):self.add("error","E14.PROJECTION.CLAIM.TYPE","projection claim must be an object",cl);continue
                sid=c.get("source_claim")
                if not self.nonempty(sid) or sid not in source_claims:self.add("error","E14.PROJECTION.CLAIM.SOURCE","source claim does not resolve",cl);continue
                if sid in selected:self.add("error","E14.PROJECTION.CLAIM.DUPLICATE","source claim projected more than once",cl)
                selected.add(sid);self.check_projected_claim(c,source_claims[sid],cl)
            omitted=self.string_list(p.get("omitted_claims"),loc,"E14.PROJECTION.OMITTED",True)
            if set(omitted)!=set(source_claims)-selected:self.add("error","E14.PROJECTION.OMISSION_ACCOUNTING","omitted_claims must exactly account for source claims",loc)
            cm=p.get("commitment")
            if not isinstance(cm,dict) or cm.get("algorithm")!="sha256" or cm.get("digest")!=commitment_for(p):self.add("error","E14.PROJECTION.COMMITMENT","projection commitment mismatch",loc)
            if not self.bad_at(loc):self.valid_projections.add(pid)
    def run(self):
        reg=self.load(self.registry_path,"E14.REGISTRY"); trans=self.load(self.transition_path,"E14.TRANSITION"); self.check_profile()
        if trans is not None:self.check_transition(trans)
        if reg is not None:
            if reg.get("standard")!=STANDARD:self.add("error","E14.REGISTRY.STANDARD","unexpected registry standard",str(self.registry_path))
            if reg.get("revision")!="EIGIIB-E14-draft-1.0":self.add("error","E14.REGISTRY.REVISION","unexpected registry revision",str(self.registry_path))
            if reg.get("status")!="structural-only":self.add("error","E14.REGISTRY.STATUS","registry must be structural-only",str(self.registry_path))
            self.records=self.index(reg,"records","E14.RECORD");self.projections=self.index(reg,"projections","E14.PROJECTION");self.check_records();self.check_projections()
        errors=any(f.severity=="error" for f in self.findings)
        rr="not-evaluated" if not self.records else ("conformant" if len(self.valid_records)==len(self.records) and not errors else "non-conformant")
        pr="not-evaluated" if not self.projections else ("conformant" if len(self.valid_projections)==len(self.projections) and not errors else "non-conformant")
        tr="non-conformant" if any(f.severity=="error" and f.code.startswith("E14.TRANSITION") for f in self.findings) else "conformant"
        return {"tool":"eigiib-confidential-evidence-check","tool_version":TOOL_VERSION,"standard":STANDARD,"structural_result":"non-conformant" if errors else "conformant","adoption_transition_result":tr,"confidential_record_result":rr,"projection_binding_result":pr,"claim_boundary_result":"not-evaluated" if not self.projections else pr,"record_count":len(self.records),"projection_count":len(self.projections),"findings":[asdict(f) for f in sorted(self.findings)]}

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--registry",default="conformance/confidential-evidence.json");p.add_argument("--transition",default="conformance/e14-a1-adoption-transition.json");p.add_argument("--json",action="store_true");a=p.parse_args(argv)
    r=Checker(Path(a.root),Path(a.registry),Path(a.transition)).run();print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["structural_result"]=="conformant" else 1
if __name__=="__main__":raise SystemExit(main())
