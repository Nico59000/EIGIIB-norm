#!/usr/bin/env python3
"""Static EIGIIB-E14-A3 correlation-control and consumption replay checker."""
from __future__ import annotations
import argparse,json,tomllib
from dataclasses import asdict,dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E14-A3-1.0"
A1_STANDARD="EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0+E14-1.0"
A2_STANDARD="EIGIIB-E14-A2-1.0"; PROFILE_STATES={"active","revoked","contested","unavailable"}; BUDGET_STATES={"active","exhausted","contested","unavailable"}; STATES={"committed","rejected","held","unavailable"}; MODES={"isolated","pairwise","declared-shared"}; A2_STATES={"permit","deny","held","unavailable"}

@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str

class Checker:
 def __init__(self,root:Path,registry:Path=Path("conformance/correlation-control.json"),projection_registry:Path=Path("conformance/confidential-evidence.json"),authorization_registry:Path=Path("conformance/disclosure-authorization.json")):
  self.root=root.resolve();self.registry_path=registry;self.projection_registry_path=projection_registry;self.authorization_registry_path=authorization_registry;self.findings=[]
  self.records={};self.projections={};self.audiences={};self.auth_requests={};self.auth_decisions={};self.profiles={};self.budgets={};self.requests={};self.consumptions={};self.valid_requests=set();self.valid_consumptions=set();self.derived={}
 @staticmethod
 def ne(v):return isinstance(v,str) and bool(v)
 @staticmethod
 def integer(v,n=0):return isinstance(v,int) and not isinstance(v,bool) and v>=n
 def add(self,s,c,m,p=""):self.findings.append(Finding(s,c,p,m))
 def bad(self,p):return any(f.severity=="error" and (f.path==p or f.path.startswith(p+".")) for f in self.findings)
 def confined(self,rel,code,must=False):
  if not self.ne(rel) or Path(rel).is_absolute():self.add("error",f"{code}.PATH","path must be non-empty and repository-relative",str(rel));return None
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
   p=f"{k}[{i}]"
   if not isinstance(x,dict):self.add("error",f"{code}.ITEM","item must be an object",p);continue
   ident=x.get("id")
   if not self.ne(ident):self.add("error",f"{code}.ID","id must be non-empty",p);continue
   if ident in out:self.add("error",f"{code}.DUPLICATE",f"duplicate id {ident}",p);continue
   out[ident]=x
  return out
 def sl(self,v,p,code,empty=False):
  if not isinstance(v,list) or (not empty and not v) or any(not self.ne(x) for x in v) or len(v)!=len(set(v)):self.add("error",code,"must be a unique array of non-empty strings",p);return []
  return v
 def profile(self):
  try:o=tomllib.loads((self.root/"EIGIIB.toml").read_text(encoding="utf-8"))
  except Exception as e:self.add("error","E14A3.PROFILE.PARSE",str(e),"EIGIIB.toml");return
  if "E14-1.0" not in o.get("extensions",[]):self.add("error","E14A3.PROFILE.ADOPTION","E14-1.0 must be adopted","EIGIIB.toml")
  if o.get("revision") not in {"EIGIIB-E14-draft-1.0","EIGIIB-E14-1.0"}:self.add("error","E14A3.PROFILE.REVISION","revision must be an E14 1.0 draft or final revision","EIGIIB.toml")
  exp={"confidential_evidence":"conformance/confidential-evidence.json","disclosure_authorization":"conformance/disclosure-authorization.json","e14_a3_contract":"extensions/E14-A3-CORRELATION-CONTROL-SINGLE-USE-LINKABILITY-REPLAY.md","correlation_control":"conformance/correlation-control.json","e14_a3_human_mastery":"docs/E14-A3-HUMAN-MASTERY-GUIDE.md"};auth=o.get("authorities",{});req=o.get("required_authorities",[])
  for k,v in exp.items():
   if not isinstance(auth,dict) or auth.get(k)!=v:self.add("error","E14A3.PROFILE.AUTHORITY",f"authority {k} must bind {v}","EIGIIB.toml")
   else:self.confined(v,"E14A3.PROFILE",True)
   if not isinstance(req,list) or k not in req:self.add("error","E14A3.PROFILE.REQUIRED",f"required authority missing: {k}","EIGIIB.toml")
  gs=o.get("manual_gates",[]);ms=[g for g in gs if isinstance(g,dict) and g.get("id")=="e14-a3-correlation-control-boundary-review"] if isinstance(gs,list) else [];exact=("complete","e14_a3_contract","conformance/E14-A3-MANUAL-REVIEW.md")
  if len(ms)!=1:self.add("error","E14A3.PROFILE.GATE","E14-A3 manual gate missing or duplicated","EIGIIB.toml")
  elif (ms[0].get("status"),ms[0].get("authority"),ms[0].get("attestation"))!=exact:self.add("error","E14A3.PROFILE.GATE","E14-A3 manual gate is not exact","EIGIIB.toml")
  else:self.confined(ms[0]["attestation"],"E14A3.PROFILE",True)
 def a1(self,o):
  p=str(self.projection_registry_path)
  if o.get("standard")!=A1_STANDARD:self.add("error","E14A3.A1.STANDARD","unexpected E14-A1 registry standard",p)
  self.records=self.index(o,"records","E14A3.A1.RECORD");self.projections=self.index(o,"projections","E14A3.A1.PROJECTION")
  for ident,x in self.records.items():
   p=f"record:{ident}"
   for k in ("revision","subject"):
    if not self.ne(x.get(k)):self.add("error","E14A3.A1.RECORD.FIELD",f"{k} must be non-empty",p)
   c=x.get("commitment")
   if not isinstance(c,dict) or c.get("algorithm")!="sha256" or not self.ne(c.get("digest")):self.add("error","E14A3.A1.RECORD.COMMITMENT","record commitment is missing",p)
  for ident,x in self.projections.items():
   p=f"projection:{ident}"
   for k in ("revision","source_record","source_revision","source_commitment"):
    if not self.ne(x.get(k)):self.add("error","E14A3.A1.PROJECTION.FIELD",f"{k} must be non-empty",p)
   if x.get("state") not in {"prepared","sealed"}:self.add("error","E14A3.A1.PROJECTION.STATE","unsupported projection state",p)
   c=x.get("commitment")
   if not isinstance(c,dict) or c.get("algorithm")!="sha256" or not self.ne(c.get("digest")):self.add("error","E14A3.A1.PROJECTION.COMMITMENT","projection commitment is missing",p)
   self.sl(x.get("correlation_controls"),p,"E14A3.A1.PROJECTION.CONTROLS")
 def a2(self,o):
  p=str(self.authorization_registry_path)
  if o.get("standard")!=A2_STANDARD:self.add("error","E14A3.A2.STANDARD","unexpected E14-A2 registry standard",p)
  if o.get("upstream_registry")!=str(self.projection_registry_path):self.add("error","E14A3.A2.UPSTREAM","E14-A2 upstream path mismatch",p)
  self.audiences=self.index(o,"audiences","E14A3.A2.AUDIENCE");self.auth_requests=self.index(o,"requests","E14A3.A2.REQUEST");self.auth_decisions=self.index(o,"decisions","E14A3.A2.DECISION")
  for ident,x in self.audiences.items():
   if not self.ne(x.get("revision")):self.add("error","E14A3.A2.AUDIENCE.REVISION","revision must be non-empty",f"audience:{ident}")
  for ident,x in self.auth_requests.items():
   p=f"authorization-request:{ident}"
   for k in ("revision","projection","projection_revision","projection_commitment","source_record","source_revision","source_commitment","audience","audience_revision","purpose","operation"):
    if not self.ne(x.get(k)):self.add("error","E14A3.A2.REQUEST.FIELD",f"{k} must be non-empty",p)
  for ident,x in self.auth_decisions.items():
   p=f"authorization-decision:{ident}"
   if not self.ne(x.get("request")) or not self.ne(x.get("request_revision")):self.add("error","E14A3.A2.DECISION.REQUEST","decision request binding is missing",p)
   if x.get("state") not in A2_STATES:self.add("error","E14A3.A2.DECISION.STATE","unsupported authorization decision state",p)
 def objects(self):
  for ident,x in self.profiles.items():
   p=f"profile:{ident}"
   if not self.ne(x.get("revision")):self.add("error","E14A3.CONTROL.REVISION","revision must be non-empty",p)
   if x.get("state") not in PROFILE_STATES:self.add("error","E14A3.CONTROL.STATE","unsupported profile state",p)
   self.sl(x.get("required_controls"),p,"E14A3.CONTROL.REQUIRED");mode=x.get("linkability_mode")
   if mode not in MODES:self.add("error","E14A3.CONTROL.MODE","unsupported linkability mode",p)
   for k in ("max_uses_per_projection","max_uses_per_source_record"):
    if not self.integer(x.get(k),1):self.add("error","E14A3.CONTROL.BUDGET",f"{k} must be integer >= 1",p)
   for k in ("require_distinct_operation_nonce","allow_cross_audience_linkage","allow_cross_purpose_linkage"):
    if not isinstance(x.get(k),bool):self.add("error","E14A3.CONTROL.BOOLEAN",f"{k} must be boolean",p)
   ds=self.sl(x.get("allowed_shared_domains"),p,"E14A3.CONTROL.DOMAINS",True)
   if mode=="declared-shared" and not ds:self.add("error","E14A3.CONTROL.DOMAINS","declared-shared mode requires a domain",p)
   if mode in {"isolated","pairwise"} and ds:self.add("error","E14A3.CONTROL.DOMAINS","non-shared mode forbids declared domains",p)
  for ident,x in self.budgets.items():
   p=f"budget:{ident}"
   for k in ("revision","profile","profile_revision","source_record","source_revision","source_commitment","audience","audience_revision","purpose","linkability_domain"):
    if not self.ne(x.get(k)):self.add("error","E14A3.BUDGET.FIELD",f"{k} must be non-empty",p)
   if x.get("state") not in BUDGET_STATES:self.add("error","E14A3.BUDGET.STATE","unsupported budget state",p)
   if not self.integer(x.get("max_uses"),1):self.add("error","E14A3.BUDGET.MAX","max_uses must be integer >= 1",p)
   y=self.profiles.get(x.get("profile"));r=self.records.get(x.get("source_record"));a=self.audiences.get(x.get("audience"))
   if y is None:self.add("error","E14A3.BUDGET.PROFILE","profile does not resolve",p)
   else:
    if x.get("profile_revision")!=y.get("revision"):self.add("error","E14A3.BUDGET.PROFILE_REVISION","profile revision is stale",p)
    if self.integer(x.get("max_uses"),1) and self.integer(y.get("max_uses_per_source_record"),1) and x["max_uses"]>y["max_uses_per_source_record"]:self.add("error","E14A3.BUDGET.PROFILE_LIMIT","budget exceeds profile source limit",p)
    if y.get("linkability_mode")=="declared-shared" and x.get("linkability_domain") not in y.get("allowed_shared_domains",[]):self.add("error","E14A3.BUDGET.DOMAIN","domain is not declared by profile",p)
   if r is None:self.add("error","E14A3.BUDGET.RECORD","source record does not resolve",p)
   else:
    if x.get("source_revision")!=r.get("revision"):self.add("error","E14A3.BUDGET.RECORD_REVISION","source revision is stale",p)
    if x.get("source_commitment")!=r.get("commitment",{}).get("digest"):self.add("error","E14A3.BUDGET.RECORD_COMMITMENT","source commitment mismatch",p)
   if a is None:self.add("error","E14A3.BUDGET.AUDIENCE","audience does not resolve",p)
   elif x.get("audience_revision")!=a.get("revision"):self.add("error","E14A3.BUDGET.AUDIENCE_REVISION","audience revision is stale",p)
 def check_requests(self):
  for ident,x in self.requests.items():
   p=f"request:{ident}"
   fields=("revision","authorization_decision","authorization_request","authorization_request_revision","projection","projection_revision","projection_commitment","source_record","source_revision","source_commitment","audience","audience_revision","purpose","operation","control_profile","control_profile_revision","budget","budget_revision","linkability_domain","operation_nonce")
   for k in fields:
    if not self.ne(x.get(k)):self.add("error","E14A3.REQUEST.FIELD",f"{k} must be non-empty",p)
   d=self.auth_decisions.get(x.get("authorization_decision"));q=self.auth_requests.get(x.get("authorization_request"));z=self.projections.get(x.get("projection"));r=self.records.get(x.get("source_record"));c=self.profiles.get(x.get("control_profile"));b=self.budgets.get(x.get("budget"))
   for o,code,name in ((d,"DECISION","authorization decision"),(q,"AUTH_REQUEST","authorization request"),(z,"PROJECTION","projection"),(r,"RECORD","source record"),(c,"PROFILE","control profile"),(b,"BUDGET","budget")):
    if o is None:self.add("error",f"E14A3.REQUEST.{code}",f"{name} does not resolve",p)
   if d and q:
    if d.get("request")!=x.get("authorization_request"):self.add("error","E14A3.REQUEST.DECISION_BINDING","decision references another request",p)
    if d.get("request_revision")!=q.get("revision"):self.add("error","E14A3.REQUEST.DECISION_REVISION","decision request revision is stale",p)
    if x.get("authorization_request_revision")!=q.get("revision"):self.add("error","E14A3.REQUEST.AUTH_REVISION","authorization request revision is stale",p)
   if q:
    for k in ("projection","projection_revision","projection_commitment","source_record","source_revision","source_commitment","audience","audience_revision","purpose","operation"):
     if x.get(k)!=q.get(k):self.add("error","E14A3.REQUEST.AUTH_BINDING",f"{k} differs from authorization request",p)
   if z:
    if x.get("projection_revision")!=z.get("revision"):self.add("error","E14A3.REQUEST.PROJECTION_REVISION","projection revision is stale",p)
    if x.get("projection_commitment")!=z.get("commitment",{}).get("digest"):self.add("error","E14A3.REQUEST.PROJECTION_COMMITMENT","projection commitment mismatch",p)
    if any(x.get(k)!=z.get(k) for k in ("source_record","source_revision","source_commitment")):self.add("error","E14A3.REQUEST.PROJECTION_SOURCE","projection source binding mismatch",p)
   if r:
    if x.get("source_revision")!=r.get("revision"):self.add("error","E14A3.REQUEST.RECORD_REVISION","source revision is stale",p)
    if x.get("source_commitment")!=r.get("commitment",{}).get("digest"):self.add("error","E14A3.REQUEST.RECORD_COMMITMENT","source commitment mismatch",p)
   if c:
    if x.get("control_profile_revision")!=c.get("revision"):self.add("error","E14A3.REQUEST.PROFILE_REVISION","profile revision is stale",p)
    if z and not set(c.get("required_controls",[]))<=set(z.get("correlation_controls",[])):self.add("error","E14A3.REQUEST.CONTROLS","projection lacks required controls",p)
   if b:
    if x.get("budget_revision")!=b.get("revision"):self.add("error","E14A3.REQUEST.BUDGET_REVISION","budget revision is stale",p)
    for k in ("source_record","source_revision","source_commitment","audience","audience_revision","purpose","linkability_domain"):
     if x.get(k)!=b.get(k):self.add("error","E14A3.REQUEST.BUDGET_BINDING",f"{k} differs from budget",p)
    if x.get("control_profile")!=b.get("profile") or x.get("control_profile_revision")!=b.get("profile_revision"):self.add("error","E14A3.REQUEST.BUDGET_PROFILE","budget profile mismatch",p)
   if not self.bad(p):self.valid_requests.add(ident)
 @staticmethod
 def base_state(d,p,b):
  if d.get("state")=="deny" or p.get("state")=="revoked" or b.get("state")=="exhausted":return "rejected"
  if d.get("state")=="held" or p.get("state")=="contested" or b.get("state")=="contested":return "held"
  if d.get("state")=="unavailable" or p.get("state")=="unavailable" or b.get("state")=="unavailable":return "unavailable"
  return None
 @staticmethod
 def link_conflict(x,p,done):
  same=[i["request"] for i in done if i["request"].get("linkability_domain")==x.get("linkability_domain")];mode=p.get("linkability_mode")
  if mode=="isolated":return any(i.get("projection")!=x.get("projection") for i in same)
  if mode=="pairwise":return any((i.get("source_record"),i.get("audience"),i.get("purpose"))!=(x.get("source_record"),x.get("audience"),x.get("purpose")) for i in same)
  if mode=="declared-shared":return any((i.get("audience")!=x.get("audience") and not p.get("allow_cross_audience_linkage")) or (i.get("purpose")!=x.get("purpose") and not p.get("allow_cross_purpose_linkage")) for i in same)
  return False
 def check_consumptions(self):
  per={};seqs={};done=[];ordered=sorted(self.consumptions.items(),key=lambda i:(self.requests.get(i[1].get("enforcement_request"),{}).get("budget",""),i[1].get("sequence",-1) if self.integer(i[1].get("sequence"),1) else -1,i[0]))
  for ident,x in ordered:
   p=f"consumption:{ident}";rid=x.get("enforcement_request");r=self.requests.get(rid);per[rid]=per.get(rid,0)+1
   if not self.ne(x.get("revision")):self.add("error","E14A3.CONSUMPTION.REVISION","revision must be non-empty",p)
   if r is None:self.add("error","E14A3.CONSUMPTION.REQUEST","request does not resolve",p);continue
   if rid not in self.valid_requests:self.add("error","E14A3.CONSUMPTION.REQUEST_INVALID","request is structurally invalid",p);continue
   if x.get("enforcement_request_revision")!=r.get("revision"):self.add("error","E14A3.CONSUMPTION.REQUEST_REVISION","request revision is stale",p)
   if x.get("state") not in STATES:self.add("error","E14A3.CONSUMPTION.STATE","unsupported state",p)
   if not self.integer(x.get("sequence"),1):self.add("error","E14A3.CONSUMPTION.SEQUENCE","sequence must be integer >= 1",p)
   reasons=self.sl(x.get("reasons"),p,"E14A3.CONSUMPTION.REASONS");evidence=self.sl(x.get("evidence"),p,"E14A3.CONSUMPTION.EVIDENCE",True);d=self.auth_decisions[r["authorization_decision"]];c=self.profiles[r["control_profile"]];b=self.budgets[r["budget"]];expected=self.base_state(d,c,b);rr=[]
   if expected is None:
    if c.get("require_distinct_operation_nonce") and any(i["request"].get("operation_nonce")==r.get("operation_nonce") for i in done):rr.append("operation-nonce-replay")
    if sum(i["request"].get("projection")==r.get("projection") for i in done)>=c.get("max_uses_per_projection",0):rr.append("projection-budget-exhausted")
    if sum(i["request"].get("source_record")==r.get("source_record") for i in done)>=c.get("max_uses_per_source_record",0):rr.append("source-record-budget-exhausted")
    if sum(i["request"].get("budget")==r.get("budget") for i in done)>=b.get("max_uses",0):rr.append("budget-exhausted")
    if self.link_conflict(r,c,done):rr.append("linkability-domain-conflict")
    expected="rejected" if rr else "committed"
   if x.get("state")!=expected:self.add("error","E14A3.CONSUMPTION.DERIVATION",f"state must be {expected}",p)
   if expected in {"committed","rejected"} and not evidence:self.add("error","E14A3.CONSUMPTION.MATERIAL_EVIDENCE","committed and rejected require evidence",p)
   if not reasons:self.add("error","E14A3.CONSUMPTION.REASON","at least one reason is required",p)
   if rr and not set(rr)<=set(reasons):self.add("error","E14A3.CONSUMPTION.REPLAY_REASON","replay reasons are incomplete",p)
   if self.integer(x.get("sequence"),1):seqs.setdefault(r.get("budget"),[]).append(x["sequence"])
   self.derived[ident]={"state":expected,"replay_reasons":rr}
   if not self.bad(p):
    self.valid_consumptions.add(ident)
    if expected=="committed":done.append({"id":ident,"request":r})
  for rid,n in per.items():
   if rid is not None and n>1:self.add("error","E14A3.CONSUMPTION.DUPLICATE","more than one consumption exists for one request",f"request:{rid}")
  for bid,xs in seqs.items():
   if sorted(xs)!=list(range(1,len(xs)+1)):self.add("error","E14A3.CONSUMPTION.SEQUENCE_GAP","budget sequences must be unique and contiguous from 1",f"budget:{bid}")
 def run(self):
  self.profile();a1=self.load(self.projection_registry_path,"E14A3.A1");a2=self.load(self.authorization_registry_path,"E14A3.A2");reg=self.load(self.registry_path,"E14A3.REGISTRY")
  if a1:self.a1(a1)
  if a2:self.a2(a2)
  if reg:
   if reg.get("standard")!=STANDARD:self.add("error","E14A3.REGISTRY.STANDARD","unexpected registry standard",str(self.registry_path))
   if reg.get("status")!="structural-only":self.add("error","E14A3.REGISTRY.STATUS","registry must be structural-only",str(self.registry_path))
   if reg.get("upstream_projection_registry")!=str(self.projection_registry_path):self.add("error","E14A3.REGISTRY.A1","projection registry path mismatch",str(self.registry_path))
   if reg.get("upstream_authorization_registry")!=str(self.authorization_registry_path):self.add("error","E14A3.REGISTRY.A2","authorization registry path mismatch",str(self.registry_path))
   self.profiles=self.index(reg,"control_profiles","E14A3.CONTROL");self.budgets=self.index(reg,"budgets","E14A3.BUDGET");self.requests=self.index(reg,"enforcement_requests","E14A3.REQUEST");self.consumptions=self.index(reg,"consumptions","E14A3.CONSUMPTION");self.objects()
   if a1 and a2:self.check_requests();self.check_consumptions()
  errors=any(f.severity=="error" for f in self.findings);up=any(f.severity=="error" and f.code.startswith(("E14A3.A1","E14A3.A2")) for f in self.findings);states=[x.get("state") for x in self.derived.values()];result="not-evaluated" if not self.consumptions else ("conformant" if len(self.valid_consumptions)==len(self.consumptions) and not errors else "non-conformant")
  return {"tool":"eigiib-correlation-control-check","tool_version":TOOL_VERSION,"standard":STANDARD,"structural_result":"non-conformant" if errors else "conformant","upstream_binding_result":"non-conformant" if up else "conformant","correlation_control_result":result,"single_use_result":result,"cross_projection_linkability_result":result,"control_profile_count":len(self.profiles),"budget_count":len(self.budgets),"enforcement_request_count":len(self.requests),"consumption_count":len(self.consumptions),"consumption_counts":{s:states.count(s) for s in sorted(STATES)},"findings":[asdict(f) for f in sorted(self.findings)]}

def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--registry",default="conformance/correlation-control.json");p.add_argument("--projection-registry",default="conformance/confidential-evidence.json");p.add_argument("--authorization-registry",default="conformance/disclosure-authorization.json");p.add_argument("--json",action="store_true");a=p.parse_args(argv);r=Checker(Path(a.root),Path(a.registry),Path(a.projection_registry),Path(a.authorization_registry)).run();print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["structural_result"]=="conformant" else 1
if __name__=="__main__":raise SystemExit(main())
