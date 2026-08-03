#!/usr/bin/env python3
"""Static EIGIIB-E16-A1 preservation-intent and replica-binding checker."""
from __future__ import annotations
import argparse, hashlib, json, re, tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E16-A1-1.0"; TRANSITION_STANDARD="EIGIIB-E16-A1-TRANSITION-1.0"; FREEZE_STANDARD="EIGIIB-E16-A1-FREEZE-1.0"; HISTORY_STANDARD="EIGIIB-E16-A1-HISTORICAL-M0-A7-REPLAY-1.0"; PROFILE_REVISION="EIGIIB-E16-draft-1.0"; SOURCE_E15_HEAD="036b81c3c128524858d66d096a1eb87e23cc5dad"; SOURCE_M0_A7_HEAD="ae189e1c478c523789f11e4424395be154e8521d"; ACTION="eigiib:e16:preserve"; HEX64=re.compile(r"^[0-9a-f]{64}$")
GATES={"permit","deny","held","unavailable"}; DECISIONS={"admissible","rejected","held","unavailable"}; PROFILE_STATES={"active","retired","contested","unavailable"}; BINDING_STATES={"bound","rejected","held","unavailable"}
EXPECTED_FREEZE_PATHS={
 ".github/workflows/e16-a1-preservation-intent.yml",".github/workflows/eigiib.yml","EIGIIB.toml","conformance/E16-A1-MANUAL-REVIEW.md","conformance/M0-A7-MANUAL-REVIEW.md","conformance/e16-a1-adoption-transition.json","conformance/extension-graph.json","conformance/m0-a7-e16-entry.json","conformance/preservation-intent.json","docs/E16-A1-HUMAN-MASTERY-GUIDE.md","docs/M0-A7-E16-NORMATIVE-ENTRY-NORMALIZATION-AND-E15-AUTHORITY-CONTINUITY.md","docs/M0-A7-HUMAN-MASTERY-GUIDE.md","extensions/E16-EXTERNAL-CUSTODY-REPLICATION-RETENTION-RECOVERY-GOVERNANCE.md","schemas/eigiib-e16-a1-adoption-transition.schema.json","schemas/eigiib-e16-a1-authority-freeze.schema.json","schemas/eigiib-e16-a1-preservation-intent.schema.json","schemas/eigiib-m0-a7-e16-entry.schema.json","tests/fixtures/e16-a1/expected-report.json","tests/test_eigiib_e15_final_closure.py","tests/test_eigiib_m0_a7.py","tests/test_eigiib_preservation_intent.py","tests/test_eigiib_publication_readback.py","tests/test_eigiib_withdrawal_governance.py","tools/eigiib_extension_graph_check.py","tools/eigiib_historical_m0_a7_replay.py","tools/eigiib_m0_a7_check.py","tools/eigiib_preservation_intent_check.py"}
@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str
def canonical(value:Any)->bytes: return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()
def commitment_for(value:dict[str,Any])->str: return hashlib.sha256(canonical({k:v for k,v in value.items() if k!="commitment"})).hexdigest()
def combine(values:list[str])->str:
    if "deny" in values:return "deny"
    if "unavailable" in values:return "unavailable"
    if "held" in values:return "held"
    return "permit"
def derive(gates:dict[str,str])->str:
    value=combine(list(gates.values())); return {"deny":"rejected","unavailable":"unavailable","held":"held","permit":"admissible"}[value]
class Checker:
 def __init__(self,root:Path,registry=Path("conformance/preservation-intent.json"),transition=Path("conformance/e16-a1-adoption-transition.json"),freeze=Path("conformance/e16-a1-authority-freeze.json"),history_report:Path|None=None):
  self.root=root.resolve(); self.registry_path=registry; self.transition_path=transition; self.freeze_path=freeze; self.history_report_path=history_report; self.findings:list[Finding]=[]; self.custodians={};self.replicas={};self.policies={};self.intents={};self.bindings={};self.decisions={};self.publications={};self.lifecycle={};self.valid=set();self.states={}
 def add(self,code,msg,path=""): self.findings.append(Finding("error",code,path,msg))
 def nonempty(self,v): return isinstance(v,str) and bool(v)
 def confined(self,rel:str,must=True):
  if not self.nonempty(rel) or Path(rel).is_absolute(): self.add("E16A1.PATH","path must be repository-relative",str(rel)); return None
  p=(self.root/rel).resolve(strict=False)
  try:p.relative_to(self.root)
  except ValueError:self.add("E16A1.PATH","path escapes repository root",rel);return None
  if must and not p.is_file():self.add("E16A1.MISSING","required file is missing",rel);return None
  return p
 def load(self,rel:Path,code:str):
  p=self.confined(rel.as_posix())
  if not p:return None
  try:v=json.loads(p.read_text(encoding="utf-8"))
  except Exception as e:self.add(code+".PARSE",str(e),rel.as_posix());return None
  if not isinstance(v,dict):self.add(code+".TYPE","JSON root must be object",rel.as_posix());return None
  return v
 def index(self,obj,field,code):
  values=obj.get(field);out={}
  if not isinstance(values,list):self.add(code+".TYPE",field+" must be array",field);return out
  for i,v in enumerate(values):
   path=f"{field}[{i}]"
   if not isinstance(v,dict) or not self.nonempty(v.get("id")):self.add(code+".ITEM","item requires id",path);continue
   if v["id"] in out:self.add(code+".DUP","duplicate id",path);continue
   out[v["id"]]=v
  return out
 def liststr(self,v,path,allow_empty=False):
  if not isinstance(v,list) or (not allow_empty and not v) or any(not self.nonempty(x) for x in v) or len(v)!=len(set(v)):self.add("E16A1.LIST","must be unique non-empty strings",path);return []
  return v
 def check_commit(self,v,path):
  c=v.get("commitment")
  if not isinstance(c,dict) or c.get("algorithm")!="sha256" or c.get("digest")!=commitment_for(v):self.add("E16A1.COMMITMENT","invalid canonical commitment",path)
 def state_gate(self,state): return "permit" if state=="active" else "deny" if state=="retired" else "held" if state=="contested" else "unavailable"
 def check_profile(self):
  try:p=tomllib.loads((self.root/"EIGIIB.toml").read_text())
  except Exception as e:self.add("E16A1.PROFILE.PARSE",str(e),"EIGIIB.toml");return
  if "E16-1.0" not in p.get("extensions",[]):self.add("E16A1.PROFILE.ADOPTION","E16-1.0 must be adopted","EIGIIB.toml")
  if p.get("revision")!=PROFILE_REVISION:self.add("E16A1.PROFILE.REVISION","unexpected profile revision","EIGIIB.toml")
  expected={"m0_a7_e16_entry":"conformance/m0-a7-e16-entry.json","m0_a7_human_mastery":"docs/M0-A7-HUMAN-MASTERY-GUIDE.md","e16":"extensions/E16-EXTERNAL-CUSTODY-REPLICATION-RETENTION-RECOVERY-GOVERNANCE.md","preservation_intent":self.registry_path.as_posix(),"e16_a1_transition":self.transition_path.as_posix(),"e16_a1_authority_freeze":self.freeze_path.as_posix(),"e16_a1_human_mastery":"docs/E16-A1-HUMAN-MASTERY-GUIDE.md"}
  auth=p.get("authorities",{});req=p.get("required_authorities",[])
  for k,v in expected.items():
   if not isinstance(auth,dict) or auth.get(k)!=v:self.add("E16A1.PROFILE.AUTHORITY",f"{k} must bind {v}","EIGIIB.toml")
   elif not self.confined(v):pass
   if k not in req:self.add("E16A1.PROFILE.REQUIRED",f"missing {k}","EIGIIB.toml")
  gates=p.get("manual_gates",[])
  for gid,authority,att in [("m0-a7-e16-entry-normalization-review","m0_a7_e16_entry","conformance/M0-A7-MANUAL-REVIEW.md"),("e16-a1-preservation-intent-boundary-review","e16","conformance/E16-A1-MANUAL-REVIEW.md")]:
   m=[x for x in gates if isinstance(x,dict) and x.get("id")==gid]
   if len(m)!=1 or (m[0].get("status"),m[0].get("authority"),m[0].get("attestation"))!=("complete",authority,att):self.add("E16A1.PROFILE.GATE",gid+" gate invalid","EIGIIB.toml")
 def check_history(self):
  if self.history_report_path is None:self.add("E16A1.HISTORY.MISSING","historical M0-A7 report required");return "non-conformant"
  h=self.load(self.history_report_path,"E16A1.HISTORY")
  if not h:return "non-conformant"
  if h.get("standard")!=HISTORY_STANDARD or h.get("source_commit")!=SOURCE_M0_A7_HEAD or h.get("overall_result")!="conformant":self.add("E16A1.HISTORY.RESULT","historical report is not conformant",self.history_report_path.as_posix())
  for k in ("e15_history_result","e15_final_closure_result","m0_a7_result","m0_a7_tests_result"):
   if h.get(k)!="conformant":self.add("E16A1.HISTORY.COMPONENT",k+" is not conformant",self.history_report_path.as_posix())
  return "non-conformant" if any(f.code.startswith("E16A1.HISTORY") for f in self.findings) else "conformant"
 def check_transition(self,t):
  if not t:return
  if t.get("standard")!=TRANSITION_STANDARD or t.get("status")!="adopted-e16-a1":self.add("E16A1.TRANSITION.HEADER","transition header invalid",self.transition_path.as_posix())
  s=t.get("source",{});target=t.get("target",{})
  if s.get("head_commit")!=SOURCE_M0_A7_HEAD or s.get("e15_final_head_commit")!=SOURCE_E15_HEAD:self.add("E16A1.TRANSITION.SOURCE","transition source changed",self.transition_path.as_posix())
  if target.get("extension")!="E16-1.0" or target.get("slice")!="E16-A1":self.add("E16A1.TRANSITION.TARGET","transition target invalid",self.transition_path.as_posix())
  hp=t.get("historical_preservation",{})
  if hp!={"e15_claims_rewritten":False,"e15_source_freeze_mutated":False,"m0_a7_source_mutated":False,"transition_is_additive":True,"descendant_profile_frozen_separately":True}:self.add("E16A1.TRANSITION.PRESERVATION","historical preservation contract changed",self.transition_path.as_posix())
 def check_graph(self):
  g=self.load(Path("conformance/extension-graph.json"),"E16A1.GRAPH")
  if not g:return
  m=[x for x in g.get("nodes",[]) if isinstance(x,dict) and x.get("id")=="E16"]
  if len(m)!=1 or m[0].get("checker")!="tools/eigiib_preservation_intent_check.py" or "E15" not in m[0].get("depends_on",[]):self.add("E16A1.GRAPH.NODE","E16 graph node invalid","conformance/extension-graph.json")
 def load_upstream(self):
  closure=self.load(Path("conformance/e15-final-closure.json"),"E16A1.UPSTREAM.CLOSURE")
  if closure and (closure.get("final_state")!="closed" or closure.get("profile_revision")!="EIGIIB-E15-1.0"):self.add("E16A1.UPSTREAM.CLOSURE","E15 final closure invalid","conformance/e15-final-closure.json")
  p=self.load(Path("conformance/publication-readback.json"),"E16A1.UPSTREAM.PUBLICATION")
  if p:
   self.publications=self.index(p,"external_publication_records","E16A1.UPSTREAM.PUBLICATION")
   self.lifecycle=self.index(p,"publication_lifecycle_decisions","E16A1.UPSTREAM.LIFECYCLE")
 def validate_profiles(self):
  for ident,v in self.custodians.items():
   path=f"custodian_profiles[{ident}]";self.check_commit(v,path)
   if not self.nonempty(v.get("revision")) or v.get("state") not in PROFILE_STATES:self.add("E16A1.CUSTODIAN.SHAPE","invalid custodian revision or state",path)
   for f in ("principal_id","service_boundary"):
    if not self.nonempty(v.get(f)):self.add("E16A1.CUSTODIAN.FIELD",f+" required",path)
   self.liststr(v.get("authority_scope"),path+".authority_scope");self.liststr(v.get("allowed_replica_kinds"),path+".allowed_replica_kinds")
  for ident,v in self.replicas.items():
   path=f"replica_profiles[{ident}]";self.check_commit(v,path)
   if not self.nonempty(v.get("revision")) or v.get("state") not in PROFILE_STATES:self.add("E16A1.REPLICA.SHAPE","invalid replica revision or state",path)
   for f in ("custodian","custodian_revision","kind","locator_class","provider_id","account_id","region_id","implementation_id","storage_class"):
    if not self.nonempty(v.get(f)):self.add("E16A1.REPLICA.FIELD",f+" required",path)
   self.liststr(v.get("content_algorithms"),path+".content_algorithms");self.liststr(v.get("properties"),path+".properties")
   c=self.custodians.get(str(v.get("custodian")))
   if c is None or c.get("revision")!=v.get("custodian_revision") or v.get("kind") not in (c.get("allowed_replica_kinds") if c else []):self.add("E16A1.REPLICA.CUSTODIAN","replica custodian binding invalid",path)
  for ident,v in self.policies.items():
   path=f"preservation_policies[{ident}]";self.check_commit(v,path)
   if not self.nonempty(v.get("revision")) or v.get("state") not in PROFILE_STATES or not isinstance(v.get("max_payload_bytes"),int) or v.get("max_payload_bytes")<0:self.add("E16A1.POLICY.SHAPE","invalid policy",path)
   for f in ("allowed_custodians","allowed_replicas","allowed_purposes","allowed_actions","required_replica_properties"):self.liststr(v.get(f),path+"."+f)
 def validate_intents(self):
  keys={}
  for ident,v in self.intents.items():
   path=f"preservation_intents[{ident}]";self.check_commit(v,path)
   for f in ("revision","source_publication","source_publication_revision","source_publication_commitment","source_lifecycle_decision","source_lifecycle_decision_revision","source_lifecycle_decision_commitment","source_closure","source_closure_revision","custodian","custodian_revision","replica","replica_revision","policy","policy_revision","purpose","action","idempotency_key","content_sha256"):
    if not self.nonempty(v.get(f)):self.add("E16A1.INTENT.FIELD",f+" required",path)
   if not HEX64.fullmatch(str(v.get("source_publication_commitment",""))) or not HEX64.fullmatch(str(v.get("source_lifecycle_decision_commitment",""))) or not HEX64.fullmatch(str(v.get("content_sha256",""))):self.add("E16A1.INTENT.DIGEST","invalid SHA-256",path)
   if not isinstance(v.get("content_bytes"),int) or v.get("content_bytes")<0:self.add("E16A1.INTENT.BYTES","content_bytes invalid",path)
   self.liststr(v.get("requested_replica_properties"),path+".requested_replica_properties")
   key=v.get("idempotency_key")
   if key in keys:self.add("E16A1.INTENT.IDEMPOTENCY",f"key already used by {keys[key]}",path)
   keys[key]=ident
   pub=self.publications.get(str(v.get("source_publication")));life=self.lifecycle.get(str(v.get("source_lifecycle_decision")));c=self.custodians.get(str(v.get("custodian")));r=self.replicas.get(str(v.get("replica")));p=self.policies.get(str(v.get("policy")))
   source="permit"
   if v.get("source_closure")!="conformance/e15-final-closure.json" or v.get("source_closure_revision")!="EIGIIB-E15-1.0":source="deny"
   elif pub is None or pub.get("revision")!=v.get("source_publication_revision") or pub.get("publication_state")!="positive" or pub.get("observed_event")!="published":source="deny"
   elif (pub.get("commitment") or {}).get("digest")!=v.get("source_publication_commitment") or pub.get("payload_sha256")!=v.get("content_sha256") or pub.get("payload_bytes")!=v.get("content_bytes"):source="deny"
   if life is None or life.get("revision")!=v.get("source_lifecycle_decision_revision") or life.get("publication")!=v.get("source_publication") or life.get("lifecycle_state") not in {"publication-observed","persistence-observed","independently-read-back"}:source="deny"
   elif (life.get("commitment") or {}).get("digest")!=v.get("source_lifecycle_decision_commitment"):source="deny"
   cg="deny" if c is None or c.get("revision")!=v.get("custodian_revision") else self.state_gate(c.get("state"));rg="deny" if r is None or r.get("revision")!=v.get("replica_revision") else self.state_gate(r.get("state"));pg="deny" if p is None or p.get("revision")!=v.get("policy_revision") else self.state_gate(p.get("state"))
   if p:
    if v.get("custodian") not in p.get("allowed_custodians",[]) or v.get("replica") not in p.get("allowed_replicas",[]) or v.get("purpose") not in p.get("allowed_purposes",[]) or v.get("action") not in p.get("allowed_actions",[]) or v.get("content_bytes",0)>p.get("max_payload_bytes",-1):pg="deny"
    if r and any(x not in r.get("properties",[]) for x in p.get("required_replica_properties",[])):pg="deny"
   self.states[ident]={"source_result":source,"custodian_result":cg,"replica_result":rg,"policy_result":pg,"idempotency_result":"deny" if any(f.code=="E16A1.INTENT.IDEMPOTENCY" and f.path==path for f in self.findings) else "permit","content_identity_result":source}
 def validate_bindings_decisions(self):
  used=set(); seen_intents=set()
  for ident,b in self.bindings.items():
   path=f"replica_bindings[{ident}]";self.check_commit(b,path)
   i=self.intents.get(str(b.get("intent")));c=self.custodians.get(str(b.get("custodian")));r=self.replicas.get(str(b.get("replica")))
   gate="permit"
   if i is None or i.get("revision")!=b.get("intent_revision") or c is None or c.get("revision")!=b.get("custodian_revision") or r is None or r.get("revision")!=b.get("replica_revision"):gate="deny"
   elif (b.get("content_sha256"),b.get("content_bytes"),b.get("custodian"),b.get("replica"))!=(i.get("content_sha256"),i.get("content_bytes"),i.get("custodian"),i.get("replica")):gate="deny"
   expected={"permit":"bound","deny":"rejected","held":"held","unavailable":"unavailable"}[gate]
   if b.get("state")!=expected or not isinstance(b.get("sequence"),int) or b.get("sequence")<1:self.add("E16A1.BINDING.STATE",f"binding must be {expected}",path)
   self.liststr(b.get("evidence_refs"),path+".evidence_refs");self.states.setdefault(str(b.get("intent")),{})["binding_result"]=gate
  for ident,d in self.decisions.items():
   path=f"preservation_decisions[{ident}]";self.check_commit(d,path);i=self.intents.get(str(d.get("intent")));b=self.bindings.get(str(d.get("binding")))
   if i is None or b is None or d.get("intent_revision")!=i.get("revision") or d.get("binding_revision")!=b.get("revision") or b.get("intent")!=d.get("intent"):self.add("E16A1.DECISION.BINDING","decision references invalid intent or binding",path);continue
   if d.get("intent") in seen_intents:self.add("E16A1.DECISION.DUPLICATE","intent has more than one decision",path)
   seen_intents.add(d.get("intent"));g=self.states.get(d.get("intent"),{});expected={k:g.get(k,"deny") for k in ("source_result","custodian_result","replica_result","policy_result","idempotency_result","content_identity_result")};expected["source_result"]=combine([expected["source_result"],g.get("binding_result","deny")])
   for k,v in expected.items():
    if d.get(k)!=v or d.get(k) not in GATES:self.add("E16A1.DECISION.GATE",f"{k} must be {v}",path)
   state=derive(expected)
   if d.get("state")!=state or d.get("state") not in DECISIONS:self.add("E16A1.DECISION.STATE",f"state must be {state}",path)
   self.liststr(d.get("reasons"),path+".reasons");self.liststr(d.get("evidence_refs"),path+".evidence_refs")
   if not any(f.path==path for f in self.findings):self.valid.add(ident);self.states[d.get("intent")]["decision_state"]=state
  for ident in set(self.intents)-seen_intents:self.add("E16A1.INTENT.UNDECIDED","intent has no decision",ident)
 def check_freeze(self,f):
  if not f:return "non-conformant"
  if f.get("standard")!=FREEZE_STANDARD or f.get("status")!="frozen" or f.get("profile_revision")!=PROFILE_REVISION:self.add("E16A1.FREEZE.HEADER","freeze header invalid",self.freeze_path.as_posix())
  src=f.get("source",{})
  if src.get("e15_head_commit")!=SOURCE_E15_HEAD or src.get("m0_a7_head_commit")!=SOURCE_M0_A7_HEAD:self.add("E16A1.FREEZE.SOURCE","freeze source invalid",self.freeze_path.as_posix())
  entries=f.get("authorities");idx={}
  if not isinstance(entries,list):self.add("E16A1.FREEZE.TYPE","authorities must be array",self.freeze_path.as_posix());return "non-conformant"
  for e in entries:
   if not isinstance(e,dict) or not self.nonempty(e.get("path")):self.add("E16A1.FREEZE.ITEM","invalid freeze entry");continue
   rel=e["path"]
   if rel in idx:self.add("E16A1.FREEZE.DUP","duplicate path",rel);continue
   idx[rel]=e;p=self.confined(rel)
   if p:
    raw=p.read_bytes()
    if e.get("bytes")!=len(raw):self.add("E16A1.FREEZE.BYTES","byte length changed",rel)
    if e.get("sha256")!=hashlib.sha256(raw).hexdigest():self.add("E16A1.FREEZE.DIGEST","digest changed",rel)
  for rel in EXPECTED_FREEZE_PATHS-set(idx):self.add("E16A1.FREEZE.MISSING","required path not frozen",rel)
  for rel in set(idx)-EXPECTED_FREEZE_PATHS:self.add("E16A1.FREEZE.EXTRA","unexpected frozen path",rel)
  return "non-conformant" if any(f.code.startswith("E16A1.FREEZE") for f in self.findings) else "conformant"
 def run(self):
  self.check_profile();history=self.check_history();self.check_transition(self.load(self.transition_path,"E16A1.TRANSITION"));self.check_graph();self.load_upstream();r=self.load(self.registry_path,"E16A1.REGISTRY");freeze=self.load(self.freeze_path,"E16A1.FREEZE")
  if r:
   if r.get("standard")!=STANDARD or r.get("status")!="structural-only" or r.get("source_e15_commit")!=SOURCE_E15_HEAD or r.get("source_m0_a7_commit")!=SOURCE_M0_A7_HEAD:self.add("E16A1.REGISTRY.HEADER","registry header invalid",self.registry_path.as_posix())
   self.custodians=self.index(r,"custodian_profiles","E16A1.CUSTODIAN");self.replicas=self.index(r,"replica_profiles","E16A1.REPLICA");self.policies=self.index(r,"preservation_policies","E16A1.POLICY");self.intents=self.index(r,"preservation_intents","E16A1.INTENT");self.bindings=self.index(r,"replica_bindings","E16A1.BINDING");self.decisions=self.index(r,"preservation_decisions","E16A1.DECISION");self.validate_profiles();self.validate_intents();self.validate_bindings_decisions()
  fr=self.check_freeze(freeze);errors=bool(self.findings);result="not-evaluated" if not self.intents else "conformant" if len(self.valid)==len(self.decisions)==len(self.intents) and not errors else "non-conformant";states=[x.get("decision_state") for x in self.states.values() if x.get("decision_state")]
  return {"tool":"eigiib-preservation-intent-check","tool_version":TOOL_VERSION,"standard":STANDARD,"structural_result":"non-conformant" if errors else "conformant","historical_continuity_result":history,"authority_freeze_result":fr,"preservation_intent_result":result,"custodian_profile_count":len(self.custodians),"replica_profile_count":len(self.replicas),"preservation_policy_count":len(self.policies),"preservation_intent_count":len(self.intents),"replica_binding_count":len(self.bindings),"preservation_decision_count":len(self.decisions),"decision_state_counts":{x:states.count(x) for x in sorted(DECISIONS)},"findings":[asdict(f) for f in sorted(self.findings)]}
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--registry",default="conformance/preservation-intent.json");p.add_argument("--transition",default="conformance/e16-a1-adoption-transition.json");p.add_argument("--freeze",default="conformance/e16-a1-authority-freeze.json");p.add_argument("--history-report");p.add_argument("--json",action="store_true");a=p.parse_args(argv);r=Checker(Path(a.root),Path(a.registry),Path(a.transition),Path(a.freeze),Path(a.history_report) if a.history_report else None).run();print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["structural_result"]=="conformant" else 1
if __name__=="__main__":raise SystemExit(main())
