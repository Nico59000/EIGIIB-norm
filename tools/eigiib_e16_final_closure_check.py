#!/usr/bin/env python3
"""Evaluate the final E16-A5 preservation closure and authority freeze."""
from __future__ import annotations
import argparse, hashlib, json, tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E16-A5-CLOSURE-REPORT-1.0"; CLOSURE_STANDARD="EIGIIB-E16-A5-CLOSURE-1.0"; TRANSITION_STANDARD="EIGIIB-E16-A5-TRANSITION-1.0"; MANIFEST_STANDARD="EIGIIB-E16-A5-AUTHORITY-MANIFEST-1.0"; FREEZE_STANDARD="EIGIIB-E16-A5-FREEZE-1.0"; HISTORY_STANDARD="EIGIIB-E16-A5-HISTORICAL-E16-A4-REPLAY-1.0"; MATRIX_STANDARD="EIGIIB-E16-A5-MATRIX-REPORT-1.0"; PROFILE_REVISION="EIGIIB-E16-1.0"; SOURCE_COMMIT="b28fe74f829141232770155724620617bfb1241c"; EXPECTED_AUTHORITY_COUNT=95; EXPECTED_CASE_COUNT=20; EXPECTED_VERIFIER_COUNT=2
@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str
class Checker:
 def __init__(self,root:Path,history_report=Path("historical-e16-a4-report.json"),matrix_report=Path("e16-a5-matrix-report.json"),closure=Path("conformance/e16-final-closure.json"),transition=Path("conformance/e16-a5-adoption-transition.json"),manifest=Path("conformance/e16-a5-authority-manifest.json"),freeze=Path("conformance/e16-a5-authority-freeze.json")):
  self.root=root.resolve();self.history_path=history_report;self.matrix_path=matrix_report;self.closure_path=closure;self.transition_path=transition;self.manifest_path=manifest;self.freeze_path=freeze;self.findings=[]
 def add(self,code,msg,path=""): self.findings.append(Finding("error",code,path,msg))
 def confined(self,rel,must=True):
  if not isinstance(rel,str) or not rel or Path(rel).is_absolute(): self.add("E16A5.PATH","path must be repository-relative",str(rel));return None
  p=(self.root/rel).resolve(strict=False)
  try:p.relative_to(self.root)
  except ValueError:self.add("E16A5.PATH","path escapes repository root",rel);return None
  if must and not p.is_file():self.add("E16A5.MISSING","required file missing",rel);return None
  return p
 def load(self,path,code):
  p=self.confined(path.as_posix())
  if not p:return None
  try:v=json.loads(p.read_text(encoding="utf-8"))
  except Exception as e:self.add(code+".PARSE",str(e),path.as_posix());return None
  if not isinstance(v,dict):self.add(code+".TYPE","root must be object",path.as_posix());return None
  return v
 def check_history(self,h):
  ok=isinstance(h,dict) and h.get("standard")==HISTORY_STANDARD and h.get("source_commit")==SOURCE_COMMIT and h.get("overall_result")=="conformant" and all(h.get(k)=="conformant" for k in ("ancestry_result","e16_a3_history_result","e16_a4_result","e16_a4_tests_result"))
  if not ok:self.add("E16A5.HISTORY.RESULT","historical E16-A4 replay is not conformant",self.history_path.as_posix())
  return "conformant" if ok else "non-conformant"
 def check_matrix(self,m):
  ok=isinstance(m,dict) and m.get("standard")==MATRIX_STANDARD and m.get("overall_result")=="conformant" and m.get("differential_restore_result")=="conformant" and m.get("case_count")==EXPECTED_CASE_COUNT and m.get("matched_case_count")==EXPECTED_CASE_COUNT and m.get("verifier_count")==EXPECTED_VERIFIER_COUNT and m.get("verifier_source_distinct") is True and m.get("reports_byte_identical") is True
  if not ok:self.add("E16A5.MATRIX.RESULT","independent differential matrix is not conformant",self.matrix_path.as_posix())
  return "conformant" if ok else "non-conformant"
 def check_profile(self):
  try:p=tomllib.loads((self.root/"EIGIIB.toml").read_text(encoding="utf-8"))
  except Exception as e:self.add("E16A5.PROFILE.PARSE",str(e),"EIGIIB.toml");return
  if p.get("revision")!=PROFILE_REVISION:self.add("E16A5.PROFILE.REVISION","stable E16 profile revision required","EIGIIB.toml")
  if "E16-1.0" not in p.get("extensions",[]):self.add("E16A5.PROFILE.ADOPTION","E16-1.0 must remain adopted","EIGIIB.toml")
  expected={"e16_a5_contract":"extensions/E16-A5-INDEPENDENT-PRESERVATION-VERIFIER-MATRIX-DIFFERENTIAL-RESTORE-REPLAY-FINAL-FREEZE.md","e16_final_closure":self.closure_path.as_posix(),"e16_a5_verifier_matrix":"conformance/e16-a5-verifier-matrix.json","e16_a5_transition":self.transition_path.as_posix(),"e16_a5_authority_manifest":self.manifest_path.as_posix(),"e16_a5_authority_freeze":self.freeze_path.as_posix(),"e16_a5_human_mastery":"docs/E16-A5-HUMAN-MASTERY-GUIDE.md","e16_final_closure_report":"docs/E16-FINAL-CLOSURE-REPORT.md"}
  auth=p.get("authorities",{});req=p.get("required_authorities",[])
  for k,v in expected.items():
   if not isinstance(auth,dict) or auth.get(k)!=v:self.add("E16A5.PROFILE.AUTHORITY",f"{k} must bind {v}","EIGIIB.toml")
   if k not in req:self.add("E16A5.PROFILE.REQUIRED",f"missing {k}","EIGIIB.toml")
  gates=p.get("manual_gates",[]);m=[x for x in gates if isinstance(x,dict) and x.get("id")=="e16-a5-final-closure-review"]
  if len(m)!=1 or (m[0].get("status"),m[0].get("authority"),m[0].get("attestation"))!=("complete","e16_a5_contract","conformance/E16-A5-MANUAL-REVIEW.md"):self.add("E16A5.PROFILE.GATE","final closure manual gate invalid","EIGIIB.toml")
 def check_transition(self,t):
  if not t:return
  if t.get("standard")!=TRANSITION_STANDARD or t.get("status")!="adopted-e16-a5-final":self.add("E16A5.TRANSITION.HEADER","transition header invalid",self.transition_path.as_posix())
  if t.get("source",{}).get("head_commit")!=SOURCE_COMMIT or t.get("target",{}).get("profile_revision")!=PROFILE_REVISION:self.add("E16A5.TRANSITION.BINDING","transition source or target changed",self.transition_path.as_posix())
  hp=t.get("historical_preservation",{})
  if hp!={"e16_a1_through_a4_claims_rewritten":False,"e16_a4_source_freeze_mutated":False,"transition_is_additive":True,"historical_slices_replayed_in_isolated_trees":True,"final_authority_frozen_separately":True}:self.add("E16A5.TRANSITION.PRESERVATION","historical preservation contract changed",self.transition_path.as_posix())
 def check_manifest(self,m):
  if not m:return
  if m.get("standard")!=MANIFEST_STANDARD or m.get("status")!="final-authority-manifest" or m.get("profile_revision")!=PROFILE_REVISION or m.get("source_e16_a4_commit")!=SOURCE_COMMIT:self.add("E16A5.MANIFEST.HEADER","authority manifest header invalid",self.manifest_path.as_posix())
  req=m.get("required_authorities");auth=m.get("authorities")
  if not isinstance(req,list) or not isinstance(auth,dict) or set(req)!=set(auth):self.add("E16A5.MANIFEST.SET","authority manifest key set invalid",self.manifest_path.as_posix());return
  for k in req:
   p=auth.get(k)
   if not isinstance(p,str) or not self.confined(p):self.add("E16A5.MANIFEST.AUTHORITY",f"invalid authority {k}",self.manifest_path.as_posix())
 def check_closure(self,c):
  if not c:return
  if c.get("standard")!=CLOSURE_STANDARD or c.get("status")!="final-frozen-closure" or c.get("final_state")!="closed" or c.get("profile_revision")!=PROFILE_REVISION or c.get("source_e16_a4_commit")!=SOURCE_COMMIT:self.add("E16A5.CLOSURE.HEADER","final closure header invalid",self.closure_path.as_posix())
  if (c.get("expected_case_count"),c.get("expected_verifier_count"),c.get("expected_authority_count"))!=(EXPECTED_CASE_COUNT,EXPECTED_VERIFIER_COUNT,EXPECTED_AUTHORITY_COUNT):self.add("E16A5.CLOSURE.COUNTS","final closure expected counts changed",self.closure_path.as_posix())
 def check_freeze(self,f):
  if not f:return "non-conformant",0
  if f.get("standard")!=FREEZE_STANDARD or f.get("status")!="final-frozen" or f.get("profile_revision")!=PROFILE_REVISION or f.get("source_e16_a4_commit")!=SOURCE_COMMIT:self.add("E16A5.FREEZE.HEADER","final freeze header invalid",self.freeze_path.as_posix())
  items=f.get("authorities")
  if not isinstance(items,list):self.add("E16A5.FREEZE.TYPE","authorities must be array",self.freeze_path.as_posix());return "non-conformant",0
  if len(items)!=EXPECTED_AUTHORITY_COUNT or f.get("authority_count")!=EXPECTED_AUTHORITY_COUNT:self.add("E16A5.FREEZE.COUNT",f"expected {EXPECTED_AUTHORITY_COUNT} authorities",self.freeze_path.as_posix())
  seen=set()
  for i,item in enumerate(items):
   path=f"authorities[{i}]"
   if not isinstance(item,dict) or not isinstance(item.get("path"),str):self.add("E16A5.FREEZE.ITEM","invalid freeze item",path);continue
   rel=item["path"]
   if rel in seen:self.add("E16A5.FREEZE.DUPLICATE","duplicate frozen path",rel);continue
   seen.add(rel);p=self.confined(rel)
   if not p:continue
   raw=p.read_bytes()
   if item.get("bytes")!=len(raw):self.add("E16A5.FREEZE.BYTES","byte count mismatch",rel)
   if item.get("sha256")!=hashlib.sha256(raw).hexdigest():self.add("E16A5.FREEZE.DIGEST","SHA-256 mismatch",rel)
  return ("non-conformant" if any(x.code.startswith("E16A5.FREEZE") for x in self.findings) else "conformant"),len(items)
 def check_graph(self):
  g=self.load(Path("conformance/extension-graph.json"),"E16A5.GRAPH")
  if not g:return
  nodes=[x for x in g.get("nodes",[]) if isinstance(x,dict) and x.get("id")=="E16"]
  if len(nodes)!=1 or nodes[0].get("checker")!="tools/eigiib_e16_final_closure_check.py" or nodes[0].get("registry")!="conformance/e16-final-closure.json" or "E16-A5" not in nodes[0].get("hardening_profiles",[]):self.add("E16A5.GRAPH.NODE","final E16 graph node invalid","conformance/extension-graph.json")
 def run(self):
  h=self.load(self.history_path,"E16A5.HISTORY");mrep=self.load(self.matrix_path,"E16A5.MATRIX");c=self.load(self.closure_path,"E16A5.CLOSURE");t=self.load(self.transition_path,"E16A5.TRANSITION");manifest=self.load(self.manifest_path,"E16A5.MANIFEST");freeze=self.load(self.freeze_path,"E16A5.FREEZE")
  hist=self.check_history(h);matrix=self.check_matrix(mrep);self.check_profile();self.check_transition(t);self.check_manifest(manifest);self.check_closure(c);self.check_graph();freeze_result,count=self.check_freeze(freeze)
  structural="non-conformant" if self.findings else "conformant";final="closed" if structural=="conformant" and hist==matrix==freeze_result=="conformant" else "open"
  return {"tool":"eigiib-e16-final-closure-check","tool_version":TOOL_VERSION,"standard":STANDARD,"profile_revision":PROFILE_REVISION,"source_e16_a4_commit":SOURCE_COMMIT,"historical_continuity_result":hist,"matrix_result":matrix,"matrix_case_count":mrep.get("case_count",0) if isinstance(mrep,dict) else 0,"matched_case_count":mrep.get("matched_case_count",0) if isinstance(mrep,dict) else 0,"verifier_count":mrep.get("verifier_count",0) if isinstance(mrep,dict) else 0,"differential_restore_result":mrep.get("differential_restore_result","non-conformant") if isinstance(mrep,dict) else "non-conformant","authority_count":count,"authority_freeze_result":freeze_result,"structural_result":structural,"final_state":final,"findings":[asdict(x) for x in sorted(self.findings)]}
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--history-report",default="historical-e16-a4-report.json");p.add_argument("--matrix-report",default="e16-a5-matrix-report.json");p.add_argument("--json",action="store_true");a=p.parse_args(argv);r=Checker(Path(a.root),Path(a.history_report),Path(a.matrix_report)).run();print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["final_state"]=="closed" else 1
if __name__=="__main__": raise SystemExit(main())
