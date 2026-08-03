#!/usr/bin/env python3
"""Cross-implementation E15-A5 external-evidence verifier matrix."""
from __future__ import annotations
import argparse, json, subprocess, sys, tempfile
from pathlib import Path

TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E15-A5-1.0"
ALLOWED={"delivery-evidence-bounded","acknowledgement-evidence-bounded","publication-evidence-bounded","persistence-evidence-bounded","independent-readback-bounded","withdrawal-request-bounded","tombstone-bounded","distribution-stop-bounded","withdrawal-evidence-bounded","rejected","held","unavailable"}
EXPECTED_INPUTS={"lineage_result","delivery_result","publication_result","withdrawal_result","content_identity_result","observer_independence_result","anti_rollback_result"}

def invoke(command:list[str])->dict:
    p=subprocess.run(command,check=False,capture_output=True,text=True)
    if p.returncode: raise RuntimeError(p.stderr or p.stdout or "verifier failed")
    value=json.loads(p.stdout)
    if not isinstance(value,dict): raise RuntimeError("verifier output must be an object")
    return value

def run_matrix(root:Path,catalog_path:Path)->dict:
    catalog=json.loads((root/catalog_path).read_text(encoding="utf-8")); findings=[]; outcomes=[]
    if catalog.get("standard")!=STANDARD or catalog.get("status")!="frozen-vectors": findings.append({"severity":"error","code":"E15A5.MATRIX.HEADER","path":str(catalog_path),"message":"unexpected matrix header"})
    exact={"reference_verifier":"tools/eigiib_e15_external_evidence_reference.py","independent_verifier":"tools/eigiib_e15_external_evidence_independent.py"}
    for k,v in exact.items():
        if catalog.get(k)!=v: findings.append({"severity":"error","code":"E15A5.MATRIX.VERIFIER","path":k,"message":f"{k} must be {v}"})
    cases=catalog.get("cases")
    if not isinstance(cases,list) or not cases: findings.append({"severity":"error","code":"E15A5.MATRIX.CASES","path":"cases","message":"cases must be non-empty"}); cases=[]
    seen=set(); valid=[]
    for pos,case in enumerate(cases):
        path=f"cases[{pos}]"; ident=case.get("id") if isinstance(case,dict) else None; inputs=case.get("inputs") if isinstance(case,dict) else None; expected=case.get("expected_state") if isinstance(case,dict) else None
        if not isinstance(ident,str) or not ident or ident in seen or not isinstance(inputs,dict) or set(inputs)!=EXPECTED_INPUTS or expected not in ALLOWED:
            findings.append({"severity":"error","code":"E15A5.MATRIX.CASE","path":path,"message":"invalid or duplicate case"}); continue
        seen.add(ident); valid.append(case)
    if valid:
        with tempfile.TemporaryDirectory() as td:
            vector=Path(td)/"vectors.json"; vector.write_text(json.dumps({"cases":[{"id":c["id"],"inputs":c["inputs"]} for c in valid]}),encoding="utf-8")
            try:
                ref_states=invoke([sys.executable,str(root/exact["reference_verifier"]),str(vector)]).get("states",{})
                alt_states=invoke([sys.executable,str(root/exact["independent_verifier"]),str(vector)]).get("states",{})
            except Exception as exc:
                findings.append({"severity":"error","code":"E15A5.MATRIX.EXECUTION","path":"cases","message":str(exc)}); ref_states={}; alt_states={}
        for case in valid:
            ident=case["id"]; expected=case["expected_state"]; r=ref_states.get(ident); a=alt_states.get(ident)
            outcomes.append({"id":ident,"reference":r,"independent":a,"expected":expected})
            if r!=a: findings.append({"severity":"error","code":"E15A5.MATRIX.DIFFERENTIAL","path":ident,"message":"verifiers disagree"})
            if r!=expected: findings.append({"severity":"error","code":"E15A5.MATRIX.EXPECTED","path":ident,"message":f"derived {r}, expected {expected}"})
    errors=any(x["severity"]=="error" for x in findings)
    return {"tool":"eigiib-e15-verifier-matrix","tool_version":TOOL_VERSION,"standard":STANDARD,"structural_result":"non-conformant" if errors else "conformant","verifier_matrix_result":"non-conformant" if errors else "conformant","verifier_count":2,"case_count":len(cases),"matched_case_count":sum(1 for x in outcomes if x["reference"]==x["independent"]==x["expected"]),"outcomes":outcomes,"findings":findings}

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("root",nargs="?",default="."); p.add_argument("--catalog",default="conformance/e15-a5-verifier-matrix.json"); p.add_argument("--json",action="store_true"); a=p.parse_args(argv)
    report=run_matrix(Path(a.root).resolve(),Path(a.catalog)); print(json.dumps(report,indent=2,sort_keys=True)); return 0 if report["structural_result"]=="conformant" else 1
if __name__=="__main__": raise SystemExit(main())
