#!/usr/bin/env python3
"""Materialize and replay the exact historical M0-A7 and E15 authority."""
from __future__ import annotations
import argparse, json, subprocess, sys, tarfile, tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E16-A1-HISTORICAL-M0-A7-REPLAY-1.0"; SOURCE_COMMIT="ae189e1c478c523789f11e4424395be154e8521d"
@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str
def run(args:list[str],cwd:Path)->subprocess.CompletedProcess[str]: return subprocess.run(args,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
def parsed(proc:subprocess.CompletedProcess[str],label:str)->dict[str,Any]:
    if proc.returncode: raise RuntimeError(f"{label} exited {proc.returncode}: {proc.stderr or proc.stdout}")
    value=json.loads(proc.stdout)
    if not isinstance(value,dict): raise RuntimeError(f"{label} did not emit an object")
    return value
def replay(root:Path,source_commit:str=SOURCE_COMMIT,e15_output:Path|None=None)->dict[str,Any]:
    root=root.resolve(); findings=[]; results={k:"non-conformant" for k in ("e15_history_result","e15_final_closure_result","m0_a7_result","m0_a7_tests_result")}
    exact=run(["git","rev-parse","--verify",f"{source_commit}^{{commit}}"],root); ancestor=run(["git","merge-base","--is-ancestor",source_commit,"HEAD"],root)
    if exact.returncode or exact.stdout.strip()!=source_commit: findings.append(Finding("error","E16A1.HISTORY.SOURCE","","exact M0-A7 source commit is unavailable"))
    if ancestor.returncode: findings.append(Finding("error","E16A1.HISTORY.ANCESTRY","","M0-A7 source commit is not an ancestor of HEAD"))
    if not findings:
      with tempfile.TemporaryDirectory(prefix="eigiib-m0-a7-history-") as td:
        td=Path(td); archive=td/"tree.tar"; tree=td/"tree"; tree.mkdir()
        p=run(["git","archive","--format=tar",f"--output={archive}",source_commit],root)
        if p.returncode: findings.append(Finding("error","E16A1.HISTORY.ARCHIVE","",p.stderr.strip()))
        else:
          try:
            with tarfile.open(archive,"r:") as tf: tf.extractall(tree,filter="data")
          except Exception as exc: findings.append(Finding("error","E16A1.HISTORY.EXTRACT","",str(exc)))
        if not findings:
          try:
            parent=parsed(run([sys.executable,str(tree/"tools/eigiib_historical_e15_a4_replay.py"),str(root),"--json"],root),"historical-e15-a4")
            if parent.get("overall_result")!="conformant": raise RuntimeError("historical E15-A4 replay is non-conformant")
            results["e15_history_result"]="conformant"
            rel=Path(".eigiib-runtime/e15-a4-history.json"); hp=tree/rel; hp.parent.mkdir(parents=True,exist_ok=True); hp.write_text(json.dumps(parent,indent=2,sort_keys=True)+"\n",encoding="utf-8")
            final=parsed(run([sys.executable,str(tree/"tools/eigiib_e15_final_closure_check.py"),str(tree),"--history-report",rel.as_posix(),"--json"],tree),"e15-final")
            expected=json.loads((tree/"tests/fixtures/e15-a5/expected-closure-report.json").read_text(encoding="utf-8"))
            if final!=expected: raise RuntimeError("E15 final report differs from frozen fixture")
            results["e15_final_closure_result"]="conformant"
            if e15_output:
              target=(root/e15_output).resolve(); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(final,indent=2,sort_keys=True)+"\n",encoding="utf-8")
          except Exception as exc: findings.append(Finding("error","E16A1.HISTORY.E15","e15",str(exc)))
          try:
            m0=parsed(run([sys.executable,str(tree/"tools/eigiib_m0_a7_check.py"),str(tree),"--json"],tree),"m0-a7")
            expected=json.loads((tree/"tests/fixtures/m0-a7/expected-report.json").read_text(encoding="utf-8"))
            if m0!=expected: raise RuntimeError("M0-A7 report differs from frozen fixture")
            results["m0_a7_result"]="conformant"
          except Exception as exc: findings.append(Finding("error","E16A1.HISTORY.M0A7","m0-a7",str(exc)))
          try:
            p=run([sys.executable,"-m","unittest","-v","tests/test_eigiib_m0_a7.py"],tree)
            if p.returncode: raise RuntimeError(p.stderr or p.stdout)
            results["m0_a7_tests_result"]="conformant"
          except Exception as exc: findings.append(Finding("error","E16A1.HISTORY.TESTS","m0-a7-tests",str(exc)))
    overall="non-conformant" if findings or any(v!="conformant" for v in results.values()) else "conformant"
    return {"tool":"eigiib-historical-m0-a7-replay","tool_version":TOOL_VERSION,"standard":STANDARD,"source_commit":source_commit,"materialization":"git-archive-isolated-tree","ancestry_result":"conformant" if ancestor.returncode==0 else "non-conformant",**results,"overall_result":overall,"findings":[asdict(f) for f in sorted(findings)]}
def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("root",nargs="?",default="."); p.add_argument("--source-commit",default=SOURCE_COMMIT); p.add_argument("--e15-output"); p.add_argument("--json",action="store_true"); a=p.parse_args(argv)
    report=replay(Path(a.root),a.source_commit,Path(a.e15_output) if a.e15_output else None); print(json.dumps(report,indent=2,sort_keys=True)); return 0 if report["overall_result"]=="conformant" else 1
if __name__=="__main__": raise SystemExit(main())
