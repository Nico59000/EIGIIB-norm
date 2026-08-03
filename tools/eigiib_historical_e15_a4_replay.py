#!/usr/bin/env python3
"""Materialize and replay the exact historical E15-A4 authority."""
from __future__ import annotations
import argparse, json, subprocess, sys, tarfile, tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E15-A5-HISTORICAL-E15-A4-REPLAY-1.0"; SOURCE_COMMIT="fce0ba52930e32069b54ab8f5634501a130222a7"
@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str

def run(args:list[str],cwd:Path)->subprocess.CompletedProcess[str]: return subprocess.run(args,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
def parsed(proc:subprocess.CompletedProcess[str],label:str)->dict[str,Any]:
    if proc.returncode: raise RuntimeError(f"{label} exited {proc.returncode}: {proc.stderr or proc.stdout}")
    value=json.loads(proc.stdout)
    if not isinstance(value,dict): raise RuntimeError(f"{label} did not emit an object")
    return value

def replay(root:Path,source_commit:str=SOURCE_COMMIT)->dict[str,Any]:
    root=root.resolve(); findings=[]; results={k:"non-conformant" for k in ("historical_e14_result","e15_a1_result","e15_a2_result","e15_a3_result","e15_a4_result","e15_a4_tests_result")}
    exact=run(["git","rev-parse","--verify",f"{source_commit}^{{commit}}"],root)
    ancestor=run(["git","merge-base","--is-ancestor",source_commit,"HEAD"],root)
    if exact.returncode or exact.stdout.strip()!=source_commit: findings.append(Finding("error","E15A5.HISTORY.SOURCE","","exact E15-A4 source commit is unavailable"))
    if ancestor.returncode: findings.append(Finding("error","E15A5.HISTORY.ANCESTRY","","E15-A4 source commit is not an ancestor of HEAD"))
    if not findings:
        with tempfile.TemporaryDirectory(prefix="eigiib-e15-a4-history-") as td:
            td=Path(td); archive=td/"tree.tar"; tree=td/"tree"; tree.mkdir()
            p=run(["git","archive","--format=tar",f"--output={archive}",source_commit],root)
            if p.returncode: findings.append(Finding("error","E15A5.HISTORY.ARCHIVE","",p.stderr.strip()))
            else:
                try:
                    with tarfile.open(archive,"r:") as tf: tf.extractall(tree,filter="data")
                except Exception as exc: findings.append(Finding("error","E15A5.HISTORY.EXTRACT","",str(exc)))
            if not findings:
                try:
                    parent=parsed(run([sys.executable,str(tree/"tools/eigiib_historical_e15_a3_replay.py"),str(root),"--json"],root),"historical-e15-a3")
                    if parent.get("overall_result")!="conformant": raise RuntimeError("historical E15-A3 replay is non-conformant")
                    for key in ("historical_e14_result","e15_a1_result","e15_a2_result","e15_a3_result"):
                        results[key]="conformant" if parent.get(key)=="conformant" else "non-conformant"
                    rel=Path(".eigiib-runtime/historical-e15-a3-report.json"); hp=tree/rel; hp.parent.mkdir(parents=True,exist_ok=True); hp.write_text(json.dumps(parent,indent=2,sort_keys=True)+"\n",encoding="utf-8")
                    report=parsed(run([sys.executable,str(tree/"tools/eigiib_withdrawal_governance_check.py"),str(tree),"--history-report",rel.as_posix(),"--json"],tree),"e15-a4")
                    expected=json.loads((tree/"tests/fixtures/e15-a4/expected-report.json").read_text(encoding="utf-8"))
                    if report!=expected: raise RuntimeError("E15-A4 report differs from frozen fixture")
                    results["e15_a4_result"]="conformant"
                except Exception as exc: findings.append(Finding("error","E15A5.HISTORY.E15A4","e15-a4",str(exc)))
                try:
                    p=run([sys.executable,"-m","unittest","-v","tests/test_eigiib_withdrawal_governance.py"],tree)
                    if p.returncode: raise RuntimeError(p.stderr or p.stdout)
                    results["e15_a4_tests_result"]="conformant"
                except Exception as exc: findings.append(Finding("error","E15A5.HISTORY.TESTS","e15-a4-tests",str(exc)))
    overall="non-conformant" if findings or any(v!="conformant" for v in results.values()) else "conformant"
    return {"tool":"eigiib-historical-e15-a4-replay","tool_version":TOOL_VERSION,"standard":STANDARD,"source_commit":source_commit,"materialization":"git-archive-isolated-tree","ancestry_result":"conformant" if ancestor.returncode==0 else "non-conformant",**results,"overall_result":overall,"findings":[asdict(f) for f in sorted(findings)]}

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("root",nargs="?",default="."); p.add_argument("--source-commit",default=SOURCE_COMMIT); p.add_argument("--json",action="store_true"); a=p.parse_args(argv)
    report=replay(Path(a.root),a.source_commit); print(json.dumps(report,indent=2,sort_keys=True)); return 0 if report["overall_result"]=="conformant" else 1
if __name__=="__main__": raise SystemExit(main())
