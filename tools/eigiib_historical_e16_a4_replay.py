#!/usr/bin/env python3
"""Materialize and replay the exact historical E16-A4 authority."""
from __future__ import annotations
import argparse, json, subprocess, sys, tarfile, tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E16-A5-HISTORICAL-E16-A4-REPLAY-1.0"; SOURCE_COMMIT="b28fe74f829141232770155724620617bfb1241c"
@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str
def run(args:list[str],cwd:Path): return subprocess.run(args,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=False)
def parsed(proc,label):
 if proc.returncode: raise RuntimeError(f"{label} exited {proc.returncode}: {proc.stderr or proc.stdout}")
 value=json.loads(proc.stdout)
 if not isinstance(value,dict): raise RuntimeError(f"{label} did not emit an object")
 return value
def replay(root:Path,source_commit:str=SOURCE_COMMIT)->dict[str,Any]:
 root=root.resolve(); findings=[]; results={"e16_a3_history_result":"non-conformant","e16_a4_result":"non-conformant","e16_a4_tests_result":"non-conformant"}
 exact=run(["git","rev-parse","--verify",f"{source_commit}^{{commit}}"],root); ancestor=run(["git","merge-base","--is-ancestor",source_commit,"HEAD"],root)
 if exact.returncode or exact.stdout.strip()!=source_commit: findings.append(Finding("error","E16A5.HISTORY.SOURCE","","exact E16-A4 source commit is unavailable"))
 if ancestor.returncode: findings.append(Finding("error","E16A5.HISTORY.ANCESTRY","","E16-A4 source commit is not an ancestor of HEAD"))
 if not findings:
  with tempfile.TemporaryDirectory(prefix="eigiib-e16-a4-history-") as raw:
   td=Path(raw); archive=td/"tree.tar"; tree=td/"tree"; tree.mkdir()
   proc=run(["git","archive","--format=tar",f"--output={archive}",source_commit],root)
   if proc.returncode: findings.append(Finding("error","E16A5.HISTORY.ARCHIVE","",proc.stderr.strip()))
   else:
    try:
     with tarfile.open(archive,"r:") as tf: tf.extractall(tree,filter="data")
    except Exception as exc: findings.append(Finding("error","E16A5.HISTORY.EXTRACT","",str(exc)))
   if not findings:
    try:
     history=parsed(run([sys.executable,str(tree/"tools/eigiib_historical_e16_a3_replay.py"),str(root),"--json"],root),"historical-e16-a3")
     if history.get("overall_result")!="conformant": raise RuntimeError("historical E16-A3 replay is non-conformant")
     results["e16_a3_history_result"]="conformant"
     rel=Path(".eigiib-runtime/e16-a3-history.json"); hp=tree/rel; hp.parent.mkdir(parents=True,exist_ok=True); hp.write_text(json.dumps(history,indent=2,sort_keys=True)+"\n",encoding="utf-8")
     a4=parsed(run([sys.executable,str(tree/"tools/eigiib_custodian_succession_recovery_check.py"),str(tree),"--history-report",rel.as_posix(),"--json"],tree),"e16-a4")
     expected=json.loads((tree/"tests/fixtures/e16-a4/expected-report.json").read_text(encoding="utf-8"))
     if a4!=expected: raise RuntimeError("E16-A4 report differs from frozen fixture")
     results["e16_a4_result"]="conformant"
    except Exception as exc: findings.append(Finding("error","E16A5.HISTORY.E16A4","e16-a4",str(exc)))
    try:
     proc=run([sys.executable,"-m","unittest","-v","tests/test_eigiib_custodian_succession_recovery.py"],tree)
     if proc.returncode: raise RuntimeError(proc.stderr or proc.stdout)
     results["e16_a4_tests_result"]="conformant"
    except Exception as exc: findings.append(Finding("error","E16A5.HISTORY.TESTS","e16-a4-tests",str(exc)))
 overall="non-conformant" if findings or any(v!="conformant" for v in results.values()) else "conformant"
 return {"tool":"eigiib-historical-e16-a4-replay","tool_version":TOOL_VERSION,"standard":STANDARD,"source_commit":source_commit,"materialization":"git-archive-isolated-tree","ancestry_result":"conformant" if ancestor.returncode==0 else "non-conformant",**results,"overall_result":overall,"findings":[asdict(x) for x in sorted(findings)]}
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--source-commit",default=SOURCE_COMMIT);p.add_argument("--json",action="store_true");a=p.parse_args(argv);r=replay(Path(a.root),a.source_commit);print(json.dumps(r,indent=2,sort_keys=True));return 0 if r["overall_result"]=="conformant" else 1
if __name__=="__main__": raise SystemExit(main())
