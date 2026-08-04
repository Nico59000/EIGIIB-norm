#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path
from eigiib_m0_a15_replay import verify_case

A14_HEAD = "5936ed072187cd7fe72db2c33119c8db92d06570"
A14_TREE = "8b77cadd56e5d51a08b94bbeee603d994ca7a5d2"
FREEZE_PATH = "conformance/m0-a15-authority-freeze.json"
REQUIRED = (
 "conformance/m0-a15-witnessing-authority.json",
 "conformance/m0-a15-registry-policy.json",
 "conformance/m0-a15-split-brain-policy.json",
 "conformance/m0-a15-reconciliation-policy.json",
 "conformance/m0-a15-reconciliation-ledger.json",
 "conformance/m0-a15-htnt-decision-protocol.json",
)
def load(path): return json.loads(path.read_text(encoding="utf-8"))
def evaluate(root):
    root=Path(root); findings=[]
    try: docs={p:load(root/p) for p in REQUIRED}
    except Exception as exc:
        return {"standard":"EIGIIB-M0-A15-REPORT-1.0","htntLabel":"F","decision":"invalid","findings":[str(exc)],
        "summary":{"a14Decision":"unknown","checkpointCount":0,"splitBrainEvents":0,"reconciliationDecision":"unknown"}}
    authority=docs[REQUIRED[0]]; ledger=docs[REQUIRED[4]]
    try:
        freeze=load(root/FREEZE_PATH); authorities=freeze.get("authorities",[])
        if freeze.get("authorityCount")!=len(authorities): findings.append("authority-freeze-count-mismatch")
        for entry in authorities:
            p=root/entry.get("path","")
            if not p.is_file(): findings.append("authority-freeze-path-missing"); continue
            raw=p.read_bytes()
            if len(raw)!=entry.get("bytes") or hashlib.sha256(raw).hexdigest()!=entry.get("sha256"):
                findings.append("authority-freeze-digest-mismatch")
    except Exception: findings.append("authority-freeze-invalid")
    src=authority.get("source",{})
    if src.get("m0A14Head")!=A14_HEAD: findings.append("source-head-mismatch")
    if src.get("m0A14Tree")!=A14_TREE: findings.append("source-tree-mismatch")
    if ledger.get("sourceHead")!=A14_HEAD: findings.append("ledger-anchor-mismatch")
    if ledger.get("entries")!=[] or ledger.get("checkpointCount")!=0: findings.append("baseline-ledger-not-empty")
    a14_verified=False
    try:
        a14=load(root/"conformance/m0-a14-maintenance-ledger.json")
        a14_verified=a14.get("continuityDecision")=="accumulated" and a14.get("driftDecision")=="controlled"
    except Exception: pass
    evidence=root/"evidence/m0-a15/reconciliation-history.json"; replay=None
    if evidence.exists():
        try: replay=verify_case(load(evidence))
        except Exception as exc: replay={"verified":False,"errors":[str(exc)]}
    if findings: label,decision="F","invalid"
    elif replay and replay.get("verified") and a14_verified: label,decision="T","verified"
    elif replay is not None: label,decision="NT","incomplete-or-invalid-reconciliation-evidence"
    else: label,decision="NF","not-observed"
    return {"standard":"EIGIIB-M0-A15-REPORT-1.0","htntLabel":label,"decision":decision,
      "findings":findings if findings else ([] if replay is None else replay.get("errors",[])),
      "summary":{"a14Decision":"verified" if a14_verified else "not-verified",
      "checkpointCount":ledger.get("checkpointCount"),"splitBrainEvents":ledger.get("splitBrainEventCount"),
      "reconciliationDecision":ledger.get("reconciliationDecision")}}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="."); ap.add_argument("--output"); ap.add_argument("--require-verified",action="store_true")
    args=ap.parse_args(); report=evaluate(args.root); text=json.dumps(report,indent=2)+"\n"
    if args.output: Path(args.output).write_text(text,encoding="utf-8")
    else: print(text,end="")
    return 0 if (not args.require_verified or report["htntLabel"]=="T") else 2
if __name__=="__main__": raise SystemExit(main())
