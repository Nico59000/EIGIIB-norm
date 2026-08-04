#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path
from eigiib_m0_a14_replay import verify_case

A13_HEAD="d096b9fbf68cead15a3a9eb7bf4cff1493a0aa45"
FREEZE_PATH="conformance/m0-a14-authority-freeze.json"
REQUIRED=("conformance/m0-a14-continuity-authority.json","conformance/m0-a14-continuity-policy.json","conformance/m0-a14-revocation-policy.json","conformance/m0-a14-governance-drift-policy.json","conformance/m0-a14-maintenance-ledger.json","conformance/m0-a14-htnt-decision-protocol.json")

def load(path): return json.loads(path.read_text(encoding="utf-8"))

def evaluate(root):
    root=Path(root); findings=[]
    try: docs={p:load(root/p) for p in REQUIRED}
    except Exception as exc: return {"standard":"EIGIIB-M0-A14-REPORT-1.0","htntLabel":"F","decision":"invalid","findings":[str(exc)],"summary":{"a13Decision":"unknown","acceptedCycles":0,"revocationEvents":0,"driftDecision":"unknown"}}
    authority=docs[REQUIRED[0]]; ledger=docs[REQUIRED[4]]
    try:
        freeze=load(root/FREEZE_PATH); entries=freeze.get("authorities",[])
        if freeze.get("authorityCount")!=len(entries): findings.append("authority-freeze-count-mismatch")
        for entry in entries:
            path=root/entry.get("path","")
            if not path.is_file(): findings.append("authority-freeze-path-missing"); continue
            raw=path.read_bytes()
            if len(raw)!=entry.get("bytes") or hashlib.sha256(raw).hexdigest()!=entry.get("sha256"): findings.append("authority-freeze-digest-mismatch")
    except Exception: findings.append("authority-freeze-invalid")
    if authority.get("source",{}).get("m0A13Head")!=A13_HEAD: findings.append("source-head-mismatch")
    if ledger.get("sourceHead")!=A13_HEAD: findings.append("ledger-anchor-mismatch")
    if ledger.get("entries")!=[] or ledger.get("cycleCount")!=0 or ledger.get("revocationEventCount")!=0: findings.append("baseline-ledger-not-empty")
    a13_verified=False
    try:
        a13=load(root/"conformance/m0-a13-maintenance-ledger.json")
        a13_verified=a13.get("maintenanceDecision")=="verified" and a13.get("refreezeDecision")=="refrozen"
    except Exception: pass
    evidence=root/"evidence/m0-a14/multi-cycle-chain.json"; replay=None
    if evidence.exists():
        try: replay=verify_case(load(evidence))
        except Exception as exc: replay={"verified":False,"errors":[str(exc)],"summary":{}}
    if findings: label,decision="F","invalid"
    elif replay and replay.get("verified") and a13_verified: label,decision="T","verified"
    elif replay is not None: label,decision="NT","incomplete-or-invalid-cycle-evidence"
    else: label,decision="NF","not-accumulated"
    summary=replay.get("summary",{}) if replay else {}
    return {"standard":"EIGIIB-M0-A14-REPORT-1.0","htntLabel":label,"decision":decision,"findings":findings if findings else ([] if replay is None else replay.get("errors",[])),"summary":{"a13Decision":"verified" if a13_verified else "not-verified","acceptedCycles":summary.get("cycleCount",0),"revocationEvents":summary.get("revocationEventCount",0),"governanceTransitions":summary.get("governanceTransitionCount",0),"driftDecision":"controlled" if label=="T" else "not-evaluated"}}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="."); ap.add_argument("--output"); ap.add_argument("--require-verified",action="store_true"); args=ap.parse_args()
    report=evaluate(args.root); text=json.dumps(report,indent=2)+"\n"
    if args.output: Path(args.output).write_text(text,encoding="utf-8")
    else: print(text,end="")
    return 0 if (not args.require_verified or report["htntLabel"]=="T") else 2
if __name__=="__main__": raise SystemExit(main())
