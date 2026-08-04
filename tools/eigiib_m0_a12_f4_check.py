#!/usr/bin/env python3
import argparse,json
from pathlib import Path
F3_HEAD="fb2d9515280d456e280848f2d364a2a33c774e6e"
BUNDLE="96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
REQUIRED=("conformance/m0-a12-f4-emergency-recovery.json","conformance/m0-a12-f4-emergency-policy.json","conformance/m0-a12-f4-recovery-policy.json","conformance/m0-a12-f4-e17-evidence-matrix.json","conformance/m0-a12-f4-recovery-ledger.json","conformance/m0-a12-f4-htnt-decision-protocol.json")
def load(p): return json.loads(p.read_text(encoding="utf-8"))
def evaluate(root):
 root=Path(root); findings=[]
 try: docs={p:load(root/p) for p in REQUIRED}
 except Exception as e: return {"standard":"EIGIIB-M0-A12-F4-REPORT-1.0","htntLabel":"F","decision":"invalid","findings":[str(e)],"e17Decision":"not-ready-for-adoption"}
 main=docs[REQUIRED[0]]; ledger=docs[REQUIRED[4]]; matrix=docs[REQUIRED[3]]
 if main.get("source",{}).get("m0A12F3Head")!=F3_HEAD: findings.append("source-head-mismatch")
 if main.get("source",{}).get("stableBundleSha256")!=BUNDLE: findings.append("bundle-digest-mismatch")
 if matrix.get("matrixDecision")!="not-ready-for-adoption": findings.append("e17-premature-promotion")
 evidence=root/"evidence/m0-a12-f4"; f3_t=False
 try: f3_t=load(root/"conformance/m0-a12-f3-replay-ledger.json").get("replayDecision")=="verified"
 except Exception: pass
 if findings: label,decision="F","invalid"
 elif not f3_t and not evidence.exists(): label,decision="NF","not-verified"
 elif evidence.exists(): label,decision="NT","incomplete-or-unverified-external-evidence"
 else: label,decision="NF","not-verified"
 return {"standard":"EIGIIB-M0-A12-F4-REPORT-1.0","htntLabel":label,"decision":decision,"findings":findings,"summary":{"f3Replay":"verified" if f3_t else "not-verified","recoveryDecision":ledger.get("recoveryDecision"),"e17Decision":matrix.get("matrixDecision"),"blockingMatrixRows":sum(1 for r in matrix.get("rows",[]) if r.get("blocking"))}}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="."); ap.add_argument("--output"); ap.add_argument("--require-verified",action="store_true"); a=ap.parse_args(); r=evaluate(a.root); out=json.dumps(r,indent=2)+"\n"; Path(a.output).write_text(out,encoding="utf-8") if a.output else print(out,end=""); return 0 if (not a.require_verified or r["htntLabel"]=="T") else 2
if __name__=="__main__": raise SystemExit(main())
