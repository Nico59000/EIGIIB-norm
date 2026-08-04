#!/usr/bin/env python3
import argparse,json
from pathlib import Path
F4_HEAD='e92fee6cafc54f94c5b417949fde12c951cc0635'
REQUIRED=('conformance/m0-a12-f5-adoption-authority.json','conformance/m0-a12-f5-adoption-policy.json','conformance/m0-a12-f5-governance-convergence.json','conformance/m0-a12-f5-e17-adoption-matrix.json','conformance/m0-a12-f5-final-freeze.json','conformance/m0-a12-f5-ledger.json','conformance/m0-a12-f5-htnt-decision-protocol.json')
def load(p): return json.loads(p.read_text(encoding='utf-8'))
def evaluate(root):
 root=Path(root); findings=[]
 try: docs={p:load(root/p) for p in REQUIRED}
 except Exception as e: return {'standard':'EIGIIB-M0-A12-F5-REPORT-1.0','htntLabel':'F','decision':'invalid','findings':[str(e)],'summary':{}}
 main=docs[REQUIRED[0]]; matrix=docs[REQUIRED[3]]; ledger=docs[REQUIRED[5]]
 if main.get('source',{}).get('m0A12F4Head')!=F4_HEAD: findings.append('source-head-mismatch')
 if matrix.get('matrixDecision')!='not-adopted': findings.append('premature-adoption')
 rows=matrix.get('rows',[]); blocking=sum(1 for r in rows if r.get('classification')=='adoptable' and r.get('blocking'))
 evidence=root/'evidence/m0-a12-f5'; f4_t=False
 try: f4_t=load(root/'conformance/m0-a12-f4-recovery-ledger.json').get('recoveryDecision')=='verified'
 except Exception: pass
 if findings: label,decision='F','invalid'
 elif not f4_t and not evidence.exists(): label,decision='NF','not-adopted'
 elif evidence.exists(): label,decision='NT','incomplete-or-unverified-adoption-evidence'
 else: label,decision='NF','not-adopted'
 return {'standard':'EIGIIB-M0-A12-F5-REPORT-1.0','htntLabel':label,'decision':decision,'findings':findings,'summary':{'f4Replay':'verified' if f4_t else 'not-verified','adoptableRowsClosed':ledger.get('adoptableRowsClosed'), 'blockingRows':blocking,'collegeApprovals':ledger.get('governanceCollegeApprovalCount'),'finalFreezeDecision':ledger.get('finalFreezeDecision')}}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument('root',nargs='?',default='.'); ap.add_argument('--output'); ap.add_argument('--require-adopted',action='store_true'); a=ap.parse_args(); r=evaluate(a.root); out=json.dumps(r,indent=2)+'\n'; Path(a.output).write_text(out,encoding='utf-8') if a.output else print(out,end=''); return 0 if (not a.require_adopted or r['htntLabel']=='T') else 2
if __name__=='__main__': raise SystemExit(main())
