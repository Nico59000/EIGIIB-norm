#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from eigiib_m0_a12_f2_canonical import digest_document, load_json, parse_time
from eigiib_m0_a12_f2_ledger import evaluate_chain

STANDARD="EIGIIB-M0-A12-F2-1.0"
REPORT_STANDARD="EIGIIB-M0-A12-F2-REPORT-1.0"
F1_HEAD="eaa64be6c27d30ceba7762ecf1ec7f93fe805745"
AUTHORITY_PATH="conformance/m0-a12-f2-continuity.json"
POLICY_PATH="conformance/m0-a12-f2-accumulation-policy.json"
LEDGER_PATH="conformance/m0-a12-f2-continuity-ledger.json"
PROTOCOL_PATH="conformance/m0-a12-f2-htnt-decision-protocol.json"
FREEZE_PATH="conformance/m0-a12-f2-authority-freeze.json"
F1_AUTHORITY_PATH="conformance/m0-a12-f1-bound-ingress.json"
F1_LEDGER_PATH="conformance/m0-a12-f1-closure-ledger.json"
CERT_PATH="evidence/m0-a12-f2/continuity-certificate.json"

def sha256(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()
def add(findings:list[str],code:str,condition:bool)->None:
    if condition: findings.append(code)
def load_required(root:Path,rel:str,findings:list[str])->dict[str,Any]:
    try: return load_json(root/rel)
    except Exception as exc:
        findings.append(f"M0A12F2.JSON:{rel}:{type(exc).__name__}"); return {}

def verify_freeze(root:Path,findings:list[str])->int:
    freeze=load_required(root,FREEZE_PATH,findings)
    add(findings,"M0A12F2.FREEZE.STANDARD",freeze.get("standard")!="EIGIIB-M0-A12-F2-AUTHORITY-FREEZE-1.0")
    add(findings,"M0A12F2.FREEZE.SOURCE",freeze.get("sourceHead")!=F1_HEAD)
    authorities=freeze.get("authorities",[])
    add(findings,"M0A12F2.FREEZE.COUNT",freeze.get("authorityCount")!=len(authorities))
    add(findings,"M0A12F2.FREEZE.EXCLUSION",freeze.get("excludedPath")!=FREEZE_PATH)
    seen=set()
    for item in authorities:
        rel=item.get("path")
        if not rel or rel in seen or rel==FREEZE_PATH:
            findings.append("M0A12F2.FREEZE.PATH_SET"); continue
        seen.add(rel); path=root/rel
        if not path.is_file(): findings.append(f"M0A12F2.FREEZE.MISSING:{rel}"); continue
        if path.stat().st_size!=item.get("bytes"): findings.append(f"M0A12F2.FREEZE.BYTES:{rel}")
        if sha256(path)!=item.get("sha256"): findings.append(f"M0A12F2.FREEZE.SHA256:{rel}")
    return len(authorities)

def baseline(root:Path,findings:list[str]):
    authority=load_required(root,AUTHORITY_PATH,findings)
    policy=load_required(root,POLICY_PATH,findings)
    ledger=load_required(root,LEDGER_PATH,findings)
    protocol=load_required(root,PROTOCOL_PATH,findings)
    f1=load_required(root,F1_AUTHORITY_PATH,findings)
    f1ledger=load_required(root,F1_LEDGER_PATH,findings)
    add(findings,"M0A12F2.AUTHORITY.STANDARD",authority.get("standard")!=STANDARD)
    add(findings,"M0A12F2.AUTHORITY.STATUS",authority.get("status")!="continuity-harness-established-f1-closure-pending")
    add(findings,"M0A12F2.AUTHORITY.SOURCE",authority.get("source",{}).get("m0A12F1Head")!=F1_HEAD)
    add(findings,"M0A12F2.F1.STANDARD",f1.get("standard")!="EIGIIB-M0-A12-F1-1.0")
    add(findings,"M0A12F2.F1.SUCCESSOR",f1.get("naturalSuccessor",{}).get("id")!="M0-A12-F2")
    add(findings,"M0A12F2.POLICY.STANDARD",policy.get("standard")!="EIGIIB-M0-A12-F2-ACCUMULATION-POLICY-1.0")
    add(findings,"M0A12F2.POLICY.SOURCE",policy.get("sourceHead")!=F1_HEAD)
    add(findings,"M0A12F2.POLICY.SCHEDULE",policy.get("schedule")!={"cadenceSeconds":86400,"graceSeconds":21600,"lapseAfterSeconds":172800,"clock":"utc-rfc3339"})
    add(findings,"M0A12F2.POLICY.THRESHOLD",policy.get("threshold")!={"firstSequence":1,"lastSequence":30,"totalObservationCount":30,"continuationObservationCount":29,"minimumElapsedSeconds":2505600,"maximumOverdueObservations":0,"maximumLapses":0})
    add(findings,"M0A12F2.POLICY.CHECKPOINTS",policy.get("checkpointPolicy",{}).get("sequences")!=[7,14,21,28])
    add(findings,"M0A12F2.LEDGER.STANDARD",ledger.get("standard")!="EIGIIB-M0-A12-F2-CONTINUITY-LEDGER-1.0")
    add(findings,"M0A12F2.LEDGER.SOURCE",ledger.get("sourceHead")!=F1_HEAD)
    add(findings,"M0A12F2.LEDGER.PREMATURE",ledger.get("entries")!=[] or ledger.get("accumulationDecision")!="not-accumulated")
    add(findings,"M0A12F2.PROTOCOL.STANDARD",protocol.get("standard")!="EIGIIB-M0-A12-F2-HTNT-DECISION-PROTOCOL-1.0")
    add(findings,"M0A12F2.PROTOCOL.CONTEXT",protocol.get("fixedContext") is not True)
    add(findings,"M0A12F2.PROTOCOL.CURRENT",protocol.get("current",{}).get("label")!="NF")
    add(findings,"M0A12F2.BOUNDARY.E17",authority.get("accumulationBoundary",{}).get("e17Decision")!="not-ready-for-adoption")
    return policy,f1ledger

def f1_closed(root:Path,f1ledger:dict[str,Any])->bool:
    return f1ledger.get("closureDecision")=="point-in-time-activation-closed" and bool(f1ledger.get("closureCertificateDigest")) and (root/"evidence/m0-a12-f1/closure-certificate.json").is_file()

def verify_certificate(root:Path,chain:dict[str,Any],findings:list[str])->None:
    cert=load_required(root,CERT_PATH,findings)
    add(findings,"M0A12F2.CERT.STANDARD",cert.get("standard")!="EIGIIB-M0-A12-F2-CONTINUITY-CERTIFICATE-1.0")
    add(findings,"M0A12F2.CERT.SOURCE",cert.get("sourceF1Head")!=F1_HEAD)
    for key in ["firstObservationDigest","lastObservationDigest","firstObservedAt","lastObservedAt","totalObservationCount","continuationObservationCount","elapsedSeconds","overdueCount","lapseCount","lapseState"]:
        add(findings,f"M0A12F2.CERT.FIELD:{key}",cert.get(key)!=chain.get(key))
    add(findings,"M0A12F2.CERT.DECISION",cert.get("decision")!="bounded-long-horizon-preservation-accumulation-verified")
    add(findings,"M0A12F2.CERT.BOUNDARY",cert.get("claimBoundary")!="bounded-observed-window-not-future-guarantee")
    add(findings,"M0A12F2.CERT.DIGEST",cert.get("certificateDigest")!=digest_document(cert,"certificateDigest"))

def evaluate(root:Path,as_of:datetime|None=None)->dict[str,Any]:
    findings=[]; policy,f1ledger=baseline(root,findings); authority_count=verify_freeze(root,findings)
    closed=f1_closed(root,f1ledger); evidence_present=(root/"evidence/m0-a12-f2").exists()
    accepted=0; state="blocked"; result="f1-closure-pending"
    if findings:
        structural="nonconformant"; label="F"
    elif not closed:
        if evidence_present:
            findings.append("M0A12F2.EVIDENCE.BEFORE_F1_CLOSURE")
            structural="nonconformant-external-evidence"; label="NT"; result="premature-or-conflicting-temporal-evidence"
        else:
            structural="conformant-blocked-prerequisite"; label="NF"
    elif not evidence_present:
        structural="conformant-awaiting-continuity"; label="NF"; state="awaiting-sequence-2"; result="continuity-evidence-pending"
    else:
        try:
            chain=evaluate_chain(root,policy,as_of or datetime.now(timezone.utc))
            accepted=chain["totalObservationCount"]; state=chain["lapseState"]; verify_certificate(root,chain,findings)
            threshold=policy["threshold"]
            if chain["totalObservationCount"]!=threshold["totalObservationCount"]: findings.append("M0A12F2.THRESHOLD.COUNT")
            if chain["elapsedSeconds"]<threshold["minimumElapsedSeconds"]: findings.append("M0A12F2.THRESHOLD.ELAPSED")
            if chain["overdueCount"]>threshold["maximumOverdueObservations"]: findings.append("M0A12F2.THRESHOLD.OVERDUE")
            if chain["lapseCount"]>threshold["maximumLapses"] or state=="lapsed": findings.append("M0A12F2.THRESHOLD.LAPSE")
        except Exception as exc:
            findings.append(f"M0A12F2.CONTINUITY:{type(exc).__name__}:{exc}")
        if findings:
            structural="nonconformant-external-evidence"; label="NT"; result="continuity-invalid-incomplete-or-lapsed"
        elif state in {"current","grace"}:
            structural="conformant"; label="T"; result="bounded-long-horizon-preservation-accumulation-verified"
        else:
            structural="nonconformant-external-evidence"; label="NT"; result="continuity-not-current"
    return {"standard":REPORT_STANDARD,"structural_result":structural,"continuity_result":result,"htntLabel":label,
      "findings":sorted(set(findings)),"summary":{"sourceF1Head":F1_HEAD,"prerequisiteF1Closed":closed,
      "acceptedObservations":accepted,"requiredObservations":30,"requiredElapsedSeconds":2505600,
      "lapseState":state,"authorityCount":authority_count,"e17Decision":"not-ready-for-adoption"}}

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument("root",nargs="?",default="."); p.add_argument("--as-of"); p.add_argument("--output"); p.add_argument("--require-accumulated",action="store_true"); a=p.parse_args()
    report=evaluate(Path(a.root),parse_time(a.as_of) if a.as_of else None)
    encoded=json.dumps(report,indent=2,sort_keys=True)+"\n"
    if a.output: Path(a.output).write_text(encoded,encoding="utf-8",newline="\n")
    else: print(encoded,end="")
    if report["structural_result"].startswith("nonconformant"): return 1
    if a.require_accumulated and report["continuity_result"]!="bounded-long-horizon-preservation-accumulation-verified": return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
