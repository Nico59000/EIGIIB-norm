#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from eigiib_m0_a12_f3_canonical import digest_document, load_json, parse_time
from eigiib_m0_a12_f3_replay import evaluate_replay

STANDARD="EIGIIB-M0-A12-F3-1.0"
REPORT_STANDARD="EIGIIB-M0-A12-F3-REPORT-1.0"
F2_HEAD="597ba0931d3510b01136d8ca6c6075ee106a7f19"
AUTHORITY_PATH="conformance/m0-a12-f3-differential-continuity.json"
POLICY_PATH="conformance/m0-a12-f3-differential-policy.json"
OBSERVER_PATH="conformance/m0-a12-f3-observer-registry.json"
SUCCESSION_PATH="conformance/m0-a12-f3-succession-policy.json"
LEDGER_PATH="conformance/m0-a12-f3-replay-ledger.json"
PROTOCOL_PATH="conformance/m0-a12-f3-htnt-decision-protocol.json"
FREEZE_PATH="conformance/m0-a12-f3-authority-freeze.json"
F2_AUTHORITY_PATH="conformance/m0-a12-f2-continuity.json"
F2_LEDGER_PATH="conformance/m0-a12-f2-continuity-ledger.json"
CERT_PATH="evidence/m0-a12-f3/differential-succession-certificate.json"

def sha256(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()
def add(findings:list[str],code:str,condition:bool)->None:
    if condition: findings.append(code)
def load_required(root:Path,rel:str,findings:list[str])->dict[str,Any]:
    try: return load_json(root/rel)
    except Exception as exc:
        findings.append(f"M0A12F3.JSON:{rel}:{type(exc).__name__}"); return {}

def verify_freeze(root:Path,findings:list[str])->int:
    freeze=load_required(root,FREEZE_PATH,findings)
    add(findings,"M0A12F3.FREEZE.STANDARD",freeze.get("standard")!="EIGIIB-M0-A12-F3-AUTHORITY-FREEZE-1.0")
    add(findings,"M0A12F3.FREEZE.SOURCE",freeze.get("sourceHead")!=F2_HEAD)
    authorities=freeze.get("authorities",[])
    add(findings,"M0A12F3.FREEZE.COUNT",freeze.get("authorityCount")!=len(authorities))
    add(findings,"M0A12F3.FREEZE.EXCLUSION",freeze.get("excludedPath")!=FREEZE_PATH)
    seen=set()
    for item in authorities:
        rel=item.get("path")
        if not rel or rel in seen or rel==FREEZE_PATH:
            findings.append("M0A12F3.FREEZE.PATH_SET"); continue
        seen.add(rel); path=root/rel
        if not path.is_file(): findings.append(f"M0A12F3.FREEZE.MISSING:{rel}"); continue
        if path.stat().st_size!=item.get("bytes"): findings.append(f"M0A12F3.FREEZE.BYTES:{rel}")
        if sha256(path)!=item.get("sha256"): findings.append(f"M0A12F3.FREEZE.SHA256:{rel}")
    return len(authorities)

def baseline(root:Path,findings:list[str]):
    authority=load_required(root,AUTHORITY_PATH,findings); policy=load_required(root,POLICY_PATH,findings)
    observer=load_required(root,OBSERVER_PATH,findings); succession=load_required(root,SUCCESSION_PATH,findings)
    ledger=load_required(root,LEDGER_PATH,findings); protocol=load_required(root,PROTOCOL_PATH,findings)
    f2=load_required(root,F2_AUTHORITY_PATH,findings); f2ledger=load_required(root,F2_LEDGER_PATH,findings)
    add(findings,"M0A12F3.AUTHORITY.STANDARD",authority.get("standard")!=STANDARD)
    add(findings,"M0A12F3.AUTHORITY.STATUS",authority.get("status")!="differential-succession-harness-established-f2-accumulation-pending")
    add(findings,"M0A12F3.AUTHORITY.SOURCE",authority.get("source",{}).get("m0A12F2Head")!=F2_HEAD)
    add(findings,"M0A12F3.F2.STANDARD",f2.get("standard")!="EIGIIB-M0-A12-F2-1.0")
    add(findings,"M0A12F3.F2.SUCCESSOR",f2.get("naturalSuccessor",{}).get("id")!="M0-A12-F3")
    add(findings,"M0A12F3.POLICY.STANDARD",policy.get("standard")!="EIGIIB-M0-A12-F3-DIFFERENTIAL-POLICY-1.0")
    add(findings,"M0A12F3.POLICY.SOURCE",policy.get("sourceF2Head")!=F2_HEAD)
    add(findings,"M0A12F3.POLICY.WINDOW",{k:policy.get("window",{}).get(k) for k in ["firstSequence","lastSequence","pairedRoundCount","signedObservationCount"]}!={"firstSequence":31,"lastSequence":37,"pairedRoundCount":7,"signedObservationCount":14})
    add(findings,"M0A12F3.POLICY.CUTOVER",policy.get("succession",{}).get("cutoverSequence")!=34)
    add(findings,"M0A12F3.OBSERVER.STANDARD",observer.get("standard")!="EIGIIB-M0-A12-F3-OBSERVER-REGISTRY-1.0")
    add(findings,"M0A12F3.OBSERVER.COUNT",len(observer.get("observers",[]))!=2)
    add(findings,"M0A12F3.SUCCESSION.STANDARD",succession.get("standard")!="EIGIIB-M0-A12-F3-SUCCESSION-POLICY-1.0")
    add(findings,"M0A12F3.LEDGER.STANDARD",ledger.get("standard")!="EIGIIB-M0-A12-F3-REPLAY-LEDGER-1.0")
    add(findings,"M0A12F3.LEDGER.SOURCE",ledger.get("sourceHead")!=F2_HEAD)
    add(findings,"M0A12F3.LEDGER.PREMATURE",ledger.get("entries")!=[] or ledger.get("replayDecision")!="not-verified")
    add(findings,"M0A12F3.PROTOCOL.STANDARD",protocol.get("standard")!="EIGIIB-M0-A12-F3-HTNT-DECISION-PROTOCOL-1.0")
    add(findings,"M0A12F3.PROTOCOL.CURRENT",protocol.get("current",{}).get("label")!="NF")
    add(findings,"M0A12F3.BOUNDARY.E17",authority.get("claimBoundary",{}).get("e17Decision")!="not-ready-for-adoption")
    return policy,f2ledger

def f2_accumulated(root:Path,ledger:dict[str,Any])->bool:
    return ledger.get("accumulationDecision")=="bounded-long-horizon-preservation-accumulation-verified" and bool(ledger.get("continuityCertificateDigest")) and (root/"evidence/m0-a12-f2/continuity-certificate.json").is_file()

def verify_certificate(root:Path,replay:dict[str,Any],findings:list[str])->None:
    cert=load_required(root,CERT_PATH,findings)
    add(findings,"M0A12F3.CERT.STANDARD",cert.get("standard")!="EIGIIB-M0-A12-F3-DIFFERENTIAL-SUCCESSION-CERTIFICATE-1.0")
    add(findings,"M0A12F3.CERT.SOURCE",cert.get("sourceF2Head")!=F2_HEAD)
    for key in ["f2AnchorDigest","observerIndependenceDigest","firstSequence","lastSequence","pairedRoundCount","signedObservationCount","differentialMismatchCount","primaryLastDigest","secondaryLastDigest","successionRecordDigest","cutoverSequence","successionEffectiveAt","lastObservedAt","elapsedSeconds","lapseState"]:
        add(findings,f"M0A12F3.CERT.FIELD:{key}",cert.get(key)!=replay.get(key))
    add(findings,"M0A12F3.CERT.DECISION",cert.get("decision")!="independent-multi-observer-differential-continuity-and-custodian-succession-replay-verified")
    add(findings,"M0A12F3.CERT.BOUNDARY",cert.get("claimBoundary")!="bounded-differential-window-and-single-succession-only")
    add(findings,"M0A12F3.CERT.DIGEST",cert.get("certificateDigest")!=digest_document(cert,"certificateDigest"))

def evaluate(root:Path,as_of:datetime|None=None)->dict[str,Any]:
    findings=[]; policy,f2ledger=baseline(root,findings); authority_count=verify_freeze(root,findings)
    accumulated=f2_accumulated(root,f2ledger); evidence_present=(root/"evidence/m0-a12-f3").exists()
    paired=0; signed=0; mismatches=0; state="blocked"; result="f2-accumulation-pending"
    if findings:
        structural="nonconformant"; label="F"
    elif not accumulated:
        if evidence_present:
            findings.append("M0A12F3.EVIDENCE.BEFORE_F2_ACCUMULATION")
            structural="nonconformant-external-evidence"; label="NT"; result="premature-or-conflicting-differential-evidence"
        else:
            structural="conformant-blocked-prerequisite"; label="NF"
    elif not evidence_present:
        structural="conformant-awaiting-differential-replay"; label="NF"; state="awaiting-sequence-31"; result="differential-and-succession-evidence-pending"
    else:
        try:
            replay=evaluate_replay(root,policy,as_of or datetime.now(timezone.utc))
            paired=replay["pairedRoundCount"]; signed=replay["signedObservationCount"]; mismatches=replay["differentialMismatchCount"]; state=replay["lapseState"]
            verify_certificate(root,replay,findings)
            if paired!=policy["window"]["pairedRoundCount"]: findings.append("M0A12F3.THRESHOLD.PAIRED_ROUNDS")
            if signed!=policy["window"]["signedObservationCount"]: findings.append("M0A12F3.THRESHOLD.SIGNED_OBSERVATIONS")
            if mismatches!=0: findings.append("M0A12F3.THRESHOLD.DIFFERENTIAL_MISMATCH")
            if replay["elapsedSeconds"]<policy["window"]["minimumElapsedSeconds"]: findings.append("M0A12F3.THRESHOLD.ELAPSED")
        except Exception as exc:
            findings.append(f"M0A12F3.REPLAY:{type(exc).__name__}:{exc}")
        if findings:
            structural="nonconformant-external-evidence"; label="NT"; result="differential-or-succession-replay-invalid-incomplete-or-lapsed"
        elif state in {"current","grace"}:
            structural="conformant"; label="T"; result="independent-multi-observer-differential-continuity-and-custodian-succession-replay-verified"
        else:
            structural="nonconformant-external-evidence"; label="NT"; result="differential-window-not-current"
    return {"standard":REPORT_STANDARD,"structural_result":structural,"replay_result":result,"htntLabel":label,"findings":sorted(set(findings)),
      "summary":{"sourceF2Head":F2_HEAD,"prerequisiteF2Accumulated":accumulated,"pairedRounds":paired,"requiredPairedRounds":7,"signedObservations":signed,"requiredSignedObservations":14,"differentialMismatchCount":mismatches,"cutoverSequence":34,"lapseState":state,"authorityCount":authority_count,"e17Decision":"not-ready-for-adoption"}}

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("root",nargs="?",default="."); parser.add_argument("--as-of"); parser.add_argument("--output"); parser.add_argument("--require-verified",action="store_true"); args=parser.parse_args()
    report=evaluate(Path(args.root),parse_time(args.as_of) if args.as_of else None)
    encoded=json.dumps(report,indent=2,sort_keys=True)+"\n"
    if args.output: Path(args.output).write_text(encoded,encoding="utf-8",newline="\n")
    else: print(encoded,end="")
    if report["structural_result"].startswith("nonconformant"): return 1
    if args.require_verified and report["replay_result"]!="independent-multi-observer-differential-continuity-and-custodian-succession-replay-verified": return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
