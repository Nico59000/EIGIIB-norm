#!/usr/bin/env python3
import argparse, json
from pathlib import Path
from eigiib_m0_a13_replay import verify_case

F5_HEAD = "58945ceab905cb515dff076227bb2b387f907461"
F5_TREE = "fe54597cee5546cee125284b5d084de7459505cd"
FREEZE_ID = "eigiib-m0-final-freeze-v1"
FREEZE_PATH = "conformance/m0-a13-authority-freeze.json"
REQUIRED = (
    "conformance/m0-a13-maintenance-authority.json",
    "conformance/m0-a13-maintenance-policy.json",
    "conformance/m0-a13-reopening-policy.json",
    "conformance/m0-a13-supersession-policy.json",
    "conformance/m0-a13-maintenance-ledger.json",
    "conformance/m0-a13-htnt-decision-protocol.json",
)

def load(path):
    return json.loads(path.read_text(encoding="utf-8"))

def evaluate(root):
    root = Path(root)
    findings = []
    try:
        docs = {p: load(root / p) for p in REQUIRED}
    except Exception as exc:
        return {"standard":"EIGIIB-M0-A13-REPORT-1.0","htntLabel":"F","decision":"invalid","findings":[str(exc)],"summary":{"f5FinalFreeze":"unknown","maintenanceCycles":0,"reopeningDecision":"unknown","refreezeDecision":"unknown"}}
    authority = docs[REQUIRED[0]]
    ledger = docs[REQUIRED[4]]
    try:
        freeze = load(root / FREEZE_PATH)
        authorities = freeze.get("authorities", [])
        if freeze.get("authorityCount") != len(authorities):
            findings.append("authority-freeze-count-mismatch")
        for entry in authorities:
            path = root / entry.get("path", "")
            if not path.is_file():
                findings.append("authority-freeze-path-missing")
                continue
            raw = path.read_bytes()
            import hashlib
            if len(raw) != entry.get("bytes") or hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
                findings.append("authority-freeze-digest-mismatch")
    except Exception:
        findings.append("authority-freeze-invalid")
    src = authority.get("source", {})
    if src.get("m0A12F5Head") != F5_HEAD:
        findings.append("source-head-mismatch")
    if src.get("m0A12F5Tree") != F5_TREE:
        findings.append("source-tree-mismatch")
    if src.get("finalFreezeId") != FREEZE_ID:
        findings.append("freeze-id-mismatch")
    if ledger.get("sourceHead") != F5_HEAD or ledger.get("freezeId") != FREEZE_ID:
        findings.append("ledger-anchor-mismatch")
    if ledger.get("entries") != [] or ledger.get("maintenanceCycleCount") != 0:
        findings.append("baseline-ledger-not-empty")
    f5_frozen = False
    try:
        f5 = load(root / "conformance/m0-a12-f5-ledger.json")
        f5_frozen = f5.get("adoptionDecision") == "adopted" and f5.get("finalFreezeDecision") == "frozen"
    except Exception:
        pass
    evidence = root / "evidence/m0-a13/maintenance-cycle.json"
    replay = None
    if evidence.exists():
        try:
            replay = verify_case(load(evidence))
        except Exception as exc:
            replay = {"verified":False,"errors":[str(exc)]}
    if findings:
        label, decision = "F", "invalid"
    elif replay and replay.get("verified") and f5_frozen:
        label, decision = "T", "verified"
    elif replay is not None:
        label, decision = "NT", "incomplete-or-invalid-maintenance-evidence"
    else:
        label, decision = "NF", "not-authorized"
    return {
        "standard":"EIGIIB-M0-A13-REPORT-1.0",
        "htntLabel":label,
        "decision":decision,
        "findings":findings if findings else ([] if replay is None else replay.get("errors", [])),
        "summary":{
            "f5FinalFreeze":"frozen" if f5_frozen else "not-frozen",
            "maintenanceCycles":ledger.get("maintenanceCycleCount"),
            "reopeningDecision":ledger.get("reopeningDecision"),
            "refreezeDecision":ledger.get("refreezeDecision")
        }
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--output")
    ap.add_argument("--require-verified", action="store_true")
    args = ap.parse_args()
    report = evaluate(args.root)
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if (not args.require_verified or report["htntLabel"] == "T") else 2

if __name__ == "__main__":
    raise SystemExit(main())
