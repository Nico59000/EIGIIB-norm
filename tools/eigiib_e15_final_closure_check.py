#!/usr/bin/env python3
"""Validate E15-A5 differential closure and final E15 authority freeze."""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-E15-A5-CLOSURE-1.0"; MATRIX_STANDARD="EIGIIB-E15-A5-1.0"; TRANSITION_STANDARD="EIGIIB-E15-A5-TRANSITION-1.0"; FREEZE_STANDARD="EIGIIB-E15-A5-FREEZE-1.0"; HISTORY_STANDARD="EIGIIB-E15-A5-HISTORICAL-E15-A4-REPLAY-1.0"; PROFILE_REVISION="EIGIIB-E15-1.0"; SOURCE_A4="fce0ba52930e32069b54ab8f5634501a130222a7"
EXPECTED_FREEZE_PATHS: set[str] = {
    '.github/workflows/e15-a1-delivery-intent.yml',
    '.github/workflows/e15-a2-delivery-evidence.yml',
    '.github/workflows/e15-a3-publication-readback.yml',
    '.github/workflows/e15-a4-withdrawal-governance.yml',
    '.github/workflows/e15-a5-final-closure.yml',
    '.github/workflows/eigiib.yml',
    '.github/workflows/m0-a6-e15-entry-normalization.yml',
    'EIGIIB.toml',
    'conformance/E15-A1-MANUAL-REVIEW.md',
    'conformance/E15-A2-MANUAL-REVIEW.md',
    'conformance/E15-A3-MANUAL-REVIEW.md',
    'conformance/E15-A4-MANUAL-REVIEW.md',
    'conformance/E15-A5-MANUAL-REVIEW.md',
    'conformance/M0-A6-MANUAL-REVIEW.md',
    'conformance/delivery-evidence.json',
    'conformance/delivery-intent.json',
    'conformance/e15-a1-adoption-transition.json',
    'conformance/e15-a1-authority-freeze.json',
    'conformance/e15-a2-adoption-transition.json',
    'conformance/e15-a2-authority-freeze.json',
    'conformance/e15-a3-adoption-transition.json',
    'conformance/e15-a3-authority-freeze.json',
    'conformance/e15-a4-adoption-transition.json',
    'conformance/e15-a4-authority-freeze.json',
    'conformance/e15-a5-adoption-transition.json',
    'conformance/e15-a5-verifier-matrix.json',
    'conformance/e15-final-closure.json',
    'conformance/extension-graph.json',
    'conformance/m0-a6-e15-entry.json',
    'conformance/publication-readback.json',
    'conformance/withdrawal-governance.json',
    'docs/E15-A1-HUMAN-MASTERY-GUIDE.md',
    'docs/E15-A2-HUMAN-MASTERY-GUIDE.md',
    'docs/E15-A3-HUMAN-MASTERY-GUIDE.md',
    'docs/E15-A4-HUMAN-MASTERY-GUIDE.md',
    'docs/E15-A5-HUMAN-MASTERY-GUIDE.md',
    'docs/E15-FINAL-CLOSURE-REPORT.md',
    'docs/M0-A6-E15-NORMATIVE-ENTRY-NORMALIZATION-AND-AUTHORITY-CONTINUITY.md',
    'docs/M0-A6-HUMAN-MASTERY-GUIDE.md',
    'extensions/E15-A5-INDEPENDENT-EXTERNAL-EVIDENCE-VERIFIER-MATRIX-FINAL-AUTHORITY-FREEZE.md',
    'extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md',
    'schemas/eigiib-e15-a1-adoption-transition.schema.json',
    'schemas/eigiib-e15-a1-authority-freeze.schema.json',
    'schemas/eigiib-e15-a1-delivery-intent.schema.json',
    'schemas/eigiib-e15-a2-adoption-transition.schema.json',
    'schemas/eigiib-e15-a2-authority-freeze.schema.json',
    'schemas/eigiib-e15-a2-delivery-evidence.schema.json',
    'schemas/eigiib-e15-a3-adoption-transition.schema.json',
    'schemas/eigiib-e15-a3-authority-freeze.schema.json',
    'schemas/eigiib-e15-a3-publication-readback.schema.json',
    'schemas/eigiib-e15-a4-adoption-transition.schema.json',
    'schemas/eigiib-e15-a4-authority-freeze.schema.json',
    'schemas/eigiib-e15-a4-withdrawal-governance.schema.json',
    'schemas/eigiib-e15-a5-adoption-transition.schema.json',
    'schemas/eigiib-e15-a5-authority-freeze.schema.json',
    'schemas/eigiib-e15-a5-final-closure.schema.json',
    'schemas/eigiib-e15-a5-verifier-matrix.schema.json',
    'schemas/eigiib-m0-a6-e15-entry.schema.json',
    'tests/fixtures/e15-a1/expected-report.json',
    'tests/fixtures/e15-a2/expected-report.json',
    'tests/fixtures/e15-a3/expected-report.json',
    'tests/fixtures/e15-a4/expected-report.json',
    'tests/fixtures/e15-a5/expected-closure-report.json',
    'tests/fixtures/e15-a5/expected-matrix-report.json',
    'tests/fixtures/m0-a6/expected-report.json',
    'tests/test_eigiib_delivery_evidence.py',
    'tests/test_eigiib_delivery_intent.py',
    'tests/test_eigiib_e15_final_closure.py',
    'tests/test_eigiib_e15_verifier_matrix.py',
    'tests/test_eigiib_m0_a6.py',
    'tests/test_eigiib_publication_readback.py',
    'tests/test_eigiib_withdrawal_governance.py',
    'tools/eigiib_delivery_evidence_check.py',
    'tools/eigiib_delivery_intent_check.py',
    'tools/eigiib_e15_external_evidence_independent.py',
    'tools/eigiib_e15_external_evidence_reference.py',
    'tools/eigiib_e15_final_closure_check.py',
    'tools/eigiib_e15_verifier_matrix.py',
    'tools/eigiib_historical_e14_replay.py',
    'tools/eigiib_historical_e15_a1_replay.py',
    'tools/eigiib_historical_e15_a2_replay.py',
    'tools/eigiib_historical_e15_a3_replay.py',
    'tools/eigiib_historical_e15_a4_replay.py',
    'tools/eigiib_m0_a6_check.py',
    'tools/eigiib_publication_readback_check.py',
    'tools/eigiib_withdrawal_governance_check.py',
}
EXPECTED_AUTHORITIES={
 "e15":"extensions/E15-EXTERNALLY-ATTESTED-DELIVERY-DURABLE-PUBLICATION-RECIPIENT-ACKNOWLEDGEMENT-WITHDRAWAL-GOVERNANCE.md",
 "e15_a5_contract":"extensions/E15-A5-INDEPENDENT-EXTERNAL-EVIDENCE-VERIFIER-MATRIX-FINAL-AUTHORITY-FREEZE.md",
 "e15_final_closure":"conformance/e15-final-closure.json",
 "e15_a5_verifier_matrix":"conformance/e15-a5-verifier-matrix.json",
 "e15_a5_transition":"conformance/e15-a5-adoption-transition.json",
 "e15_a5_authority_freeze":"conformance/e15-a5-authority-freeze.json",
 "e15_a5_human_mastery":"docs/E15-A5-HUMAN-MASTERY-GUIDE.md",
 "e15_final_closure_report":"docs/E15-FINAL-CLOSURE-REPORT.md",
}
@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str

class Checker:
    def __init__(self,root:Path,history_report:Path): self.root=root.resolve(); self.history_report=history_report; self.findings=[]
    def add(self,code:str,message:str,path:str=""): self.findings.append(Finding("error",code,path,message))
    def confined(self,rel:str,code:str,must=True)->Path|None:
        if not isinstance(rel,str) or not rel or Path(rel).is_absolute(): self.add(code+".PATH","path must be repository-relative",str(rel)); return None
        p=(self.root/rel).resolve(strict=False)
        try: p.relative_to(self.root)
        except ValueError: self.add(code+".PATH","path escapes repository root",rel); return None
        if must and not p.is_file(): self.add(code+".MISSING","required file is missing",rel); return None
        return p
    def load(self,rel:str,code:str)->dict[str,Any]|None:
        p=self.confined(rel,code)
        if p is None: return None
        try: v=json.loads(p.read_text(encoding="utf-8"),parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
        except Exception as exc: self.add(code+".PARSE",str(exc),rel); return None
        if not isinstance(v,dict): self.add(code+".TYPE","JSON root must be an object",rel); return None
        return v
    def profile(self):
        p=self.confined("EIGIIB.toml","E15A5.PROFILE")
        if p is None: return
        try: v=tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception as exc: self.add("E15A5.PROFILE.PARSE",str(exc),"EIGIIB.toml"); return
        if v.get("revision")!=PROFILE_REVISION: self.add("E15A5.PROFILE.REVISION",f"revision must be {PROFILE_REVISION}","EIGIIB.toml")
        if "E15-1.0" not in v.get("extensions",[]): self.add("E15A5.PROFILE.EXTENSION","E15-1.0 must be adopted","EIGIIB.toml")
        auth=v.get("authorities",{}); req=v.get("required_authorities",[])
        for k,path in EXPECTED_AUTHORITIES.items():
            if not isinstance(auth,dict) or auth.get(k)!=path: self.add("E15A5.PROFILE.AUTHORITY",f"{k} must map to {path}","EIGIIB.toml")
            if not isinstance(req,list) or k not in req: self.add("E15A5.PROFILE.REQUIRED",f"{k} must be required","EIGIIB.toml")
        gates=v.get("manual_gates",[]); exact=("complete","e15_a5_contract","conformance/E15-A5-MANUAL-REVIEW.md")
        got={(g.get("status"),g.get("authority"),g.get("attestation")) for g in gates if isinstance(g,dict) and g.get("id")=="e15-a5-final-closure-review"}
        if got!={exact}: self.add("E15A5.PROFILE.GATE","final closure manual gate is missing or inexact","EIGIIB.toml")
    def transition(self):
        v=self.load("conformance/e15-a5-adoption-transition.json","E15A5.TRANSITION")
        if v is None:return
        if v.get("standard")!=TRANSITION_STANDARD or v.get("status")!="adopted-final-e15": self.add("E15A5.TRANSITION.HEADER","unexpected transition header","conformance/e15-a5-adoption-transition.json")
        s=v.get("source",{}); t=v.get("target",{})
        if not isinstance(s,dict) or s.get("head_commit")!=SOURCE_A4 or s.get("profile_revision")!="EIGIIB-E15-draft-1.3": self.add("E15A5.TRANSITION.SOURCE","source A4 binding mismatch","conformance/e15-a5-adoption-transition.json")
        if not isinstance(t,dict) or t.get("profile_revision")!=PROFILE_REVISION or t.get("checker")!="tools/eigiib_e15_final_closure_check.py" or t.get("adoption_state")!="final": self.add("E15A5.TRANSITION.TARGET","final target mismatch","conformance/e15-a5-adoption-transition.json")
        d=v.get("differential_verification",{})
        if d!={"verifier_count":2,"implementations_import_each_other":False,"frozen_expected_states_required":True,"known_negative_precedence_required":True}: self.add("E15A5.TRANSITION.MATRIX","differential contract mismatch","conformance/e15-a5-adoption-transition.json")
    def closure(self):
        v=self.load("conformance/e15-final-closure.json","E15A5.CLOSURE")
        if v is None:return
        exact={"standard":STANDARD,"status":"final-frozen-closure","source_e15_a4_commit":SOURCE_A4,"profile_revision":PROFILE_REVISION,"historical_replay_tool":"tools/eigiib_historical_e15_a4_replay.py","reference_verifier":"tools/eigiib_e15_external_evidence_reference.py","independent_verifier":"tools/eigiib_e15_external_evidence_independent.py","matrix_runner":"tools/eigiib_e15_verifier_matrix.py","matrix_catalog":"conformance/e15-a5-verifier-matrix.json","final_state":"closed"}
        for k,x in exact.items():
            if v.get(k)!=x:self.add("E15A5.CLOSURE.FIELD",f"{k} must be {x}","conformance/e15-final-closure.json")
        if not isinstance(v.get("nonclaims"),list) or len(v["nonclaims"])<10:self.add("E15A5.CLOSURE.NONCLAIMS","nonclaims are incomplete","conformance/e15-final-closure.json")
    def history(self)->str:
        v=self.load(self.history_report.as_posix(),"E15A5.HISTORY")
        if v is None:return "non-conformant"
        exact={"standard":HISTORY_STANDARD,"source_commit":SOURCE_A4,"materialization":"git-archive-isolated-tree","ancestry_result":"conformant","historical_e14_result":"conformant","e15_a1_result":"conformant","e15_a2_result":"conformant","e15_a3_result":"conformant","e15_a4_result":"conformant","e15_a4_tests_result":"conformant","overall_result":"conformant"}
        for k,x in exact.items():
            if v.get(k)!=x:self.add("E15A5.HISTORY.FIELD",f"{k} must be {x}",self.history_report.as_posix())
        if v.get("findings")!=[]: self.add("E15A5.HISTORY.FINDINGS","historical report must have no findings",self.history_report.as_posix())
        return "non-conformant" if any(f.code.startswith("E15A5.HISTORY") for f in self.findings) else "conformant"
    def matrix(self)->dict[str,Any]:
        path=self.root/"tools/eigiib_e15_verifier_matrix.py"; spec=importlib.util.spec_from_file_location("eigiib_e15_verifier_matrix",path)
        if spec is None or spec.loader is None: self.add("E15A5.MATRIX.IMPORT","cannot load matrix runner",str(path)); return {}
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        report=module.run_matrix(self.root,Path("conformance/e15-a5-verifier-matrix.json"))
        if report.get("structural_result")!="conformant" or report.get("verifier_count")!=2 or report.get("case_count")!=report.get("matched_case_count"):
            self.add("E15A5.MATRIX.RESULT","verifier matrix is non-conformant","conformance/e15-a5-verifier-matrix.json")
        return report
    def freeze(self)->str:
        v=self.load("conformance/e15-a5-authority-freeze.json","E15A5.FREEZE")
        if v is None:return "non-conformant"
        if v.get("standard")!=FREEZE_STANDARD or v.get("status")!="frozen" or v.get("profile_revision")!=PROFILE_REVISION or v.get("source")!={"e15_a4_head_commit":SOURCE_A4}: self.add("E15A5.FREEZE.HEADER","unexpected freeze header","conformance/e15-a5-authority-freeze.json")
        entries=v.get("authorities"); indexed={}
        if not isinstance(entries,list): self.add("E15A5.FREEZE.TYPE","authorities must be an array","conformance/e15-a5-authority-freeze.json"); entries=[]
        for pos,e in enumerate(entries):
            if not isinstance(e,dict) or not isinstance(e.get("path"),str) or not e["path"]: self.add("E15A5.FREEZE.ITEM","invalid authority entry",str(pos)); continue
            rel=e["path"]
            if rel in indexed:self.add("E15A5.FREEZE.DUPLICATE","duplicate frozen path",rel);continue
            indexed[rel]=e; p=self.confined(rel,"E15A5.FREEZE")
            if p is None:continue
            raw=p.read_bytes()
            if e.get("bytes")!=len(raw):self.add("E15A5.FREEZE.BYTES","frozen byte length mismatch",rel)
            if e.get("sha256")!=hashlib.sha256(raw).hexdigest():self.add("E15A5.FREEZE.DIGEST","frozen SHA-256 mismatch",rel)
        for rel in sorted(EXPECTED_FREEZE_PATHS-set(indexed)):self.add("E15A5.FREEZE.MISSING","required final authority is not frozen",rel)
        for rel in sorted(set(indexed)-EXPECTED_FREEZE_PATHS):self.add("E15A5.FREEZE.EXTRA","unexpected final authority is frozen",rel)
        return "non-conformant" if any(f.code.startswith("E15A5.FREEZE") for f in self.findings) else "conformant"
    def run(self)->dict[str,Any]:
        self.profile(); self.transition(); self.closure(); history=self.history(); matrix=self.matrix(); freeze=self.freeze(); errors=bool(self.findings)
        return {"tool":"eigiib-e15-final-closure-check","tool_version":TOOL_VERSION,"standard":STANDARD,"structural_result":"non-conformant" if errors else "conformant","historical_continuity_result":history,"verifier_matrix_result":matrix.get("verifier_matrix_result","non-conformant"),"authority_freeze_result":freeze,"final_closure_result":"non-conformant" if errors else "conformant","verifier_count":matrix.get("verifier_count",0),"case_count":matrix.get("case_count",0),"matched_case_count":matrix.get("matched_case_count",0),"findings":[asdict(f) for f in sorted(self.findings)]}

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("root",nargs="?",default="."); p.add_argument("--history-report",required=True); p.add_argument("--json",action="store_true"); a=p.parse_args(argv)
    report=Checker(Path(a.root),Path(a.history_report)).run(); print(json.dumps(report,indent=2,sort_keys=True)); return 0 if report["structural_result"]=="conformant" else 1
if __name__=="__main__": raise SystemExit(main())
