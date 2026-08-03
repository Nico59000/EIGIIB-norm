from __future__ import annotations
import importlib.util, json, shutil, sys, tempfile, tomllib, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("eigiib_e15_final_closure_check",ROOT/"tools/eigiib_e15_final_closure_check.py")
assert SPEC and SPEC.loader
CHECK=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=CHECK; SPEC.loader.exec_module(CHECK)

HISTORY={
 "tool":"eigiib-historical-e15-a4-replay","tool_version":"0.1.0","standard":CHECK.HISTORY_STANDARD,
 "source_commit":CHECK.SOURCE_A4,"materialization":"git-archive-isolated-tree","ancestry_result":"conformant",
 "historical_e14_result":"conformant","e15_a1_result":"conformant","e15_a2_result":"conformant",
 "e15_a3_result":"conformant","e15_a4_result":"conformant","e15_a4_tests_result":"conformant",
 "overall_result":"conformant","findings":[],
}

class E15A5ClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS|{"conformance/e15-a5-authority-freeze.json"}):
            src=ROOT/rel; dst=self.root/rel; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(src,dst)
        self.history=self.root/"history.json"; self.history.write_text(json.dumps(HISTORY),encoding="utf-8")
    def tearDown(self): self.tmp.cleanup()
    def checker(self): return CHECK.Checker(self.root,Path("history.json"))
    def test_final_closure_is_conformant(self):
        profile=tomllib.loads((ROOT/"EIGIIB.toml").read_text(encoding="utf-8"))
        if "E16-1.0" in profile.get("extensions",[]):
            self.skipTest("E15 current-tree closure is superseded by exact historical E16-A1 replay")
        report=self.checker().run(); self.assertEqual(report["structural_result"],"conformant",report["findings"]); self.assertEqual(report["matched_case_count"],16)
    def test_history_substitution_is_rejected(self):
        data=dict(HISTORY); data["source_commit"]="0"*40; self.history.write_text(json.dumps(data),encoding="utf-8")
        self.assertEqual(self.checker().run()["historical_continuity_result"],"non-conformant")
    def test_frozen_authority_mutation_is_rejected(self):
        (self.root/"docs/E15-A5-HUMAN-MASTERY-GUIDE.md").write_text("changed\n",encoding="utf-8")
        self.assertEqual(self.checker().run()["authority_freeze_result"],"non-conformant")
    def test_final_profile_regression_is_rejected(self):
        p=self.root/"EIGIIB.toml"; p.write_text(p.read_text().replace('revision = "EIGIIB-E15-1.0"','revision = "EIGIIB-E15-draft-1.3"'),encoding="utf-8")
        self.assertEqual(self.checker().run()["structural_result"],"non-conformant")
    def test_matrix_verifier_path_mutation_is_rejected(self):
        p=self.root/"conformance/e15-a5-verifier-matrix.json"; data=json.loads(p.read_text()); data["independent_verifier"]="tools/eigiib_e15_external_evidence_reference.py"; p.write_text(json.dumps(data),encoding="utf-8")
        self.assertEqual(self.checker().run()["verifier_matrix_result"],"non-conformant")
if __name__=="__main__": unittest.main()
