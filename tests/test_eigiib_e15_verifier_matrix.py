from __future__ import annotations
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("eigiib_e15_verifier_matrix",ROOT/"tools/eigiib_e15_verifier_matrix.py")
assert SPEC and SPEC.loader
MATRIX=importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name]=MATRIX; SPEC.loader.exec_module(MATRIX)

class E15A5MatrixTests(unittest.TestCase):
    def test_frozen_matrix_matches(self):
        report=MATRIX.run_matrix(ROOT,Path("conformance/e15-a5-verifier-matrix.json"))
        expected=json.loads((ROOT/"tests/fixtures/e15-a5/expected-matrix-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report,expected)
        self.assertEqual(report["matched_case_count"],16)
        self.assertEqual(report["verifier_count"],2)
    def test_expected_state_mismatch_is_rejected(self):
        catalog=json.loads((ROOT/"conformance/e15-a5-verifier-matrix.json").read_text(encoding="utf-8"))
        catalog["cases"][0]["expected_state"]="rejected"
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"matrix.json"; p.write_text(json.dumps(catalog),encoding="utf-8")
            report=MATRIX.run_matrix(ROOT,p)
        self.assertEqual(report["structural_result"],"non-conformant")
    def test_duplicate_case_is_rejected(self):
        catalog=json.loads((ROOT/"conformance/e15-a5-verifier-matrix.json").read_text(encoding="utf-8"))
        catalog["cases"].append(dict(catalog["cases"][0]))
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            p=Path(td)/"matrix.json"; p.write_text(json.dumps(catalog),encoding="utf-8")
            report=MATRIX.run_matrix(ROOT,p.relative_to(ROOT))
        self.assertEqual(report["structural_result"],"non-conformant")
if __name__=="__main__": unittest.main()
