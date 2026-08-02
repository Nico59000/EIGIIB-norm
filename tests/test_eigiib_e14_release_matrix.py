from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
TOOL = ROOT / "tools/eigiib_e14_release_matrix.py"
SPEC = importlib.util.spec_from_file_location("eigiib_a5_matrix", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class MatrixTests(unittest.TestCase):
    def test_frozen_matrix_matches(self):
        report = MODULE.run_matrix(ROOT, Path("conformance/e14-a5-verifier-matrix.json"))
        self.assertEqual(report["structural_result"], "conformant", report["findings"])
        self.assertEqual(report["matched_case_count"], report["case_count"])
        self.assertEqual(report["verifier_count"], 2)

    def test_expected_state_mismatch_is_rejected(self):
        catalog = json.loads((ROOT / "conformance/e14-a5-verifier-matrix.json").read_text(encoding="utf-8"))
        catalog["cases"][0]["expected_state"] = "rejected"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps(catalog), encoding="utf-8")
            report = MODULE.run_matrix(ROOT, path)
        self.assertEqual(report["structural_result"], "non-conformant")


if __name__ == "__main__":
    unittest.main()
