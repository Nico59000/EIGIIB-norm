from __future__ import annotations

import base64
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
TOOL = HERE.parents[1] / "tools" / "eigiib_in_toto_capsule.py"
spec = importlib.util.spec_from_file_location("p1a1", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

RAW = (
    b'{\n'
    b'  "tool": "eigiib-aggregate",\n'
    b'  "tool_version": "0.1.2",\n'
    b'  "standard": "EIGIIB-M0-A2-1.0",\n'
    b'  "kind": "derived-conformance-report",\n'
    b'  "source_graph": "conformance/extension-graph.json",\n'
    b'  "results_dir": ".eigiib-results/components",\n'
    b'  "overall_result": "conformant",\n'
    b'  "summary": {"expected": 1, "present": 1, "pass": 1, "qualified": 0, "incomplete": 0, "fail": 0, "unsupported": 0},\n'
    b'  "components": [],\n'
    b'  "findings": []\n'
    b'}\n'
)


class CapsuleTests(unittest.TestCase):
    def capsule(self):
        return mod.build_capsule(RAW, "aggregate.json")

    def codes(self, obj, source=None):
        return {f["code"] for f in mod.validate_capsule(obj, source)["findings"]}

    def test_build_and_verify(self):
        c = self.capsule()
        self.assertEqual("conformant", mod.validate_capsule(c, RAW)["structural_result"])

    def test_statement_type(self):
        self.assertEqual(mod.STATEMENT_TYPE, self.capsule()["statement"]["_type"])

    def test_predicate_type(self):
        self.assertEqual(mod.PREDICATE_TYPE, self.capsule()["statement"]["predicateType"])

    def test_transport_is_exact_bytes(self):
        data = self.capsule()["statement"]["predicate"]["aggregateReport"]["data"]
        self.assertEqual(RAW, base64.b64decode(data))

    def test_subject_digest_binds_exact_bytes(self):
        c1 = mod.build_capsule(RAW, "aggregate.json")
        c2 = mod.build_capsule(RAW + b" ", "aggregate.json")
        d1 = c1["statement"]["subject"][0]["digest"]["sha256"]
        d2 = c2["statement"]["subject"][0]["digest"]["sha256"]
        self.assertNotEqual(d1, d2)

    def test_reject_wrong_source_standard(self):
        raw = RAW.replace(b"EIGIIB-M0-A2-1.0", b"WRONG")
        with self.assertRaises(ValueError):
            mod.build_capsule(raw, "aggregate.json")

    def test_reject_wrong_source_result(self):
        raw = RAW.replace(b'"conformant"', b'"maybe"')
        with self.assertRaises(ValueError):
            mod.build_capsule(raw, "aggregate.json")

    def test_reject_subject_digest_mismatch(self):
        c = self.capsule()
        c["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
        self.assertIn("P1A1.STATEMENT.SUBJECT_MISMATCH", self.codes(c))

    def test_reject_identity_mismatch(self):
        c = self.capsule()
        c["statement"]["predicate"]["aggregateReport"]["identity"]["bytes"] += 1
        self.assertIn("P1A1.REPORT.IDENTITY_MISMATCH", self.codes(c))

    def test_reject_weakened_boundary(self):
        c = self.capsule()
        c["statement"]["predicate"]["claimBoundary"]["doesNotImply"].pop()
        self.assertIn("P1A1.BOUNDARY.WEAKENED", self.codes(c))

    def test_reject_invalid_base64(self):
        c = self.capsule()
        c["statement"]["predicate"]["aggregateReport"]["data"] = "!!!"
        self.assertIn("P1A1.REPORT.BASE64", self.codes(c))

    def test_reject_result_mismatch(self):
        c = self.capsule()
        c["statement"]["predicate"]["aggregateResult"]["value"] = "non-conformant"
        self.assertIn("P1A1.RESULT.MISMATCH", self.codes(c))

    def test_reject_envelope_field(self):
        c = self.capsule()
        c["envelope"] = {"signatures": []}
        self.assertIn("P1A1.CAPSULE.FIELD", self.codes(c))

    def test_authentication_is_explicitly_absent(self):
        self.assertEqual("not-provided-p1-a1", self.capsule()["authentication_state"])

    def test_source_argument_detects_different_bytes(self):
        c = self.capsule()
        self.assertIn("P1A1.SOURCE.MISMATCH", self.codes(c, RAW + b"\n"))

    def test_deterministic_output(self):
        self.assertEqual(self.capsule(), self.capsule())


if __name__ == "__main__":
    unittest.main()
