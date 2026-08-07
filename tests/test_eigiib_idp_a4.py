from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "conformance/idp-a4-public-transparency.json"
PRIVATE = ROOT / "tests/fixtures/idp-a4/synthetic-private-witness.json"
MATRIX = ROOT / "conformance/idp-a4-verifier-matrix.json"


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


REF = module("idp_a4_ref_test", ROOT / "tools/eigiib_idp_a4_check.py")
IND = module("idp_a4_ind_test", ROOT / "tools/eigiib_idp_a4_independent.py")
MAT = module("idp_a4_matrix_test", ROOT / "tools/eigiib_idp_a4_matrix.py")


class IDPA4Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.public = json.loads(PUBLIC.read_text(encoding="utf-8"))
        self.private = json.loads(PRIVATE.read_text(encoding="utf-8"))

    def test_reference_and_independent_accept_base(self) -> None:
        self.assertEqual(REF.evaluate(self.public, self.private), [])
        ok, reason = IND.decide(self.public, self.private)
        self.assertTrue(ok, reason)

    def test_same_payload_has_distinct_salted_commitments(self) -> None:
        witnesses = self.private["witnesses"]
        self.assertEqual(witnesses[0]["payloadDigest"], witnesses[1]["payloadDigest"])
        self.assertNotEqual(witnesses[0]["salt"], witnesses[1]["salt"])
        commitments = [r["commitment"] for r in self.public["records"]]
        self.assertNotEqual(commitments[0], commitments[1])
        for record, witness in zip(self.public["records"], witnesses, strict=True):
            self.assertEqual(record["commitment"], REF.commitment(record["recordId"], witness["salt"], witness["payloadDigest"]))

    def test_withdrawal_is_append_only_not_deletion(self) -> None:
        withdrawn = next(r for r in self.public["records"] if r["state"] == "withdrawn")
        event = next(w for w in self.public["withdrawals"] if w["recordId"] == withdrawn["recordId"])
        self.assertEqual(withdrawn["withdrawalId"], event["withdrawalId"])

    def test_matrix_mutations_are_differentially_fail_closed(self) -> None:
        matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        for case in matrix["cases"]:
            bundle = {"public": copy.deepcopy(self.public), "private": copy.deepcopy(self.private)}
            MAT.apply(bundle, case.get("mutation"))
            ref = "conformant" if not REF.evaluate(bundle["public"], bundle["private"]) else "nonconformant"
            ind_ok, _ = IND.decide(bundle["public"], bundle["private"])
            independent = "conformant" if ind_ok else "nonconformant"
            self.assertEqual(ref, case["expected"], case["id"])
            self.assertEqual(independent, case["expected"], case["id"])

    def test_public_boundary_rejects_internal_classification(self) -> None:
        mutated = copy.deepcopy(self.public)
        mutated["records"][0]["internalClassification"] = "D4"
        self.assertTrue(REF.evaluate(mutated, self.private))
        self.assertFalse(IND.decide(mutated, self.private)[0])


if __name__ == "__main__":
    unittest.main()
