import base64
import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import eigiib_scitt_receipt as m


class P1A3ReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p1a2 = (ROOT / "tests/fixtures/p1-a2/bundle.json").read_bytes()
        cls.issuer = ROOT / "tests/fixtures/p1-a3/issuer-public-key.pem"
        cls.ts = ROOT / "tests/fixtures/p1-a3/ts-public-key.pem"
        cls.capsule = json.loads((ROOT / "tests/fixtures/p1-a3/capsule.json").read_text())

    def verify(self, obj=None, p1a2=None, issuer=None, ts=None):
        return m.validate_capsule(
            copy.deepcopy(obj or self.capsule),
            self.p1a2 if p1a2 is None else p1a2,
            issuer or self.issuer,
            ts or self.ts,
        )

    def codes(self, out):
        return {f["code"] for f in out["findings"]}

    def test_valid_fixture(self):
        out = self.verify()
        self.assertEqual(out["structural_result"], "conformant")
        self.assertEqual(out["signed_statement_signature_result"], "valid")
        self.assertEqual(out["receipt_signature_result"], "valid")
        self.assertEqual(out["inclusion_result"], "verified")
        self.assertEqual(out["registration_evidence_result"], "receipt-bound")
        self.assertEqual(out["append_only_result"], "not-evaluated-by-p1-a3")

    def test_p1a2_identity_mismatch(self):
        obj = copy.deepcopy(self.capsule)
        obj["binding"]["p1A2Bundle"]["digest"] = "0" * 64
        out = self.verify(obj)
        self.assertIn("P1A3.BINDING.P1A2_MISMATCH", self.codes(out))

    def test_p1a2_shape_invalid(self):
        bad = json.dumps({"standard": "wrong"}).encode()
        out = self.verify(p1a2=bad)
        self.assertIn("P1A3.P1A2.INVALID", self.codes(out))

    def test_statement_signature_mutation(self):
        obj = copy.deepcopy(self.capsule)
        raw = bytearray(base64.b64decode(obj["signedStatement"]["data"]))
        raw[-1] ^= 1
        obj["signedStatement"]["data"] = base64.b64encode(raw).decode()
        obj["signedStatement"]["identity"] = m.identity(bytes(raw))
        out = self.verify(obj)
        self.assertIn("P1A3.STATEMENT.INVALID", self.codes(out))

    def test_receipt_signature_mutation(self):
        obj = copy.deepcopy(self.capsule)
        raw = bytearray(base64.b64decode(obj["receipt"]["data"]))
        raw[-1] ^= 1
        obj["receipt"]["data"] = base64.b64encode(raw).decode()
        obj["receipt"]["identity"] = m.identity(bytes(raw))
        out = self.verify(obj)
        self.assertIn("P1A3.RECEIPT.INVALID", self.codes(out))

    def test_statement_identity_mismatch(self):
        obj = copy.deepcopy(self.capsule)
        obj["signedStatement"]["identity"]["bytes"] += 1
        out = self.verify(obj)
        self.assertIn("P1A3.STATEMENT.IDENTITY_MISMATCH", self.codes(out))

    def test_receipt_identity_mismatch(self):
        obj = copy.deepcopy(self.capsule)
        obj["receipt"]["identity"]["bytes"] += 1
        out = self.verify(obj)
        self.assertIn("P1A3.RECEIPT.IDENTITY_MISMATCH", self.codes(out))

    def test_issuer_key_identity_mismatch(self):
        obj = copy.deepcopy(self.capsule)
        obj["signedStatement"]["issuerKeySpki"]["digest"] = "0" * 64
        out = self.verify(obj)
        self.assertIn("P1A3.STATEMENT.KEY_MISMATCH", self.codes(out))

    def test_ts_key_identity_mismatch(self):
        obj = copy.deepcopy(self.capsule)
        obj["receipt"]["transparencyServiceKeySpki"]["digest"] = "0" * 64
        out = self.verify(obj)
        self.assertIn("P1A3.RECEIPT.KEY_MISMATCH", self.codes(out))

    def test_wrong_tree_binding(self):
        obj = copy.deepcopy(self.capsule)
        obj["binding"]["treeSize"] = 2
        out = self.verify(obj)
        self.assertIn("P1A3.BINDING.PROOF_MISMATCH", self.codes(out))

    def test_wrong_leaf_binding(self):
        obj = copy.deepcopy(self.capsule)
        obj["binding"]["leafIndex"] = 1
        out = self.verify(obj)
        self.assertIn("P1A3.BINDING.PROOF_MISMATCH", self.codes(out))

    def test_location_binding(self):
        obj = copy.deepcopy(self.capsule)
        obj["registration"]["location"] = "https://transparency.example/entries/" + "0" * 64
        out = self.verify(obj)
        self.assertIn("P1A3.REG.LOCATION_BINDING", self.codes(out))

    def test_http_status_not_alternate(self):
        obj = copy.deepcopy(self.capsule)
        obj["registration"]["status"] = 202
        out = self.verify(obj)
        self.assertIn("P1A3.REG.VALUE", self.codes(out))

    def test_request_media_type(self):
        obj = copy.deepcopy(self.capsule)
        obj["registration"]["requestMediaType"] = "application/cose"
        out = self.verify(obj)
        self.assertIn("P1A3.REG.VALUE", self.codes(out))

    def test_receipt_media_type(self):
        obj = copy.deepcopy(self.capsule)
        obj["registration"]["receiptMediaType"] = "application/cose"
        out = self.verify(obj)
        self.assertIn("P1A3.REG.VALUE", self.codes(out))

    def test_boundary_weakening(self):
        obj = copy.deepcopy(self.capsule)
        obj["claimBoundary"]["doesNotImply"] = obj["claimBoundary"]["doesNotImply"][:-1]
        out = self.verify(obj)
        self.assertIn("P1A3.BOUNDARY.WEAKENED", self.codes(out))

    def test_unknown_top_field(self):
        obj = copy.deepcopy(self.capsule)
        obj["trusted"] = True
        out = self.verify(obj)
        self.assertIn("P1A3.CAPSULE.FIELD", self.codes(out))

    def test_invalid_statement_base64(self):
        obj = copy.deepcopy(self.capsule)
        obj["signedStatement"]["data"] = "!" + obj["signedStatement"]["data"]
        out = self.verify(obj)
        self.assertIn("P1A3.STATEMENT.BASE64", self.codes(out))

    def test_noncanonical_receipt_base64(self):
        obj = copy.deepcopy(self.capsule)
        obj["receipt"]["data"] = obj["receipt"]["data"].rstrip("=")
        out = self.verify(obj)
        self.assertIn("P1A3.RECEIPT.BASE64", self.codes(out))

    def test_duplicate_json_members_rejected(self):
        with self.assertRaises(ValueError):
            m.strict_json_loads(b'{"a":1,"a":2}')

    def test_positive_outputs_suppressed_on_error(self):
        obj = copy.deepcopy(self.capsule)
        obj["claimBoundary"]["authority"] = "e6"
        out = self.verify(obj)
        self.assertEqual(out["structural_result"], "non-conformant")
        self.assertEqual(out["receipt_signature_result"], "not-evaluated")
        self.assertEqual(out["inclusion_result"], "not-evaluated")
        self.assertEqual(out["registration_evidence_result"], "not-evaluated")


if __name__ == "__main__":
    unittest.main()
