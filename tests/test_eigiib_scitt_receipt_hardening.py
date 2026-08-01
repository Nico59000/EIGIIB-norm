import base64
import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import eigiib_scitt_receipt as p1a3
import eigiib_scitt_receipt_hardening_check as h


class P1A3HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p1a3_obj = json.loads((ROOT / "tests/fixtures/p1-a3/capsule.json").read_text())
        cls.p1a2_raw = (ROOT / "tests/fixtures/p1-a2/bundle.json").read_bytes()
        cls.p1a1_raw = (ROOT / "tests/fixtures/p1-a1/capsule.json").read_bytes()
        cls.p1a2_key = ROOT / "tests/fixtures/p1-a2/public-key.pem"
        cls.issuer_key = ROOT / "tests/fixtures/p1-a3/issuer-public-key.pem"
        cls.ts_key = ROOT / "tests/fixtures/p1-a3/ts-public-key.pem"

    def validate(self, p1a3_obj=None, p1a2_raw=None, p1a1_raw=None, p1a2_key=None):
        return h.validate_hardened(
            copy.deepcopy(self.p1a3_obj if p1a3_obj is None else p1a3_obj),
            self.p1a2_raw if p1a2_raw is None else p1a2_raw,
            self.p1a1_raw if p1a1_raw is None else p1a1_raw,
            self.p1a2_key if p1a2_key is None else p1a2_key,
            self.issuer_key,
            self.ts_key,
        )

    def codes(self, out):
        return {f["code"] for f in out["findings"]}

    def test_hardened_fixture_positive(self):
        out = self.validate()
        self.assertEqual(out["hardening_result"], "conformant")
        self.assertEqual(out["upstream_p1a2_authentication_result"], "valid")
        self.assertEqual(out["p1a3_baseline_result"], "conformant")

    def test_wrong_p1a2_key_rejected_upstream(self):
        out = self.validate(p1a2_key=self.issuer_key)
        self.assertIn("P1A3H.UPSTREAM.INVALID", self.codes(out))
        self.assertEqual(out["p1a3_baseline_result"], "not-evaluated")

    def test_tampered_p1a1_rejected_upstream(self):
        obj = json.loads(self.p1a1_raw)
        obj["authentication_state"] = "forged"
        raw = json.dumps(obj, indent=2, sort_keys=True).encode() + b"\n"
        out = self.validate(p1a1_raw=raw)
        self.assertIn("P1A3H.UPSTREAM.INVALID", self.codes(out))

    def test_tampered_p1a2_signature_rejected_upstream(self):
        obj = json.loads(self.p1a2_raw)
        sig = bytearray(base64.b64decode(obj["bundle"]["dsseEnvelope"]["signatures"][0]["sig"]))
        sig[0] ^= 1
        obj["bundle"]["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(sig).decode()
        raw = json.dumps(obj, indent=2, sort_keys=True).encode() + b"\n"
        out = self.validate(p1a2_raw=raw)
        self.assertIn("P1A3H.UPSTREAM.INVALID", self.codes(out))

    def test_baseline_failure_remains_failure_after_valid_upstream(self):
        obj = copy.deepcopy(self.p1a3_obj)
        obj["claimBoundary"]["authority"] = "e6"
        out = self.validate(p1a3_obj=obj)
        self.assertIn("P1A3H.BASELINE.INVALID", self.codes(out))
        self.assertEqual(out["upstream_p1a2_authentication_result"], "valid")


if __name__ == "__main__":
    unittest.main()
