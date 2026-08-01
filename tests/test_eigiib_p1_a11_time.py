from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a11_common import canonical_json
from eigiib_p1_a11_time_check import validate

CAPSULE = ROOT / "tests/fixtures/p1-a11/capsule.json"


class P1A11TimeTests(unittest.TestCase):
    def load(self):
        return json.loads(CAPSULE.read_text(encoding="utf-8"))

    def check_invalid(self, value):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "capsule.json"
            path.write_bytes(canonical_json(value))
            with self.assertRaises((ValueError, OSError)):
                validate(ROOT, path)

    def test_positive(self):
        report = validate(ROOT, CAPSULE)
        self.assertEqual(report["overall_result"], "conformant")
        self.assertEqual(report["accepted_observation_ids"], ["valid-window"])
        self.assertEqual(report["clock_rollback_result"], "rejected-as-required")
        self.assertEqual(report["expiry_result"], "rejected-as-required")

    def test_policy_signature_mutation(self):
        value = self.load()
        raw = bytearray(base64.b64decode(value["policy"]["envelope"]["data"]))
        raw[-1] ^= 1
        value["policy"]["envelope"]["data"] = base64.b64encode(raw).decode()
        value["policy"]["envelope"]["identity"]["digest"] = __import__("hashlib").sha256(raw).hexdigest()
        self.check_invalid(value)

    def test_timestamp_signature_mutation(self):
        value = self.load()
        carrier = value["observations"][1]["envelope"]
        raw = bytearray(base64.b64decode(carrier["data"]))
        raw[-2] ^= 1
        carrier["data"] = base64.b64encode(raw).decode()
        carrier["identity"]["digest"] = __import__("hashlib").sha256(raw).hexdigest()
        self.check_invalid(value)

    def test_authority_identity_mutation(self):
        value = self.load()
        value["timestampAuthority"]["spki"]["digest"] = "0" * 64
        self.check_invalid(value)

    def test_source_authorization_mutation(self):
        value = self.load()
        value["sourceAuthorization"]["recoveredAuthorizationPayload"]["digest"] = "0" * 64
        self.check_invalid(value)

    def test_observation_sequence_rollback(self):
        value = self.load()
        value["observations"][2]["id"] = value["observations"][1]["id"]
        self.check_invalid(value)

    def test_expected_decision_mutation(self):
        value = self.load()
        value["observations"][2]["expectedDecision"] = "conformant"
        self.check_invalid(value)

    def test_claim_boundary_required(self):
        value = self.load()
        value["claimBoundary"]["doesNotImply"].pop()
        self.check_invalid(value)

    def test_payload_identity_mutation(self):
        value = self.load()
        value["observations"][3]["payload"]["identity"]["bytes"] += 1
        self.check_invalid(value)


if __name__ == "__main__":
    unittest.main()
