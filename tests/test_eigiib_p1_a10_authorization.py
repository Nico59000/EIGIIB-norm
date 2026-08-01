from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a10_authorization_check import validate
from eigiib_p1_a10_common import canonical_json, decode_b64, encode_b64, identity

CAPSULE = ROOT / "tests/fixtures/p1-a10/capsule.json"


class P1A10AuthorizationTests(unittest.TestCase):
    def load(self):
        return json.loads(CAPSULE.read_text(encoding="utf-8"))

    def reject(self, capsule):
        with tempfile.TemporaryDirectory(prefix="eigiib-a10-test-") as temp:
            path = Path(temp) / "capsule.json"
            path.write_bytes(canonical_json(capsule))
            with self.assertRaises((ValueError, OSError)):
                validate(ROOT, path)

    def test_positive(self):
        report = validate(ROOT, CAPSULE)
        self.assertEqual(report["overall_result"], "conformant")
        self.assertEqual(report["initial_approval_ids"], ["delegate-a", "delegate-b"])
        self.assertEqual(report["recovered_approval_ids"], ["delegate-a", "delegate-c"])

    def test_policy_signature_mutation(self):
        capsule = self.load()
        raw = bytearray(decode_b64(capsule["policy"]["envelope"]["data"]))
        raw[-1] ^= 1
        raw = bytes(raw)
        capsule["policy"]["envelope"] = {"data": encode_b64(raw), "identity": identity(raw)}
        self.reject(capsule)

    def test_duplicate_approval(self):
        capsule = self.load()
        capsule["initialAuthorization"]["approvals"][1] = copy.deepcopy(
            capsule["initialAuthorization"]["approvals"][0]
        )
        self.reject(capsule)

    def test_stale_replay_must_be_after_revocation(self):
        capsule = self.load()
        capsule["staleReplay"]["evaluationSequence"] = 10
        self.reject(capsule)

    def test_revocation_payload_mutation(self):
        capsule = self.load()
        payload = json.loads(
            decode_b64(capsule["revocation"]["payload"]["data"]).decode("utf-8")
        )
        payload["revocationSequence"] = 13
        raw = canonical_json(payload)
        capsule["revocation"]["payload"] = {
            "data": encode_b64(raw),
            "identity": identity(raw),
        }
        self.reject(capsule)

    def test_recovered_set_cannot_reuse_revoked_delegate(self):
        capsule = self.load()
        capsule["recoveredAuthorization"]["approvals"] = copy.deepcopy(
            capsule["initialAuthorization"]["approvals"]
        )
        self.reject(capsule)

    def test_release_signer_binding(self):
        capsule = self.load()
        capsule["sourceReleaseSigner"] = copy.deepcopy(capsule["trustRoot"])
        self.reject(capsule)

    def test_claim_boundary_is_required(self):
        capsule = self.load()
        capsule["claimBoundary"]["doesNotImply"] = ["too-short"]
        self.reject(capsule)


if __name__ == "__main__":
    unittest.main()
