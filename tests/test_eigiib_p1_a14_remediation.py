from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a14_common import canonical_json, identity
from eigiib_p1_a14_remediation_check import evaluate

CAPSULE = ROOT / "tests/fixtures/p1-a14/capsule.json"


def write_capsule(value: dict) -> Path:
    temp = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
    temp.write(canonical_json(value))
    temp.close()
    return Path(temp.name)


def mutate_carrier(carrier: dict) -> None:
    raw = bytearray(base64.b64decode(carrier["data"]))
    raw[-1] ^= 1
    changed = bytes(raw)
    carrier["data"] = base64.b64encode(changed).decode("ascii")
    carrier["identity"] = identity(changed)


def mutate_payload_json(signed: dict, mutate) -> None:
    raw = base64.b64decode(signed["payload"]["data"])
    value = json.loads(raw)
    mutate(value)
    changed = canonical_json(value)
    signed["payload"] = {
        "data": base64.b64encode(changed).decode("ascii"),
        "identity": identity(changed),
    }


class P1A14Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = json.loads(CAPSULE.read_text(encoding="utf-8"))

    def check_rejected(self, mutate) -> None:
        value = copy.deepcopy(self.base)
        mutate(value)
        path = write_capsule(value)
        try:
            with self.assertRaises((ValueError, KeyError, TypeError)):
                evaluate(ROOT, path)
        finally:
            path.unlink(missing_ok=True)

    def test_positive(self) -> None:
        result = evaluate(ROOT, CAPSULE)
        self.assertEqual(result["overall_result"], "conformant")
        self.assertEqual(result["accepted_history"][-1], "fixed-release-sequence-43")

    def test_source_report_identity_mutation(self) -> None:
        self.check_rejected(lambda value: value["sourceAuthority"].__setitem__("revocationReportSha256", "0" * 64))

    def test_source_capsule_identity_mutation(self) -> None:
        self.check_rejected(lambda value: value["sourceAuthority"].__setitem__("revocationCapsuleSha256", "1" * 64))

    def test_policy_signature_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_carrier(value["policy"]["envelope"]))

    def test_advisory_affected_content_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_payload_json(value["advisory"], lambda payload: payload["affectedContent"].__setitem__("archiveSha256", "2" * 64)))

    def test_advisory_signature_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_carrier(value["advisory"]["envelope"]))

    def test_remediation_predecessor_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_payload_json(value["remediation"], lambda payload: payload["predecessorContent"].__setitem__("releaseId", "substituted")))

    def test_remediation_fixed_content_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_payload_json(value["remediation"], lambda payload: payload["fixedContent"].__setitem__("archiveSha256", "3" * 64)))

    def test_remediation_signature_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_carrier(value["remediation"]["envelope"]))

    def test_fixed_release_descriptor_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_payload_json(value["fixedRelease"], lambda payload: payload["descriptorArtifact"]["identity"].__setitem__("digest", "4" * 64)))

    def test_fixed_release_signature_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_carrier(value["fixedRelease"]["envelope"]))

    def test_replay_decision_mutation(self) -> None:
        self.check_rejected(lambda value: value["replays"][1].__setitem__("expectedDecision", "accepted-fixed-release"))

    def test_replay_candidate_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_carrier(value["replays"][2]["candidate"]["payload"]))

    def test_idempotent_replay_sequence_mutation(self) -> None:
        self.check_rejected(lambda value: mutate_payload_json(value["replays"][0]["candidate"], lambda payload: payload.__setitem__("candidateSequence", 44)))

    def test_claim_boundary_mutation(self) -> None:
        self.check_rejected(lambda value: value["claimBoundary"].pop())

    def test_authority_key_substitution(self) -> None:
        self.check_rejected(lambda value: value["advisoryAuthority"].__setitem__("spki", value["remediationAuthority"]["spki"]))


if __name__ == "__main__":
    unittest.main()
