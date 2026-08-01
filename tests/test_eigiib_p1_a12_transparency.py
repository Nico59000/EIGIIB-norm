from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPSULE = ROOT / "tests/fixtures/p1-a12/capsule.json"
CHECKER = ROOT / "tools/eigiib_p1_a12_transparency_check.py"
EXPECTED = ROOT / "tests/fixtures/p1-a12/expected-report.json"


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def run_capsule(value: object, *, expected: bool = False) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="eigiib-a12-test-") as temp:
        path = Path(temp) / "capsule.json"
        path.write_bytes(canonical(value))
        command = [sys.executable, str(CHECKER), str(ROOT), "--capsule", str(path), "--openssl", "openssl", "--json"]
        if expected:
            command.extend(["--expected", str(EXPECTED)])
        return subprocess.run(command, text=True, capture_output=True)


def mutate_b64(carrier: dict[str, object]) -> None:
    raw = bytearray(base64.b64decode(str(carrier["data"]), validate=True))
    raw[-1] ^= 1
    carrier["data"] = base64.b64encode(raw).decode()


class P1A12TransparencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.capsule = json.loads(CAPSULE.read_text())

    def test_positive(self) -> None:
        result = run_capsule(self.capsule, expected=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_time_identity_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        value["sourceTime"]["timeReport"]["identity"]["digest"] = "00" * 32
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_registration_signature_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        mutate_b64(value["registration"]["envelope"])
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_service_identity_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        value["services"][0]["id"] = "other-log"
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_witness_threshold_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        payload = base64.b64decode(value["registration"]["payload"]["data"])
        decoded = json.loads(payload)
        decoded["witnessSet"]["threshold"] = 1
        value["registration"]["payload"]["data"] = base64.b64encode(canonical(decoded)).decode()
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_witness_signature_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        mutate_b64(value["checkpoints"][1]["witnessStatements"][0]["envelope"])
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_consistency_proof_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        payload = json.loads(base64.b64decode(value["checkpoints"][1]["payload"]["data"]))
        payload["consistencyProof"][0] = "00" * 32
        value["checkpoints"][1]["payload"]["data"] = base64.b64encode(canonical(payload)).decode()
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_equivocation_decision_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        value["checkpoints"][2]["expectedDecision"] = "conformant"
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_succession_signature_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        mutate_b64(value["succession"]["envelope"])
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_quarantined_witness_reuse(self) -> None:
        value = copy.deepcopy(self.capsule)
        value["checkpoints"][3]["witnessStatements"][1] = copy.deepcopy(value["checkpoints"][1]["witnessStatements"][1])
        self.assertNotEqual(run_capsule(value).returncode, 0)

    def test_claim_boundary_mutation(self) -> None:
        value = copy.deepcopy(self.capsule)
        value["claimBoundary"]["doesNotImply"].pop()
        self.assertNotEqual(run_capsule(value).returncode, 0)


if __name__ == "__main__":
    unittest.main()
