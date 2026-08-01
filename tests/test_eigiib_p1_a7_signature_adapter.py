from __future__ import annotations

import base64
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "eigiib_p1_a7_signature_adapter",
    ROOT / "tools/eigiib_p1_a7_signature_adapter.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class SignatureAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.temp = Path(cls.temporary.name)
        cls.private_key = cls.temp / "private.pem"
        cls.public_key = cls.temp / "public.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.private_key)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                "openssl", "pkey", "-in", str(cls.private_key),
                "-pubout", "-out", str(cls.public_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        cls.payload = b'{"hello":"world"}'
        cls.pae = MODULE.pae(MODULE.PAYLOAD_TYPE, cls.payload)
        message = cls.temp / "message.bin"
        signature = cls.temp / "signature.bin"
        message.write_bytes(cls.pae)
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-inkey", str(cls.private_key),
                "-rawin", "-in", str(message), "-out", str(signature),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        cls.signature = signature.read_bytes()
        cls.public_pem = cls.public_key.read_text(encoding="utf-8")
        _, cls.der = MODULE.parse_public_key_pem(cls.public_pem)
        keyid = "p1-a2-ed25519-spki-sha256:" + MODULE.identity(cls.der)["digest"]
        cls.carrier = {
            "standard": MODULE.CARRIER_STANDARD,
            "profile": MODULE.PROFILE,
            "manifest": {
                "members": [
                    {"name": "payload", "identity": MODULE.identity(cls.payload)},
                    {"name": "signature", "identity": MODULE.identity(cls.signature)},
                    {"name": "public-key-spki", "identity": MODULE.identity(cls.der)},
                ]
            },
            "dsseEnvelope": {
                "payload": MODULE.canonical_b64(cls.payload),
                "payloadType": MODULE.PAYLOAD_TYPE,
                "signatures": [
                    {"keyid": keyid, "sig": MODULE.canonical_b64(cls.signature)}
                ],
            },
            "publicKeyPem": cls.public_pem,
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def evaluate(self, carrier: dict, vector_id: str = "test"):
        return MODULE.evaluate(MODULE.canonical_json(carrier), vector_id)

    def test_positive_carrier(self) -> None:
        result = self.evaluate(copy.deepcopy(self.carrier), "positive")
        self.assertTrue(result.accepted)
        self.assertIsNone(result.error_class)
        self.assertEqual(result.boundary, "signature")

    def test_manifest_order_precedes_signature_failure(self) -> None:
        carrier = copy.deepcopy(self.carrier)
        members = carrier["manifest"]["members"]
        members[0], members[1] = members[1], members[0]
        signature = bytearray(self.signature)
        signature[0] ^= 1
        carrier["dsseEnvelope"]["signatures"][0]["sig"] = MODULE.canonical_b64(bytes(signature))
        members[1]["identity"] = MODULE.identity(bytes(signature))
        result = self.evaluate(carrier, "multi")
        self.assertFalse(result.accepted)
        self.assertEqual(result.error_class, "manifest.invalid")
        self.assertEqual(result.boundary, "manifest")

    def test_wrong_payload_type_is_malformed(self) -> None:
        carrier = copy.deepcopy(self.carrier)
        carrier["dsseEnvelope"]["payloadType"] = "application/octet-stream"
        result = self.evaluate(carrier)
        self.assertEqual(result.error_class, "signature.malformed")
        self.assertEqual(result.boundary, "dsse")

    def test_payload_byte_change_is_invalid_signature(self) -> None:
        carrier = copy.deepcopy(self.carrier)
        payload = self.payload + b" "
        carrier["dsseEnvelope"]["payload"] = MODULE.canonical_b64(payload)
        carrier["manifest"]["members"][0]["identity"] = MODULE.identity(payload)
        result = self.evaluate(carrier)
        self.assertEqual(result.error_class, "signature.invalid")
        self.assertEqual(result.boundary, "signature")

    def test_truncated_signature_is_malformed(self) -> None:
        carrier = copy.deepcopy(self.carrier)
        signature = self.signature[:-1]
        carrier["dsseEnvelope"]["signatures"][0]["sig"] = MODULE.canonical_b64(signature)
        carrier["manifest"]["members"][1]["identity"] = MODULE.identity(signature)
        result = self.evaluate(carrier)
        self.assertEqual(result.error_class, "signature.malformed")
        self.assertEqual(result.boundary, "signature-carrier")

    def test_bitflip_is_invalid_signature(self) -> None:
        carrier = copy.deepcopy(self.carrier)
        signature = bytearray(self.signature)
        signature[0] ^= 1
        carrier["dsseEnvelope"]["signatures"][0]["sig"] = MODULE.canonical_b64(bytes(signature))
        carrier["manifest"]["members"][1]["identity"] = MODULE.identity(bytes(signature))
        result = self.evaluate(carrier)
        self.assertEqual(result.error_class, "signature.invalid")
        self.assertEqual(result.boundary, "signature")

    def test_keyid_mismatch_is_malformed(self) -> None:
        carrier = copy.deepcopy(self.carrier)
        carrier["dsseEnvelope"]["signatures"][0]["keyid"] = (
            "p1-a2-ed25519-spki-sha256:" + "f" * 64
        )
        result = self.evaluate(carrier)
        self.assertEqual(result.error_class, "signature.malformed")
        self.assertEqual(result.boundary, "signature-carrier")

    def test_manifest_digest_mismatch_is_rejected(self) -> None:
        carrier = copy.deepcopy(self.carrier)
        carrier["manifest"]["members"][0]["identity"]["digest"] = "0" * 64
        result = self.evaluate(carrier)
        self.assertEqual(result.error_class, "manifest.invalid")
        self.assertEqual(result.boundary, "manifest")


if __name__ == "__main__":
    unittest.main()
