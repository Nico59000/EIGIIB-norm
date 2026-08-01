from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import eigiib_p1_a7_cose_adapter as adapter
from eigiib_cose_replay_corpus import validate_corpus


class P1A75CoseAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.seed, cls.key, _, cls.rows, _ = validate_corpus(
            ROOT,
            ROOT / "tests/fixtures/p1-a7/a7.5-cose-corpus.json",
            adapter,
            "openssl",
        )

    def test_positive_signed_statement(self) -> None:
        result = adapter.evaluate(
            self.seed,
            self.key,
            "a7-positive-p1-a3-signed-statement",
            "openssl",
        )
        self.assertTrue(result.accepted)
        self.assertIsNone(result.error_class)
        self.assertEqual(result.boundary, "cose-signature")

    def test_all_negative_vectors(self) -> None:
        self.assertEqual(len(self.rows), 9)
        for row in self.rows:
            with self.subTest(vector=row["id"]):
                result = adapter.evaluate(
                    row["bytes"],
                    self.key,
                    row["id"],
                    "openssl",
                )
                self.assertFalse(result.accepted)
                self.assertEqual(result.error_class, row["expected_class"])
                self.assertEqual(result.boundary, row["expected_boundary"])

    def test_mutation_generation_is_deterministic(self) -> None:
        first = [(row["id"], adapter.identity(row["bytes"])) for row in self.rows]
        _, _, _, second_rows, _ = validate_corpus(
            ROOT,
            ROOT / "tests/fixtures/p1-a7/a7.5-cose-corpus.json",
            adapter,
            "openssl",
        )
        second = [(row["id"], adapter.identity(row["bytes"])) for row in second_rows]
        self.assertEqual(first, second)

    def test_multi_defect_precedence(self) -> None:
        row = next(
            item
            for item in self.rows
            if item["id"] == "a7-multi-cbor-order-and-unknown-critical"
        )
        self.assertEqual(
            row["precedence"],
            ["cbor.nondeterministic", "cose.unsupported-header"],
        )
        result = adapter.evaluate(row["bytes"], self.key, row["id"], "openssl")
        self.assertEqual(result.error_class, "cbor.nondeterministic")
        self.assertEqual(result.boundary, "cbor-protected-header")

    def test_source_identity_is_exact(self) -> None:
        self.assertEqual(
            adapter.identity(self.seed),
            {
                "algorithm": "sha256",
                "bytes": 396,
                "digest": "27c960d31e9afbf454c8bb6dbdd396309b3dec629f58d8f5c87553864e579d81",
            },
        )
        _, der = adapter.parse_public_key_pem(self.key)
        self.assertEqual(
            adapter.identity(der),
            {
                "algorithm": "sha256",
                "bytes": 44,
                "digest": "66ce2b50279d0f955a2e73434560439e4e47bfa6d6f365f8a83493510e97f447",
            },
        )


if __name__ == "__main__":
    unittest.main()
