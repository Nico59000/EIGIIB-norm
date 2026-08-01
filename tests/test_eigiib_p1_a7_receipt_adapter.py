from __future__ import annotations
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from eigiib_receipt_replay_common import load_adapter
from eigiib_receipt_replay_corpus import apply_mutations, validate_corpus

class ReceiptAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = load_adapter(ROOT)
        cls.seed, cls.rows, _ = validate_corpus(
            ROOT,
            ROOT / "tests/fixtures/p1-a7/a7.6-receipt-corpus.json",
            cls.adapter,
            "openssl",
        )

    def test_positive_receipt(self) -> None:
        result = self.adapter.evaluate(self.seed, "positive", "openssl")
        self.assertTrue(result.accepted)
        self.assertIsNone(result.error_class)
        self.assertEqual(result.boundary, "receipt-root")

    def test_all_negative_vectors(self) -> None:
        self.assertEqual(len(self.rows), 10)
        for row in self.rows:
            with self.subTest(vector=row["id"]):
                result = self.adapter.evaluate(row["bytes"], row["id"], "openssl")
                self.assertFalse(result.accepted)
                self.assertEqual(result.error_class, row["expected_class"])
                self.assertEqual(result.boundary, row["expected_boundary"])

    def test_generation_is_deterministic(self) -> None:
        import json
        corpus = json.loads((ROOT / "tests/fixtures/p1-a7/a7.6-receipt-corpus.json").read_text())
        for vector in corpus["vectors"]:
            first = apply_mutations(self.adapter, self.seed, vector["mutations"])
            second = apply_mutations(self.adapter, self.seed, vector["mutations"])
            self.assertEqual(first, second)

    def test_multi_defect_precedence(self) -> None:
        row = next(item for item in self.rows if item["id"] == "a7-multi-receipt-wrong-tag-and-root")
        self.assertEqual(row["precedence"], ["cose.invalid-structure", "receipt.invalid-proof"])
        result = self.adapter.evaluate(row["bytes"], row["id"], "openssl")
        self.assertEqual((result.error_class, result.boundary), ("cose.invalid-structure", "receipt-cose-structure"))

if __name__ == "__main__":
    unittest.main()
