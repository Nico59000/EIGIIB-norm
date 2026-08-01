from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ADAPTER = load(
    "eigiib_p1_a7_structural_adapter_test",
    ROOT / "tools/eigiib_p1_a7_structural_adapter.py",
)
REPLAY = load(
    "eigiib_structural_route_replay_test",
    ROOT / "tools/eigiib_structural_route_replay.py",
)
GENERATOR = load(
    "eigiib_negative_vector_generator_test_a73",
    ROOT / "tools/eigiib_negative_vector_generator.py",
)


class StructuralAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.seed = (ROOT / "tests/fixtures/p1-a7/source/a7.3-seed.json").read_bytes()
        cls.manifest = GENERATOR.strict_json_loads(
            (ROOT / "tests/fixtures/p1-a7/a7.3-structural-corpus.json").read_bytes(),
            "TEST",
        )

    def generated(self, vector_id: str) -> bytes:
        vector = next(row for row in self.manifest["vectors"] if row["id"] == vector_id)
        raw = self.seed
        for mutation in vector["mutations"]:
            raw = GENERATOR.apply_mutation(raw, mutation)
        return raw

    def test_positive_seed_is_accepted(self) -> None:
        result = ADAPTER.evaluate(self.seed, "positive")
        self.assertTrue(result.accepted)
        self.assertIsNone(result.error_class)
        self.assertEqual(result.boundary, "projection")

    def test_identity_length_precedes_digest(self) -> None:
        document = GENERATOR.strict_json_loads(self.seed, "TEST")
        document["payload"]["identity"]["bytes"] = 5
        document["payload"]["identity"]["digest"] = "0" * 64
        result = ADAPTER.evaluate(GENERATOR.canonical_json(document), "multi-identity")
        self.assertEqual(result.error_class, "identity.length-mismatch")
        self.assertEqual(result.boundary, "identity.length")

    def test_digest_mismatch_is_classified(self) -> None:
        result = ADAPTER.evaluate(
            self.generated("a7-identity-digest-mismatch"),
            "a7-identity-digest-mismatch",
        )
        self.assertEqual(result.error_class, "identity.digest-mismatch")

    def test_projection_missing_field_is_classified(self) -> None:
        result = ADAPTER.evaluate(
            self.generated("a7-projection-missing-field"),
            "a7-projection-missing-field",
        )
        self.assertEqual(result.error_class, "projection.invalid")

    def test_multi_defect_uses_declared_first_boundary(self) -> None:
        result = ADAPTER.evaluate(
            self.generated("a7-multi-base64-path-identity-projection"),
            "a7-multi-base64-path-identity-projection",
        )
        self.assertEqual(result.error_class, "encoding.noncanonical-base64")
        self.assertEqual(result.boundary, "base64")

    def test_manifest_generation_is_exact(self) -> None:
        positive, vectors = REPLAY.load_structural_corpus(ROOT, GENERATOR)
        self.assertEqual(positive, self.seed)
        self.assertEqual(len(vectors), 9)
        self.assertEqual(
            [row["id"] for row in vectors if len(row["precedence"]) > 1],
            ["a7-multi-base64-path-identity-projection"],
        )

    def test_replay_matches_canonical_report(self) -> None:
        expected = ROOT / "tests/fixtures/p1-a7/expected-a7.3-structural-replay.json"
        result = REPLAY.check_repository(ROOT, "go", expected)
        self.assertEqual(result["overall_result"], "conformant")
        self.assertEqual(result["observation_count"], 30)
        self.assertEqual(result["multi_defect_precedence_result"], "conformant")


if __name__ == "__main__":
    unittest.main()
