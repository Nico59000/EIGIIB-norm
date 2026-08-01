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
    "eigiib_p1_a7_reference_adapter_test",
    ROOT / "tools/eigiib_p1_a7_reference_adapter.py",
)
GENERATOR = load(
    "eigiib_negative_vector_generator_test_a72",
    ROOT / "tools/eigiib_negative_vector_generator.py",
)


class ReferenceAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = GENERATOR.strict_json_loads(
            (ROOT / "tests/fixtures/p1-a7/corpus.json").read_bytes(),
            "TEST",
        )
        _, generated = GENERATOR.validate_manifest(ROOT, manifest)
        cls.generated = {row["id"]: row["bytes"] for row in generated}
        cls.expected = {
            vector["id"]: vector["expect"]["errorClass"]
            for vector in manifest["vectors"]
        }

    def test_positive_seed_is_accepted(self) -> None:
        raw = (
            ROOT / "tests/fixtures/p1-a7/source/generator-seed.json"
        ).read_bytes()
        result = ADAPTER.evaluate(raw, "a7-positive-seed")
        self.assertTrue(result.accepted)
        self.assertIsNone(result.error_class)
        self.assertEqual(result.boundary, "path")

    def test_first_route_bound_slice_maps_to_portable_classes(self) -> None:
        vector_ids = [
            "a7-json-duplicate-standard",
            "a7-json-trailing-data",
            "a7-utf8-invalid-prefix",
            "a7-base64-extra-padding",
            "a7-path-parent-traversal",
        ]
        for vector_id in vector_ids:
            with self.subTest(vector_id=vector_id):
                result = ADAPTER.evaluate(self.generated[vector_id], vector_id)
                self.assertFalse(result.accepted)
                self.assertEqual(result.error_class, self.expected[vector_id])


if __name__ == "__main__":
    unittest.main()
