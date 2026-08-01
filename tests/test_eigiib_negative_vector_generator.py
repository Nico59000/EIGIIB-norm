from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "eigiib_negative_vector_generator",
    ROOT / "tools/eigiib_negative_vector_generator.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class NegativeVectorGeneratorTests(unittest.TestCase):
    def test_repository_contract_is_deterministic(self) -> None:
        first = MODULE.check_repository(ROOT)
        second = MODULE.check_repository(ROOT)
        self.assertEqual(first, second)
        self.assertEqual(first["structural_result"], "conformant")
        self.assertEqual(first["manifest_result"], "valid")
        self.assertEqual(first["taxonomy_result"], "valid")
        self.assertEqual(first["generator_result"], "deterministic")
        self.assertEqual(first["vector_count"], 8)
        self.assertEqual(first["route_replay_result"], "not-evaluated-by-p1-a7.1")

    def test_generated_bytes_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = MODULE.check_repository(ROOT, Path(first_dir))
            second = MODULE.check_repository(ROOT, Path(second_dir))
            self.assertEqual(first["structural_result"], "conformant")
            self.assertEqual(second["structural_result"], "conformant")
            first_files = {
                path.name: path.read_bytes()
                for path in Path(first_dir).iterdir()
            }
            second_files = {
                path.name: path.read_bytes()
                for path in Path(second_dir).iterdir()
            }
            self.assertEqual(first_files, second_files)

    def test_strict_json_rejects_duplicate_member(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
            MODULE.strict_json_loads(b'{"a":1,"a":2}', "TEST")

    def test_invalid_utf8_mutation_is_binary_exact(self) -> None:
        source = b'{"a":1}\n'
        generated = MODULE.apply_mutation(
            source,
            {"operator": "raw.insert-hex", "offset": 0, "hex": "ff"},
        )
        self.assertEqual(generated, bytes([255]) + source)

    def test_pointer_mutations_use_rfc6901_escapes(self) -> None:
        source = MODULE.canonical_json({"a/b": {"~key": "x"}})
        generated = MODULE.apply_mutation(
            source,
            {
                "operator": "json.append-string",
                "pointer": "/a~1b/~0key",
                "suffix": "y",
            },
        )
        self.assertEqual(
            MODULE.strict_json_loads(generated, "TEST"),
            {"a/b": {"~key": "xy"}},
        )

    def test_generated_identity_mismatch_is_rejected(self) -> None:
        manifest_path = ROOT / "tests/fixtures/p1-a7/corpus.json"
        manifest = MODULE.strict_json_loads(manifest_path.read_bytes(), "TEST")
        mutated = copy.deepcopy(manifest)
        mutated["vectors"][0]["generatedIdentity"]["digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "generated identity mismatch"):
            MODULE.validate_manifest(ROOT, mutated)

    def test_taxonomy_precedence_is_contiguous(self) -> None:
        taxonomy_path = ROOT / "tests/fixtures/p1-a7/error-taxonomy.json"
        taxonomy = MODULE.strict_json_loads(taxonomy_path.read_bytes(), "TEST")
        ranks = MODULE.validate_taxonomy(taxonomy)
        self.assertEqual(sorted(ranks.values()), list(range(1, len(ranks) + 1)))

    def test_multi_defect_precedence_must_follow_taxonomy(self) -> None:
        manifest_path = ROOT / "tests/fixtures/p1-a7/corpus.json"
        manifest = MODULE.strict_json_loads(manifest_path.read_bytes(), "TEST")
        mutated = copy.deepcopy(manifest)
        mutated["vectors"][0]["expect"]["precedence"] = [
            "identity.digest-mismatch",
            "syntax.invalid-json",
        ]
        with self.assertRaisesRegex(ValueError, "precedence order differs"):
            MODULE.validate_manifest(ROOT, mutated)


if __name__ == "__main__":
    unittest.main()
