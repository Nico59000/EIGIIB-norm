from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from eigiib_p1_a19_common import FIXTURE, load_json, mutation_cases, negotiate, report, validate_bundle, validate_registry


class P1A19InteroperabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_json(FIXTURE / "interoperability-bundle.json")
        cls.expected = load_json(FIXTURE / "expected-report.json")

    def test_001_exact_report(self) -> None:
        self.assertEqual(report(copy.deepcopy(self.bundle)), self.expected)

    def test_002_registry_signature_and_semantics(self) -> None:
        transcripts = validate_bundle(copy.deepcopy(self.bundle))
        self.assertEqual(len(transcripts), 6)

    def test_003_registry_has_six_active_profiles_and_two_deprecated_versions(self) -> None:
        registry = self.bundle["signedRegistry"]["payload"]
        validate_registry(registry)
        self.assertEqual(len(registry["activeVersions"]), 6)
        self.assertEqual(sum(p["status"] == "deprecated" for p in registry["profiles"]), 2)


def _make_route_test(index: int):
    def test(self: P1A19InteroperabilityTests) -> None:
        route = copy.deepcopy(self.bundle["routes"][index])
        actual = negotiate(self.bundle["signedRegistry"]["payload"], route)
        self.assertEqual(actual, route["expectedTranscript"])
        self.assertEqual(actual["decision"], "accepted")
        self.assertEqual(actual["selectedCapabilities"], sorted(actual["selectedCapabilities"]))
    return test


for i in range(6):
    setattr(P1A19InteroperabilityTests, f"test_{i + 4:03d}_positive_route_{i + 1:02d}", _make_route_test(i))


def _make_mutation_test(index: int, name: str):
    def test(self: P1A19InteroperabilityTests) -> None:
        mutated = mutation_cases(copy.deepcopy(self.bundle))[index][1]
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError), msg=name):
            validate_bundle(mutated)
    return test


for i, (name, _) in enumerate(mutation_cases(load_json(FIXTURE / "interoperability-bundle.json"))):
    setattr(P1A19InteroperabilityTests, f"test_{i + 10:03d}_reject_{name.replace('-', '_')}", _make_mutation_test(i, name))


if __name__ == "__main__":
    unittest.main()
