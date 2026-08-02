from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from eigiib_p1_a20_core import FIXTURE, load_bundle, load_json
from eigiib_p1_a20_mutations import mutation_cases
from eigiib_p1_a20_report import report
from eigiib_p1_a20_replay import validate_bundle

try:
    from jsonschema.exceptions import ValidationError
    from eigiib_p1_a20_schema import DRAFT_2020_12, validate_draft202012_instance
except ModuleNotFoundError:
    JSONSCHEMA_AVAILABLE = False
    DRAFT_2020_12 = None
    ValidationError = Exception
    validate_draft202012_instance = None
else:
    JSONSCHEMA_AVAILABLE = True

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas/eigiib-p1-a20-bundle.schema.json"


class P1A20ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_bundle()
        cls.expected_report = load_json(FIXTURE / "expected-report.json")

    def test_001_exact_report(self) -> None:
        self.assertEqual(report(copy.deepcopy(self.bundle)), self.expected_report)

    def test_002_signed_registries_authorization_and_routes(self) -> None:
        decisions = validate_bundle(copy.deepcopy(self.bundle))
        self.assertEqual(len(decisions), 13)
        self.assertEqual(sum(item["decision"] == "accepted" for item in decisions), 6)
        self.assertEqual(sum(item["decision"] == "rejected" for item in decisions), 7)

    def test_003_registry_inventory(self) -> None:
        runners = self.bundle["signedRunnerRegistry"]["payload"]["runners"]
        versions = self.bundle["signedToolchainRegistry"]["payload"]["versions"]
        self.assertEqual(len(runners), 6)
        self.assertEqual(sum(item["status"] == "active" for item in runners), 4)
        self.assertEqual([item["version"] for item in versions], ["1.8.0", "1.9.0", "2.0.0-rc1"])


def _make_route_test(index: int, route_id: str):
    def test(self: P1A20ReplayTests) -> None:
        decisions = validate_bundle(copy.deepcopy(self.bundle))
        self.assertEqual(decisions[index]["routeId"], route_id)
        self.assertEqual(decisions[index], self.bundle["routes"][index]["expectedDecision"])

    return test


for _index, _route in enumerate(load_bundle()["routes"]):
    setattr(P1A20ReplayTests, f"test_{_index + 4:03d}_{_route['routeId'].replace('-', '_')}", _make_route_test(_index, _route["routeId"]))


def _make_mutation_test(index: int, name: str):
    def test(self: P1A20ReplayTests) -> None:
        mutated = mutation_cases(self.bundle)[index][1]
        with self.assertRaises((ValueError, KeyError, TypeError), msg=name):
            validate_bundle(mutated)

    return test


for _index, (_name, _) in enumerate(mutation_cases(load_bundle())):
    setattr(P1A20ReplayTests, f"test_{_index + 17:03d}_reject_{_name.replace('-', '_')}", _make_mutation_test(_index, _name))


def _schema_mutations(bundle: dict) -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []

    mutated = copy.deepcopy(bundle)
    mutated["unexpected"] = True
    cases.append(("bundle-extra-property", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRunnerRegistry"]["unexpected"] = True
    cases.append(("runner-envelope-extra-property", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRunnerRegistry"]["payload"]["unexpected"] = True
    cases.append(("runner-registry-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRunnerRegistry"]["payload"]["runners"][0]["unexpected"] = True
    cases.append(("runner-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedToolchainRegistry"]["payload"]["versions"][0]["unexpected"] = True
    cases.append(("toolchain-version-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRollbackAuthorizations"][0]["payload"]["unexpected"] = True
    cases.append(("rollback-authorization-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["unexpected"] = True
    cases.append(("route-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["expectedDecision"]["unexpected"] = True
    cases.append(("decision-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedToolchainRegistry"]["payload"]["versions"][0]["compatibleRunnerGenerations"]["linux"].append("2")
    cases.append(("compatibility-generation-type-through-ref", mutated))

    return cases


@unittest.skipUnless(JSONSCHEMA_AVAILABLE, "P1-A20 locked jsonschema environment is not installed")
class P1A20SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_json(SCHEMA)
        cls.bundle = load_bundle()

    def test_047_committed_schema_and_bundle_validate(self) -> None:
        validate_draft202012_instance(self.schema, self.bundle)

    def test_048_schema_selects_exact_draft(self) -> None:
        self.assertEqual(self.schema["$schema"], DRAFT_2020_12)


def _make_schema_test(index: int, name: str):
    def test(self: P1A20SchemaTests) -> None:
        mutated = _schema_mutations(self.bundle)[index][1]
        with self.assertRaises(ValidationError, msg=name):
            validate_draft202012_instance(self.schema, mutated)

    return test


for _index, (_name, _) in enumerate(_schema_mutations(load_bundle())):
    setattr(P1A20SchemaTests, f"test_{_index + 49:03d}_reject_{_name.replace('-', '_')}", _make_schema_test(_index, _name))


if __name__ == "__main__":
    unittest.main()
