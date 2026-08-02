from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from eigiib_p1_a19_common import FIXTURE, load_json, validate_bundle

try:
    from jsonschema.exceptions import ValidationError
    from eigiib_p1_a19_schema import DRAFT_2020_12, validate_draft202012_instance
except ModuleNotFoundError:
    JSONSCHEMA_AVAILABLE = False
    DRAFT_2020_12 = None
    ValidationError = Exception
    validate_draft202012_instance = None
else:
    JSONSCHEMA_AVAILABLE = True

SCHEMA = FIXTURE.parent.parent.parent / "schemas/eigiib-p1-a19-bundle.schema.json"


@unittest.skipUnless(JSONSCHEMA_AVAILABLE, "P1-A19-F2 locked jsonschema environment is not installed")
class P1A19F2SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_json(SCHEMA)
        cls.bundle = load_json(FIXTURE / "interoperability-bundle.json")

    def test_001_committed_schema_and_bundle_validate(self) -> None:
        validate_draft202012_instance(self.schema, self.bundle)
        self.assertEqual(len(validate_bundle(copy.deepcopy(self.bundle))), 6)

    def test_002_schema_selects_exact_draft(self) -> None:
        self.assertEqual(self.schema["$schema"], DRAFT_2020_12)

    def test_003_wrong_draft_is_rejected(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["$schema"] = "https://json-schema.org/draft/2019-09/schema"
        with self.assertRaises(ValueError):
            validate_draft202012_instance(schema, self.bundle)


def _schema_mutations(bundle: dict) -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []

    mutated = copy.deepcopy(bundle)
    mutated["unexpected"] = True
    cases.append(("bundle-extra-property", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRegistry"]["unexpected"] = True
    cases.append(("signed-registry-extra-property", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRegistry"]["payload"]["unexpected"] = True
    cases.append(("registry-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRegistry"]["payload"]["profiles"][0]["unexpected"] = True
    cases.append(("profile-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["unexpected"] = True
    cases.append(("route-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["expectedTranscript"]["unexpected"] = True
    cases.append(("transcript-extra-property-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["routes"][0]["sourceClaims"].append(7)
    cases.append(("canonical-set-item-type-through-ref", mutated))

    mutated = copy.deepcopy(bundle)
    mutated["signedRegistry"]["payload"]["profiles"][0]["requiredCapabilities"].append("")
    cases.append(("canonical-set-min-length-through-ref", mutated))

    return cases


def _make_schema_rejection_test(index: int, name: str):
    def test(self: P1A19F2SchemaTests) -> None:
        mutated = _schema_mutations(self.bundle)[index][1]
        with self.assertRaises(ValidationError, msg=name):
            validate_draft202012_instance(self.schema, mutated)

    return test


for i, (name, _) in enumerate(_schema_mutations(load_json(FIXTURE / "interoperability-bundle.json"))):
    setattr(P1A19F2SchemaTests, f"test_{i + 4:03d}_reject_{name.replace('-', '_')}", _make_schema_rejection_test(i, name))


if __name__ == "__main__":
    unittest.main()
