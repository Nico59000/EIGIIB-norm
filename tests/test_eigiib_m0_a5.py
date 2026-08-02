from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools/eigiib_m0_a5_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_m0_a5_check", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class M0A5Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source_root = Path(__file__).resolve().parents[1]
        for relative in (
            "conformance/m0-a5-p1-lineage.json",
            "conformance/m0-a5-e14-handoff.json",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((source_root / relative).read_text(encoding="utf-8"), encoding="utf-8")

        lineage = json.loads((self.root / "conformance/m0-a5-p1-lineage.json").read_text(encoding="utf-8"))
        paths: set[str] = set()
        for entry in lineage["slices"]:
            paths.update((entry["document"], entry["state"], entry["manual_review"]))
        for stage in lineage["embedded_staged_closures"]["P1-A7"]:
            paths.update((stage["document"], stage["manual_review"]))
        paths.update(
            (
                "docs/M0-A5-HUMAN-MASTERY-GUIDE.md",
                "conformance/M0-A5-MANUAL-REVIEW.md",
            )
        )
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture\n", encoding="utf-8")

        self.profile = """standard = "EIGIIB-1.0"
extensions = ["E13-1.0"]
required_authorities = ["m0_a5_p1_lineage", "m0_a5_e14_handoff", "m0_a5_human_mastery"]

[authorities]
m0_a5_p1_lineage = "conformance/m0-a5-p1-lineage.json"
m0_a5_e14_handoff = "conformance/m0-a5-e14-handoff.json"
m0_a5_human_mastery = "docs/M0-A5-HUMAN-MASTERY-GUIDE.md"

[[manual_gates]]
id = "m0-a5-lineage-e14-handoff-review"
status = "complete"
authority = "m0_a5_p1_lineage"
attestation = "conformance/M0-A5-MANUAL-REVIEW.md"
"""
        (self.root / "EIGIIB.toml").write_text(self.profile, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_conformant_registry_and_handoff(self) -> None:
        report = CHECK.validate(self.root)
        expected = json.loads(
            (Path(__file__).resolve().parent / "fixtures/m0-a5/expected-report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report, expected)

    def test_canonical_head_substitution_is_rejected(self) -> None:
        path = self.root / "conformance/m0-a5-p1-lineage.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["canonical"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(CHECK.ValidationError, "canonical head mismatch"):
            CHECK.validate(self.root)

    def test_missing_required_e14_input_is_rejected(self) -> None:
        path = self.root / "conformance/m0-a5-e14-handoff.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["required_inputs"].remove("revocation_state")
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(CHECK.ValidationError, "E14 input set"):
            CHECK.validate(self.root)

    def test_premature_e14_adoption_is_rejected(self) -> None:
        (self.root / "EIGIIB.toml").write_text(self.profile.replace('["E13-1.0"]', '["E13-1.0", "E14-1.0"]'), encoding="utf-8")
        with self.assertRaisesRegex(CHECK.ValidationError, "prematurely adopted"):
            CHECK.validate(self.root)


if __name__ == "__main__":
    unittest.main()
