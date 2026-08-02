from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools/eigiib_m0_a6_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_m0_a6_check", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


class M0A6Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source_root = Path(__file__).resolve().parents[1]
        for relative in CHECK.REQUIRED_FILES:
            source = source_root / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())

        self.profile = """standard = "EIGIIB-1.0"
extensions = ["E14-1.0"]
revision = "EIGIIB-E14-1.0"
required_authorities = []

[authorities]
"""
        (self.root / "EIGIIB.toml").write_text(self.profile, encoding="utf-8")
        workflow = self.root / ".github/workflows/eigiib.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text("name: frozen\n", encoding="utf-8")
        graph = self.root / "conformance/extension-graph.json"
        graph.parent.mkdir(parents=True, exist_ok=True)
        graph.write_text("{}\n", encoding="utf-8")

        authorities = []
        for relative in ("EIGIIB.toml", ".github/workflows/eigiib.yml", "conformance/extension-graph.json"):
            data = (self.root / relative).read_bytes()
            authorities.append({
                "path": relative,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        freeze = {
            "standard": "EIGIIB-E14-A5-1.0",
            "status": "frozen",
            "source_head": "31e85dbd109ecbe8c27564cd3411f11358e87acb",
            "profile_revision": "EIGIIB-E14-1.0",
            "authorities": authorities,
        }
        (self.root / "conformance/e14-a5-authority-freeze.json").write_text(
            json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_conformant_entry_contract(self) -> None:
        report = CHECK.validate(self.root)
        expected = json.loads(
            (Path(__file__).resolve().parent / "fixtures/m0-a6/expected-report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report, expected)

    def test_source_head_substitution_is_rejected(self) -> None:
        path = self.root / "conformance/m0-a6-e15-entry.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["source_lineage"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data), encoding="utf-8")
        report = CHECK.validate(self.root)
        self.assertEqual(report["overall_result"], "non-conformant")
        self.assertTrue(any(item["code"] == "M0A6.HANDOFF.SOURCE" for item in report["findings"]))

    def test_missing_required_input_is_rejected(self) -> None:
        path = self.root / "conformance/m0-a6-e15-entry.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["required_inputs"].pop()
        path.write_text(json.dumps(data), encoding="utf-8")
        report = CHECK.validate(self.root)
        self.assertTrue(any(item["code"] == "M0A6.HANDOFF.INPUTS" for item in report["findings"]))

    def test_premature_e15_adoption_is_rejected(self) -> None:
        (self.root / "EIGIIB.toml").write_text(
            self.profile.replace('["E14-1.0"]', '["E14-1.0", "E15-1.0"]'), encoding="utf-8"
        )
        report = CHECK.validate(self.root)
        self.assertTrue(any(item["code"] == "M0A6.PROFILE.E15" for item in report["findings"]))

    def test_central_m0_a6_registration_is_rejected(self) -> None:
        (self.root / "EIGIIB.toml").write_text(
            self.profile + '\nm0_a6_entry = "conformance/m0-a6-e15-entry.json"\n', encoding="utf-8"
        )
        report = CHECK.validate(self.root)
        self.assertTrue(any(item["code"] == "M0A6.PROFILE.CENTRAL_MUTATION" for item in report["findings"]))

    def test_frozen_path_mutation_is_rejected(self) -> None:
        (self.root / ".github/workflows/eigiib.yml").write_text("name: changed\n", encoding="utf-8")
        report = CHECK.validate(self.root)
        self.assertEqual(report["e14_frozen_path_result"], "non-conformant")
        self.assertTrue(any(item["code"] == "M0A6.FREEZE.DIGEST" for item in report["findings"]))

    def test_direct_methodology_republication_is_rejected(self) -> None:
        path = self.root / "conformance/m0-a6-e15-entry.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["methodology_translation"]["direct_source_republication"] = True
        path.write_text(json.dumps(data), encoding="utf-8")
        report = CHECK.validate(self.root)
        self.assertTrue(any(item["code"] == "M0A6.HANDOFF.METHOD" for item in report["findings"]))

    def test_slice_dependency_mutation_is_rejected(self) -> None:
        path = self.root / "conformance/m0-a6-e15-entry.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["planned_slices"][3]["depends_on"] = ["E15-A1"]
        path.write_text(json.dumps(data), encoding="utf-8")
        report = CHECK.validate(self.root)
        self.assertTrue(any(item["code"] == "M0A6.HANDOFF.SLICE" for item in report["findings"]))


if __name__ == "__main__":
    unittest.main()
