from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest


REPO = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO / "tools/eigiib_m0_a7_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_m0_a7_check", CHECKER_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

M0A7_FILES = [
    "conformance/M0-A7-MANUAL-REVIEW.md",
    "conformance/m0-a7-e16-entry.json",
    "docs/M0-A7-E16-NORMATIVE-ENTRY-NORMALIZATION-AND-E15-AUTHORITY-CONTINUITY.md",
    "docs/M0-A7-HUMAN-MASTERY-GUIDE.md",
    "schemas/eigiib-m0-a7-e16-entry.schema.json",
    "tests/fixtures/m0-a7/expected-report.json",
    "tools/eigiib_m0_a7_check.py",
]


def copy_file(source_root: Path, target_root: Path, relative: str) -> None:
    source = source_root / relative
    target = target_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def make_workspace() -> tempfile.TemporaryDirectory[str]:
    temp = tempfile.TemporaryDirectory()
    target = Path(temp.name)
    freeze = json.loads((REPO / "conformance/e15-a5-authority-freeze.json").read_text(encoding="utf-8"))
    copy_file(REPO, target, "conformance/e15-a5-authority-freeze.json")
    for entry in freeze["authorities"]:
        copy_file(REPO, target, entry["path"])
    for relative in M0A7_FILES:
        copy_file(REPO, target, relative)
    return temp


class M0A7Tests(unittest.TestCase):
    def test_normalized_report_matches_fixture(self) -> None:
        profile = tomllib.loads((REPO / "EIGIIB.toml").read_text(encoding="utf-8"))
        if "E16-1.0" in profile.get("extensions", []):
            self.skipTest("M0-A7 current-tree replay is superseded by exact historical E16-A1 replay")
        report = CHECKER.evaluate(REPO)
        expected = json.loads((REPO / "tests/fixtures/m0-a7/expected-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report, expected)

    def test_source_head_substitution_is_rejected(self) -> None:
        with make_workspace() as workspace:
            root = Path(workspace)
            path = root / "conformance/m0-a7-e16-entry.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["source_lineage"]["head_commit"] = "0" * 40
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            report = CHECKER.evaluate(root)
            self.assertIn("M0A7.SOURCE.HEAD", {item["code"] for item in report["findings"]})

    def test_frozen_authority_mutation_is_rejected(self) -> None:
        with make_workspace() as workspace:
            root = Path(workspace)
            path = root / "conformance/extension-graph.json"
            path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            report = CHECKER.evaluate(root)
            codes = {item["code"] for item in report["findings"]}
            self.assertTrue({"M0A7.FREEZE.BYTES", "M0A7.FREEZE.DIGEST"} <= codes)

    def test_premature_e16_adoption_is_rejected(self) -> None:
        with make_workspace() as workspace:
            root = Path(workspace)
            path = root / "EIGIIB.toml"
            text = path.read_text(encoding="utf-8")
            text = text.replace('"E15-1.0"]', '"E15-1.0", "E16-1.0"]', 1)
            path.write_text(text, encoding="utf-8")
            report = CHECKER.evaluate(root)
            codes = {item["code"] for item in report["findings"]}
            self.assertIn("M0A7.E16.PREMATURE", codes)
            self.assertIn("M0A7.FREEZE.DIGEST", codes)

    def test_premature_e16_extension_artifact_is_rejected(self) -> None:
        with make_workspace() as workspace:
            root = Path(workspace)
            path = root / "extensions/E16-PREMATURE.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# premature\n", encoding="utf-8")
            report = CHECKER.evaluate(root)
            self.assertIn("M0A7.E16.ARTIFACT", {item["code"] for item in report["findings"]})

    def test_slice_title_mutation_is_rejected(self) -> None:
        with make_workspace() as workspace:
            root = Path(workspace)
            path = root / "conformance/m0-a7-e16-entry.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["planned_slices"][0]["title"] = "Changed"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            report = CHECKER.evaluate(root)
            self.assertIn("M0A7.SLICES.TITLE", {item["code"] for item in report["findings"]})

    def test_multiplatform_run_substitution_is_rejected(self) -> None:
        with make_workspace() as workspace:
            root = Path(workspace)
            path = root / "conformance/m0-a7-e16-entry.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["multiplatform_closure"]["e15_a5_final_closure_run"] += 1
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            report = CHECKER.evaluate(root)
            self.assertIn("M0A7.CLOSURE.FINAL_RUN", {item["code"] for item in report["findings"]})


if __name__ == "__main__":
    unittest.main()
