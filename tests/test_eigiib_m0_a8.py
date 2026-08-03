from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("eigiib_m0_a8_check", ROOT / "tools/eigiib_m0_a8_check.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class M0A8Tests(unittest.TestCase):
    def test_repository_authority_conforms(self) -> None:
        report = MODULE.check(ROOT)
        self.assertEqual(report["overall_result"], "conformant", report["findings"])
        expected = json.loads((ROOT / "tests/fixtures/m0-a8/expected-report.json").read_text(encoding="utf-8"))
        self.assertEqual(report, expected)

    def test_direct_agent_pr_to_main_is_rejected(self) -> None:
        event = {
            "pull_request": {
                "base": {"ref": "main", "sha": MODULE.DEFAULT_HEAD},
                "head": {"ref": "agent/accidental-cumulative", "sha": "0" * 40},
            }
        }
        authority = json.loads((ROOT / MODULE.AUTHORITY_PATH).read_text(encoding="utf-8"))
        findings: list[dict[str, str]] = []
        MODULE._check_event(authority, event, findings)
        self.assertEqual([item["code"] for item in findings], ["M0A8.EVENT.DIRECT_TO_DEFAULT"])

    def test_exact_m0_a8_stack_is_admitted(self) -> None:
        event = {
            "pull_request": {
                "base": {"ref": MODULE.SOURCE_BRANCH, "sha": MODULE.SOURCE_HEAD},
                "head": {"ref": MODULE.M0_A8_BRANCH, "sha": "1" * 40},
            }
        }
        authority = json.loads((ROOT / MODULE.AUTHORITY_PATH).read_text(encoding="utf-8"))
        findings: list[dict[str, str]] = []
        MODULE._check_event(authority, event, findings)
        self.assertEqual(findings, [])

    def test_lineage_substitution_is_rejected(self) -> None:
        authority = json.loads((ROOT / MODULE.AUTHORITY_PATH).read_text(encoding="utf-8"))
        mutated = copy.deepcopy(authority)
        mutated["authoritative_pr_topology"][10]["base_head"] = "f" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "conformance").mkdir()
            (root / MODULE.AUTHORITY_PATH).write_text(json.dumps(mutated), encoding="utf-8")
            (root / MODULE.E16_CLOSURE_PATH).write_text((ROOT / MODULE.E16_CLOSURE_PATH).read_text(encoding="utf-8"), encoding="utf-8")
            (root / MODULE.E16_FREEZE_PATH).write_text((ROOT / MODULE.E16_FREEZE_PATH).read_text(encoding="utf-8"), encoding="utf-8")
            report = MODULE.check(root)
        self.assertEqual(report["overall_result"], "non-conformant")
        self.assertIn("M0A8.TOPOLOGY.CHAIN", {item["code"] for item in report["findings"]})

    def test_default_branch_migration_claim_is_rejected(self) -> None:
        authority = json.loads((ROOT / MODULE.AUTHORITY_PATH).read_text(encoding="utf-8"))
        mutated = copy.deepcopy(authority)
        mutated["reconciliation"]["default_branch_moved"] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "conformance").mkdir()
            (root / MODULE.AUTHORITY_PATH).write_text(json.dumps(mutated), encoding="utf-8")
            (root / MODULE.E16_CLOSURE_PATH).write_text((ROOT / MODULE.E16_CLOSURE_PATH).read_text(encoding="utf-8"), encoding="utf-8")
            (root / MODULE.E16_FREEZE_PATH).write_text((ROOT / MODULE.E16_FREEZE_PATH).read_text(encoding="utf-8"), encoding="utf-8")
            report = MODULE.check(root)
        self.assertEqual(report["overall_result"], "non-conformant")
        self.assertIn("M0A8.RECONCILIATION", {item["code"] for item in report["findings"]})


if __name__ == "__main__":
    unittest.main()
