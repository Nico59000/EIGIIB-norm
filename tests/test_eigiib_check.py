import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools" / "eigiib_check.py"
spec = importlib.util.spec_from_file_location("eigiib_check", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader is not None
spec.loader.exec_module(mod)


VALID_TOML = '''
standard = "EIGIIB-1.0"
extensions = ["E1-1.0", "E2-1.0"]
conformance_target = "EIGIIB-C2"
revision = "r1"
registry = "conformance/registry.json"
ownership_registry = "conformance/ownership.json"
required_authorities = ["scope", "evidence"]

[authorities]
scope = "README.md"
evidence = "conformance/registry.json"

[checks]
markdown_links = true

[[manual_gates]]
id = "semantic-review"
status = "complete"
authority = "scope"
attestation = "conformance/MANUAL.md"
'''


def registry(state="established", evidence_result="pass"):
    return {
        "standard": "EIGIIB-1.0+E1-1.0",
        "revision": "r1",
        "authorities": {
            "scope": "README.md",
            "evidence": "conformance/registry.json",
        },
        "policies": [
            {
                "id": "build",
                "required_kinds": ["compile"],
                "scope_rule": "evidence-superset",
                "manual_gates": [],
            }
        ],
        "claims": [
            {
                "id": "claim.build",
                "subject": "demo",
                "predicate": "builds",
                "revision": "r1",
                "scope": {"os": ["linux"], "arch": ["x86_64"]},
                "authority": "evidence",
                "policy": "build",
                "state": state,
                "evidence": ["ev.build"],
            }
        ],
        "evidence": [
            {
                "id": "ev.build",
                "subject": "demo",
                "revision": "r1",
                "kind": "compile",
                "result": evidence_result,
                "scope": {"os": ["linux"], "arch": ["x86_64"]},
                "provenance": "ci/build",
            }
        ],
    }


class CheckerTests(unittest.TestCase):
    def make_repo(self, *, reg=None, toml=VALID_TOML):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        (root / "README.md").write_text(
            "# Demo\n\n[Manual](conformance/MANUAL.md)\n",
            encoding="utf-8",
        )
        (root / "EIGIIB.toml").write_text(toml, encoding="utf-8")
        (root / "conformance").mkdir()
        (root / "conformance" / "MANUAL.md").write_text(
            "semantic-review complete for r1\n",
            encoding="utf-8",
        )
        (root / "conformance" / "registry.json").write_text(
            json.dumps(reg or registry()),
            encoding="utf-8",
        )
        ownership = {
            "standard": "EIGIIB-1.0+E2-1.0",
            "facts": [
                {"id": "project.scope", "authority": "scope"},
                {"id": "project.evidence", "authority": "evidence"},
            ],
        }
        (root / "conformance" / "ownership.json").write_text(
            json.dumps(ownership),
            encoding="utf-8",
        )
        return td, root

    def test_valid_repository(self):
        td, root = self.make_repo()
        try:
            report = mod.Checker(root, Path("EIGIIB.toml")).run()
            self.assertEqual(report["mechanical_result"], "conformant")
            self.assertEqual(report["manual_result"], "complete")
            self.assertEqual(report["overall_result"], "conformant")
            self.assertFalse(
                [
                    finding
                    for finding in report["findings"]
                    if finding["severity"] == "error"
                ]
            )
        finally:
            td.cleanup()

    def test_established_claim_missing_required_evidence_fails(self):
        reg = registry()
        reg["claims"][0]["evidence"] = []
        td, root = self.make_repo(reg=reg)
        try:
            report = mod.Checker(root, Path("EIGIIB.toml")).run()
            codes = {finding["code"] for finding in report["findings"]}
            self.assertIn("M-STATE.UNSATISFIED", codes)
            self.assertEqual(report["mechanical_result"], "non-conformant")
        finally:
            td.cleanup()

    def test_failing_evidence_contradicts_established_claim(self):
        td, root = self.make_repo(reg=registry(evidence_result="fail"))
        try:
            report = mod.Checker(root, Path("EIGIIB.toml")).run()
            codes = {finding["code"] for finding in report["findings"]}
            self.assertIn("M-STATE.CONTRADICTION", codes)
            self.assertIn("M-STATE.UNSATISFIED", codes)
        finally:
            td.cleanup()

    def test_narrower_evidence_does_not_cover_broader_claim(self):
        reg = registry()
        reg["evidence"][0]["scope"]["compiler"] = ["gcc-14"]
        td, root = self.make_repo(reg=reg)
        try:
            report = mod.Checker(root, Path("EIGIIB.toml")).run()
            codes = {finding["code"] for finding in report["findings"]}
            self.assertIn("M-STATE.UNSATISFIED", codes)
        finally:
            td.cleanup()

    def test_pending_manual_gate_is_partial_not_failure(self):
        toml = VALID_TOML.replace(
            'status = "complete"',
            'status = "pending"',
        )
        td, root = self.make_repo(toml=toml)
        try:
            report = mod.Checker(root, Path("EIGIIB.toml")).run()
            self.assertEqual(report["mechanical_result"], "conformant")
            self.assertEqual(report["manual_result"], "pending")
            self.assertEqual(report["overall_result"], "partially-evaluated")
            self.assertEqual(mod.exit_code(report), 2)
        finally:
            td.cleanup()

    def test_parent_escape_is_rejected(self):
        toml = VALID_TOML.replace(
            'scope = "README.md"',
            'scope = "../outside.md"',
        )
        td, root = self.make_repo(toml=toml)
        try:
            report = mod.Checker(root, Path("EIGIIB.toml")).run()
            codes = {finding["code"] for finding in report["findings"]}
            self.assertIn("M-PATH.ESCAPE", codes)
        finally:
            td.cleanup()

    def test_broken_markdown_link_is_rejected(self):
        td, root = self.make_repo()
        try:
            (root / "README.md").write_text(
                "[missing](does-not-exist.md)\n",
                encoding="utf-8",
            )
            report = mod.Checker(root, Path("EIGIIB.toml")).run()
            codes = {finding["code"] for finding in report["findings"]}
            self.assertIn("M-LINK.MISSING", codes)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
