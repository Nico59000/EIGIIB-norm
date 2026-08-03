from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("m0a9", ROOT / "tools/eigiib_m0_a9_check.py")
assert SPEC and SPEC.loader
M0A9 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M0A9)


class M0A9Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for rel in [
            ".github/workflows/m0-a9-cross-lineage-reconciliation.yml",
            "conformance/M0-A9-MANUAL-REVIEW.md",
            "conformance/m0-a9-cross-lineage-capabilities.json",
            "conformance/m0-a9-promotion-readiness.json",
            "conformance/m0-a9-authority-freeze.json",
            "docs/M0-A9-CROSS-LINEAGE-CAPABILITY-RECONCILIATION-CLAIM-BOUNDARY-INDEX-AND-PROMOTION-READINESS.md",
            "docs/M0-A9-HUMAN-MASTERY-GUIDE.md",
            "schemas/eigiib-m0-a9-cross-lineage-reconciliation.schema.json",
            "tests/fixtures/m0-a9/expected-report.json",
            "tests/test_eigiib_m0_a9.py",
            "tools/eigiib_m0_a9_check.py",
            "conformance/m0-a8-lineage-publication.json",
            "conformance/m0-a5-p1-lineage.json",
            "conformance/p1-a15-live-release.json",
            "conformance/p1-a16-external-registry.json",
            "conformance/p1-a17-durable-availability.json",
            "conformance/p1-a18-governance.json",
            "conformance/p1-a19-interoperability.json",
            "conformance/p1-a19-f2-schema-enforcement.json",
            "conformance/p1-a20-runner-toolchain.json",
        ]:
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, target)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def mutate(self, rel: str, fn) -> None:
        path = self.root / rel
        value = json.loads(path.read_text(encoding="utf-8"))
        fn(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def assert_rejected(self) -> None:
        with self.assertRaises(M0A9.ConformanceError):
            M0A9.validate(self.root)

    def test_positive_reconciliation(self) -> None:
        report = M0A9.validate(self.root)
        self.assertEqual(report["capability_count"], 7)
        self.assertEqual(report["promotion_ready"], ["M0-A10"])
        self.assertFalse(report["e17_adopted"])

    def test_exact_fixture(self) -> None:
        report = M0A9.validate(self.root)
        expected = (ROOT / "tests/fixtures/m0-a9/expected-report.json").read_bytes()
        self.assertEqual(M0A9.canonical_bytes(report), expected)

    def test_rejects_m0_a8_head_substitution(self) -> None:
        self.mutate("conformance/m0-a9-cross-lineage-capabilities.json",
                    lambda x: x["source"].__setitem__("m0_a8_head", "0" * 40))
        self.assert_rejected()

    def test_rejects_p1_boundary_substitution(self) -> None:
        self.mutate("conformance/p1-a17-durable-availability.json",
                    lambda x: x.__setitem__("boundary", "broadened"))
        self.assert_rejected()

    def test_rejects_p1_head_substitution(self) -> None:
        self.mutate("conformance/m0-a5-p1-lineage.json",
                    lambda x: next(i for i in x["slices"] if i["id"] == "P1-A18").__setitem__("head_commit", "1" * 40))
        self.assert_rejected()

    def test_rejects_claim_escalation(self) -> None:
        self.mutate("conformance/m0-a9-cross-lineage-capabilities.json",
                    lambda x: x["cross_extension_index"][1].__setitem__("requires_new_operation", False))
        self.assert_rejected()

    def test_rejects_missing_nonclaim(self) -> None:
        self.mutate("conformance/m0-a9-cross-lineage-capabilities.json",
                    lambda x: x["nonclaims"].remove("correlated-failure-resistance"))
        self.assert_rejected()

    def test_rejects_premature_e17_adoption(self) -> None:
        self.mutate("conformance/m0-a9-promotion-readiness.json",
                    lambda x: next(i for i in x["candidates"] if i["id"] == "E17").__setitem__("decision", "adopted"))
        self.assert_rejected()

    def test_rejects_incomplete_m0_a10_operation_set(self) -> None:
        self.mutate("conformance/m0-a9-promotion-readiness.json",
                    lambda x: next(i for i in x["candidates"] if i["id"] == "M0-A10")["required_new_operations"].pop())
        self.assert_rejected()

    def test_rejects_freeze_digest_substitution(self) -> None:
        self.mutate("conformance/m0-a9-authority-freeze.json",
                    lambda x: x["authorities"][0].__setitem__("sha256", "0" * 64))
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
