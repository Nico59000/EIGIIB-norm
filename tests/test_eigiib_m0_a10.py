from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "eigiib_m0_a10_check",
    ROOT / "tools/eigiib_m0_a10_check.py",
)
CHECK = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CHECK)


class M0A10Test(unittest.TestCase):
    def _copy_authority(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        holder = tempfile.TemporaryDirectory()
        target = Path(holder.name)
        freeze = json.loads((ROOT / CHECK.FREEZE_PATH).read_text(encoding="utf-8"))
        paths = [item["path"] for item in freeze["authorities"]]
        paths += [CHECK.FREEZE_PATH, CHECK.PROMOTION_PATH]
        for rel in paths:
            source = ROOT / rel
            destination = target / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        return holder, target

    @staticmethod
    def _json(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _write(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    def _evaluate(self, target: Path) -> dict:
        return CHECK.evaluate(target, verify_signature=False)

    def test_positive_authority(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        report = self._evaluate(target)
        self.assertEqual("conformant", report["structural_result"], report["findings"])
        expected = json.loads((ROOT / "tests/fixtures/m0-a10/expected-report.json").read_text())
        self.assertEqual(expected, report)

    def test_m0_a9_head_substitution_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.AUTHORITY_PATH
        doc = self._json(path)
        doc["source"]["m0A9Head"] = "0" * 40
        self._write(path, doc)
        self.assertIn("M0A10.SOURCE.M0A9", self._evaluate(target)["findings"])

    def test_stable_e16_head_substitution_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.MANIFEST_PATH
        doc = self._json(path)
        doc["source"]["commit"] = "1" * 40
        self._write(path, doc)
        self.assertIn("M0A10.MANIFEST.SOURCE", self._evaluate(target)["findings"])

    def test_bundle_digest_substitution_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.EVIDENCE_PATH
        doc = self._json(path)
        doc["bundle"]["sha256"] = "2" * 64
        self._write(path, doc)
        self.assertIn("M0A10.EVIDENCE.BUNDLE", self._evaluate(target)["findings"])

    def test_signer_boundary_escalation_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.MANIFEST_PATH
        doc = self._json(path)
        doc["signature"]["authorityBoundary"] = "trusted-production-release-authority"
        self._write(path, doc)
        self.assertIn("M0A10.MANIFEST.BOUNDARY", self._evaluate(target)["findings"])

    def test_release_draft_state_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.EVIDENCE_PATH
        doc = self._json(path)
        doc["githubRelease"]["draft"] = True
        self._write(path, doc)
        self.assertIn("M0A10.EVIDENCE.RELEASE_STATE", self._evaluate(target)["findings"])

    def test_oci_manifest_digest_substitution_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.AUTHORITY_PATH
        doc = self._json(path)
        doc["channels"]["ociRegistry"]["manifestDigest"] = "sha256:" + "3" * 64
        self._write(path, doc)
        self.assertIn("M0A10.OCI.IDENTITY", self._evaluate(target)["findings"])

    def test_missing_public_route_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.EVIDENCE_PATH
        doc = self._json(path)
        del doc["routes"]["release-public"]
        self._write(path, doc)
        self.assertIn("M0A10.EVIDENCE.ROUTES", self._evaluate(target)["findings"])

    def test_future_availability_escalation_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.EVIDENCE_PATH
        doc = self._json(path)
        doc["claims"]["futureAvailability"] = "established"
        self._write(path, doc)
        self.assertIn("M0A10.EVIDENCE.NONCLAIM:futureAvailability", self._evaluate(target)["findings"])

    def test_cleanup_ref_reappearance_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.CLEANUP_PATH
        doc = self._json(path)
        doc["objects"][0]["branchRefPresent"] = True
        self._write(path, doc)
        findings = self._evaluate(target)["findings"]
        self.assertTrue(any(item.startswith("M0A10.CLEANUP.REF:") for item in findings))

    def test_premature_e17_adoption_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.AUTHORITY_PATH
        doc = self._json(path)
        doc["naturalSuccessor"]["decision"] = "adopted"
        self._write(path, doc)
        self.assertIn("M0A10.SUCCESSOR.DECISION", self._evaluate(target)["findings"])

    def test_freeze_digest_substitution_is_rejected(self) -> None:
        holder, target = self._copy_authority()
        self.addCleanup(holder.cleanup)
        path = target / CHECK.FREEZE_PATH
        doc = self._json(path)
        doc["authorities"][0]["sha256"] = "4" * 64
        self._write(path, doc)
        findings = self._evaluate(target)["findings"]
        self.assertTrue(any(item.startswith("M0A10.FREEZE.SHA256:") for item in findings))


if __name__ == "__main__":
    unittest.main()
