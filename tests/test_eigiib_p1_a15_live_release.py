from __future__ import annotations

import base64
import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a15_common import (
    BOUNDARY,
    ConformanceError,
    FIXTURE_DIR,
    RELEASE_NAME,
    RELEASE_TAG,
    SOURCE_A14_COMMIT,
    load_json,
    sha256_file,
    validate_evidence,
    validate_fixture,
    verify_signed_capsule,
)


class P1A15LiveReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = load_json(FIXTURE_DIR / "live-release-evidence.json")
        cls.manifest = load_json(FIXTURE_DIR / "live-release-manifest.json")
        cls.manifest_sha = sha256_file(FIXTURE_DIR / "live-release-manifest.json")

    def assert_rejected(self, evidence=None, manifest=None) -> None:
        with self.assertRaises(ConformanceError):
            validate_evidence(
                copy.deepcopy(self.evidence if evidence is None else evidence),
                copy.deepcopy(self.manifest if manifest is None else manifest),
                self.manifest_sha,
            )

    def test_01_positive_fixture(self) -> None:
        report = validate_fixture(ROOT)
        self.assertEqual(report["overallResult"], "conformant")
        self.assertEqual(report["portable"]["peeledCommitSha"], SOURCE_A14_COMMIT)

    def test_02_source_commit_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["source_p1_a14_commit"] = "0" * 40
        self.assert_rejected(value)

    def test_03_source_report_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["source_p1_a14_report_sha256"] = "0" * 64
        self.assert_rejected(value)

    def test_04_source_capsule_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["source_p1_a14_capsule_sha256"] = "0" * 64
        self.assert_rejected(value)

    def test_05_release_id_invalid(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["release"]["id"] = 0
        self.assert_rejected(value)

    def test_06_release_tag_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["release"]["tag_name"] = RELEASE_TAG + "-other"
        self.assert_rejected(value)

    def test_07_release_name_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["release"]["name"] = RELEASE_NAME + " altered"
        self.assert_rejected(value)

    def test_08_draft_release_rejected(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["release"]["draft"] = True
        self.assert_rejected(value)

    def test_09_non_prerelease_rejected(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["release"]["prerelease"] = False
        self.assert_rejected(value)

    def test_10_tag_target_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["release"]["peeled_commit_sha"] = "f" * 40
        self.assert_rejected(value)

    def test_11_tag_object_type_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["release"]["tag_object_type"] = "tag"
        self.assert_rejected(value)

    def test_12_asset_omission(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["assets"].pop()
        self.assert_rejected(value)

    def test_13_asset_name_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["assets"][0]["name"] = "substituted.bin"
        self.assert_rejected(value)

    def test_14_api_digest_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["assets"][0]["api_digest"] = "sha256:" + "0" * 64
        self.assert_rejected(value)

    def test_15_authenticated_digest_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["assets"][0]["authenticated_download_sha256"] = "0" * 64
        self.assert_rejected(value)

    def test_16_public_digest_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["assets"][0]["public_download_sha256"] = "0" * 64
        self.assert_rejected(value)

    def test_17_manifest_target_substitution(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["target_commit_sha"] = "0" * 40
        self.assert_rejected(manifest=value)

    def test_18_manifest_asset_substitution(self) -> None:
        value = copy.deepcopy(self.manifest)
        value["assets"][0]["digest"] = "sha256:" + "0" * 64
        self.assert_rejected(manifest=value)

    def test_19_boundary_substitution(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["boundary"] = BOUNDARY + "-expanded"
        self.assert_rejected(value)

    def test_20_immutability_decision_must_match_field(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["decisions"]["platform_immutability_enforcement"] = "conformant-for-github-immutable-release-scope"
        self.assert_rejected(value)

    def test_21_production_claim_expansion(self) -> None:
        value = copy.deepcopy(self.evidence)
        value["decisions"]["production_release_authorization"] = "conformant"
        self.assert_rejected(value)

    def test_22_capsule_signature_substitution(self) -> None:
        capsule_path = FIXTURE_DIR / "capsule.json"
        capsule = load_json(capsule_path)
        signature = bytearray(base64.b64decode(capsule["signature"]))
        signature[0] ^= 1
        capsule["signature"] = base64.b64encode(signature).decode()
        temp = self.subTest("mutated capsule")
        with temp:
            mutated = FIXTURE_DIR / ".capsule-mutated.tmp.json"
            try:
                mutated.write_text(json.dumps(capsule, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
                with self.assertRaises(ConformanceError):
                    verify_signed_capsule(mutated, FIXTURE_DIR / "evidence-registrar-public-key.pem")
            finally:
                mutated.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
