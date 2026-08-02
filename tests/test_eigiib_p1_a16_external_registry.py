from __future__ import annotations

import base64
import copy
import json
import pathlib
import tempfile
import unittest

from tools.eigiib_p1_a16_common import (
    FIXTURE_DIR,
    ROOT,
    ConformanceError,
    load_json,
    validate_evidence,
    validate_fixture,
    validate_manifest_bytes,
    verify_signed_capsule,
)


class P1A16RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = load_json(FIXTURE_DIR / "live-registry-evidence.json")

    def rejected(self, mutate):
        value = copy.deepcopy(self.evidence)
        mutate(value)
        with self.assertRaises(ConformanceError):
            validate_evidence(value, ROOT)

    def test_01_positive_fixture(self):
        result = validate_fixture(ROOT)
        self.assertEqual(result["manifestDigest"], "sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8")
        self.assertEqual(len(result["layers"]), 3)

    def test_02_source_commit_substitution(self):
        self.rejected(lambda v: v["source"].__setitem__("commit", "0" * 40))

    def test_03_source_release_id_substitution(self):
        self.rejected(lambda v: v["source"].__setitem__("releaseId", 1))

    def test_04_source_release_tag_substitution(self):
        self.rejected(lambda v: v["source"].__setitem__("releaseTag", "other"))

    def test_05_source_asset_omission(self):
        self.rejected(lambda v: v["source"]["assets"].pop())

    def test_06_source_asset_id_substitution(self):
        self.rejected(lambda v: v["source"]["assets"][0].__setitem__("assetId", 1))

    def test_07_source_api_digest_substitution(self):
        self.rejected(lambda v: v["source"]["assets"][0].__setitem__("apiDigest", "sha256:" + "0" * 64))

    def test_08_source_public_digest_substitution(self):
        self.rejected(lambda v: v["source"]["assets"][0].__setitem__("publicDownloadSha256", "0" * 64))

    def test_09_registry_host_substitution(self):
        self.rejected(lambda v: v["registry"].__setitem__("host", "registry.example"))

    def test_10_registry_repository_substitution(self):
        self.rejected(lambda v: v["registry"].__setitem__("repository", "other/repository"))

    def test_11_registry_tag_substitution(self):
        self.rejected(lambda v: v["registry"].__setitem__("tag", "latest"))

    def test_12_manifest_digest_substitution(self):
        self.rejected(lambda v: v["registry"].__setitem__("manifestDigest", "sha256:" + "0" * 64))

    def test_13_manifest_size_substitution(self):
        self.rejected(lambda v: v["registry"].__setitem__("manifestSize", 1494))

    def test_14_artifact_type_substitution(self):
        self.rejected(lambda v: v["registry"].__setitem__("artifactType", "application/octet-stream"))

    def test_15_config_digest_substitution(self):
        self.rejected(lambda v: v["registry"]["config"].__setitem__("digest", "sha256:" + "0" * 64))

    def test_16_registry_layer_omission(self):
        self.rejected(lambda v: v["registry"]["layers"].pop())

    def test_17_manifest_layer_order_substitution(self):
        manifest = json.loads((FIXTURE_DIR / "oci-manifest.json").read_bytes())
        manifest["layers"][0], manifest["layers"][1] = manifest["layers"][1], manifest["layers"][0]
        data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(ConformanceError):
            validate_manifest_bytes(data)

    def test_18_registry_layer_digest_substitution(self):
        self.rejected(lambda v: v["registry"]["layers"][0].__setitem__("digest", "sha256:" + "0" * 64))

    def test_19_registry_layer_media_type_substitution(self):
        self.rejected(lambda v: v["registry"]["layers"][0].__setitem__("mediaType", "application/octet-stream"))

    def test_20_public_registry_digest_substitution(self):
        self.rejected(lambda v: v["registry"]["layers"][0].__setitem__("publicRegistrySha256", "0" * 64))

    def test_21_public_tag_listing_omission(self):
        self.rejected(lambda v: v["registry"].__setitem__("publicTagListing", []))

    def test_22_durable_retention_claim_expansion(self):
        self.rejected(lambda v: v["decisions"].__setitem__("durableRetention", "conformant"))

    def test_23_registry_immutability_claim_expansion(self):
        self.rejected(lambda v: v["decisions"].__setitem__("registryAdministrativeImmutability", "conformant"))

    def test_24_production_claim_expansion(self):
        self.rejected(lambda v: v["decisions"].__setitem__("productionAuthorization", "conformant"))

    def test_25_boundary_substitution(self):
        self.rejected(lambda v: v.__setitem__("boundary", "expanded-boundary"))

    def test_26_capsule_signature_substitution(self):
        capsule = load_json(FIXTURE_DIR / "capsule.json")
        signature = bytearray(base64.b64decode(capsule["signature"]))
        signature[0] ^= 1
        capsule["signature"] = base64.b64encode(signature).decode()
        with tempfile.TemporaryDirectory(prefix="p1-a16-test-") as temp_dir:
            path = pathlib.Path(temp_dir) / "capsule.json"
            path.write_text(json.dumps(capsule, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            with self.assertRaises(ConformanceError):
                verify_signed_capsule(path, FIXTURE_DIR / "evidence-registrar-public-key.pem")


if __name__ == "__main__":
    unittest.main()
