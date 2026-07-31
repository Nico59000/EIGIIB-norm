import importlib.util
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "tools" / "eigiib_interop_profiles_check.py"
spec = importlib.util.spec_from_file_location("interop", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def base_registry():
    return {
        "standard": "EIGIIB-M0-A3-1.0",
        "revision": "test",
        "as_of": "2026-07-31",
        "freshness_basis": "declared-observation-date-only",
        "external_specs": [
            {
                "id": "spec-1.2",
                "name": "Spec",
                "version": "1.2",
                "status": "released",
                "domain": "attestation",
                "canonical_uri": "https://example.test/spec/v1.2/",
                "reference_mode": "versioned-reference",
                "observed_on": "2026-07-31",
            }
        ],
        "profiles": [
            {
                "id": "profile-v1",
                "revision": "1.0",
                "state": "specified",
                "external_spec": "spec-1.2",
                "direction": "import",
                "eigiib_authorities": ["e1", "e3"],
                "mappings": [
                    {
                        "external_element": "subject",
                        "eigiib_element": "artifact",
                        "relation": "represents",
                        "strength": "bounded-semantic",
                    }
                ],
                "does_not_imply": ["format-does-not-imply-truth"],
                "evidence": [],
            }
        ],
    }


def identity():
    return {"algorithm": "sha256", "digest": "a" * 64, "bytes": 123}


class InteropProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "conformance").mkdir()
        (self.root / "evidence").mkdir()
        (self.root / "evidence/ok.json").write_text("{}")
        (self.root / "EIGIIB.toml").write_text(
            '[authorities]\n'
            'e1 = "extensions/E1.md"\n'
            'e3 = "extensions/E3.md"\n'
            'e4 = "extensions/E4.md"\n'
            'e5 = "extensions/E5.md"\n'
            'e6 = "extensions/E6.md"\n'
            'aggregate_conformance = "docs/M0-A2.md"\n'
        )

    def tearDown(self):
        self.tmp.cleanup()

    def run_obj(self, obj):
        (self.root / "conformance/interop-profiles.json").write_text(json.dumps(obj))
        return mod.Checker(
            self.root,
            Path("conformance/interop-profiles.json"),
            Path("EIGIIB.toml"),
        ).run()

    def assert_code(self, result, code):
        self.assertTrue(any(f["code"] == code for f in result["findings"]), result)

    def test_baseline_conformant(self):
        r = self.run_obj(base_registry())
        self.assertEqual(r["structural_result"], "conformant")
        self.assertEqual(r["external_spec_count"], 1)
        self.assertEqual(r["profile_count"], 1)

    def test_freshness_basis_is_explicit_and_fixed(self):
        o = base_registry(); o["freshness_basis"] = "network-fresh"
        r = self.run_obj(o); self.assert_code(r, "M0A3.FRESHNESS_BASIS")

    def test_duplicate_external_spec_rejected(self):
        o = base_registry(); o["external_specs"].append(deepcopy(o["external_specs"][0]))
        r = self.run_obj(o)
        self.assertEqual(r["structural_result"], "non-conformant")
        self.assert_code(r, "M0A3.SPEC.DUPLICATE")

    def test_floating_version_token_rejected(self):
        o = base_registry(); o["external_specs"][0]["version"] = "latest"
        r = self.run_obj(o); self.assert_code(r, "M0A3.SPEC.FLOATING_VERSION")

    def test_non_https_uri_rejected(self):
        o = base_registry(); o["external_specs"][0]["canonical_uri"] = "http://example.test/spec/v1.2/"
        r = self.run_obj(o); self.assert_code(r, "M0A3.SPEC.URI")

    def test_versioned_uri_must_expose_version(self):
        o = base_registry(); o["external_specs"][0]["canonical_uri"] = "https://example.test/spec/release/"
        r = self.run_obj(o); self.assert_code(r, "M0A3.SPEC.VERSION_URI")

    def test_exact_draft_requires_draft_status_and_revision_uri(self):
        o = base_registry(); s = o["external_specs"][0]
        s.update({"version": "draft-x-22", "reference_mode": "exact-draft", "canonical_uri": "https://example.test/draft-x-21", "status": "released"})
        r = self.run_obj(o)
        self.assert_code(r, "M0A3.SPEC.DRAFT_STATUS")
        self.assert_code(r, "M0A3.SPEC.DRAFT_URI")

    def test_observation_cannot_be_after_snapshot(self):
        o = base_registry(); o["external_specs"][0]["observed_on"] = "2026-08-01"
        r = self.run_obj(o); self.assert_code(r, "M0A3.SPEC.DATE_ORDER")

    def test_invalid_external_identity_rejected_when_present(self):
        o = base_registry(); o["external_specs"][0]["identity"] = {"algorithm": "sha256", "digest": "bad", "bytes": 1}
        r = self.run_obj(o); self.assert_code(r, "M0A3.SPEC.IDENTITY")

    def test_unresolved_external_spec_rejected(self):
        o = base_registry(); o["profiles"][0]["external_spec"] = "missing"
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.SPEC")

    def test_unknown_eigiib_authority_rejected(self):
        o = base_registry(); o["profiles"][0]["eigiib_authorities"].append("invented")
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.AUTHORITY_REF")

    def test_moving_reference_cannot_be_validated(self):
        o = base_registry(); o["external_specs"][0]["reference_mode"] = "moving-reference"
        p = o["profiles"][0]; p["state"] = "validated"; p["evidence"] = ["evidence/ok.json"]
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.UNSTABLE_VALIDATION")

    def test_draft_cannot_be_validated(self):
        o = base_registry(); s = o["external_specs"][0]
        s.update({"version": "draft-x-22", "status": "draft", "reference_mode": "exact-draft", "canonical_uri": "https://example.test/draft-x-22"})
        p = o["profiles"][0]; p["state"] = "validated"; p["evidence"] = ["evidence/ok.json"]
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.UNSTABLE_VALIDATION")

    def test_validated_profile_requires_external_spec_identity(self):
        o = base_registry(); p = o["profiles"][0]
        p["state"] = "validated"; p["evidence"] = ["evidence/ok.json"]
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.SPEC_IDENTITY")

    def test_implemented_profile_requires_evidence(self):
        o = base_registry(); o["profiles"][0]["state"] = "implemented"
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.EVIDENCE_REQUIRED")

    def test_evidence_path_must_exist_and_be_confined(self):
        o = base_registry(); p = o["profiles"][0]; p["state"] = "implemented"; p["evidence"] = ["../escape.json"]
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.EVIDENCE.PATH")
        o = base_registry(); p = o["profiles"][0]; p["state"] = "implemented"; p["evidence"] = ["evidence/missing.json"]
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.EVIDENCE.MISSING")

    def test_exact_semantic_requires_validated_profile(self):
        o = base_registry(); o["profiles"][0]["mappings"][0]["strength"] = "exact-semantic"
        r = self.run_obj(o); self.assert_code(r, "M0A3.MAPPING.EXACT_UNVALIDATED")

    def test_empty_negative_boundary_rejected(self):
        o = base_registry(); o["profiles"][0]["does_not_imply"] = []
        r = self.run_obj(o); self.assert_code(r, "M0A3.PROFILE.BOUNDARY")

    def test_duplicate_mapping_rejected(self):
        o = base_registry(); o["profiles"][0]["mappings"].append(deepcopy(o["profiles"][0]["mappings"][0]))
        r = self.run_obj(o); self.assert_code(r, "M0A3.MAPPING.DUPLICATE")

    def test_validated_exact_mapping_with_identity_and_evidence_is_allowed(self):
        o = base_registry(); p = o["profiles"][0]
        o["external_specs"][0]["identity"] = identity()
        p["state"] = "validated"; p["evidence"] = ["evidence/ok.json"]; p["mappings"][0]["strength"] = "exact-semantic"
        r = self.run_obj(o)
        self.assertEqual(r["structural_result"], "conformant")
        self.assertEqual(r["validated_profile_count"], 1)


if __name__ == "__main__":
    unittest.main()
