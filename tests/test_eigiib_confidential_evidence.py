from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
TOOL = HERE.parents[1] / "tools/eigiib_confidential_evidence_check.py"
spec = importlib.util.spec_from_file_location("e14check", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class E14Tests(unittest.TestCase):
    def repo(self, production: bool = False):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        for rel in (
            "extensions/E14-CONFIDENTIAL-EVIDENCE-SELECTIVE-DISCLOSURE-INFORMATION-MINIMIZATION.md",
            "docs/E14-A1-HUMAN-MASTERY-GUIDE.md",
            "conformance/E14-A1-MANUAL-REVIEW.md",
            "conformance/m0-a5-e14-handoff.json",
            "conformance/m0-a5-f1-authority-freeze.json",
        ):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")

        profile = '''standard = "EIGIIB-1.0"
extensions = ["E14-1.0"]
revision = "EIGIIB-E14-draft-1.0"
required_authorities = ["e14", "confidential_evidence", "e14_a1_transition", "e14_a1_human_mastery"]

[authorities]
e14 = "extensions/E14-CONFIDENTIAL-EVIDENCE-SELECTIVE-DISCLOSURE-INFORMATION-MINIMIZATION.md"
confidential_evidence = "conformance/confidential-evidence.json"
e14_a1_transition = "conformance/e14-a1-adoption-transition.json"
e14_a1_human_mastery = "docs/E14-A1-HUMAN-MASTERY-GUIDE.md"

[[manual_gates]]
id = "e14-a1-confidential-evidence-boundary-review"
status = "complete"
authority = "e14"
attestation = "conformance/E14-A1-MANUAL-REVIEW.md"
'''
        (root / "EIGIIB.toml").write_text(profile, encoding="utf-8")
        transition = {
            "standard": mod.TRANSITION_STANDARD,
            "status": "adopted-e14-a1",
            "source": {
                "branch": "agent/m0-a5-canonical-p1-lineage-authority-promotion-e14-handoff",
                "head_commit": mod.SOURCE_HEAD,
                "handoff_authority": "conformance/m0-a5-e14-handoff.json",
                "freeze_authority": "conformance/m0-a5-f1-authority-freeze.json",
            },
            "target": {"extension": "E14-1.0", "slice": "E14-A1", "adoption_state": "adopted"},
            "consumed_inputs": {key: key for key in mod.EXPECTED_INPUTS},
            "historical_preservation": {"m0_a5_report_rewritten": False, "pre_adoption_finding_preserved": True},
        }
        path = root / "conformance/e14-a1-adoption-transition.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(transition), encoding="utf-8")

        registry = {"standard": mod.STANDARD, "revision": "EIGIIB-E14-draft-1.0", "status": "structural-only", "records": [], "projections": []}
        if production:
            evidence = root / "private/evidence.bin"
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_bytes(b"confidential-evidence\x00v1")
            claim1 = {"id": "c1", "type": "measurement", "subject": "artifact:A", "predicate": "score", "object": 91, "scope": ["region:eu", "release:r1"], "assurance": 3, "evidence": ["ev:1", "ev:2"]}
            claim2 = {"id": "c2", "type": "status", "subject": "artifact:A", "predicate": "review", "object": "passed", "scope": ["release:r1"], "assurance": 2, "evidence": ["ev:3"]}
            record = {
                "id": "r1", "revision": "1", "subject": "artifact:A", "classification": "confidential", "source_authority": "authority:lab",
                "artifact": {"path": "private/evidence.bin", "algorithm": "sha256", "digest": hashlib.sha256(evidence.read_bytes()).hexdigest(), "bytes": len(evidence.read_bytes())},
                "claims": [claim1, claim2], "revocation_state": "active", "commitment": {"algorithm": "sha256", "digest": ""},
            }
            record["commitment"]["digest"] = mod.commitment_for(record)
            projection_claim = {"source_claim": "c1", "type": "measurement", "subject": "artifact:A", "predicate": "score", "object": 91, "scope": ["release:r1"], "assurance": 2, "evidence": ["ev:1"]}
            projection = {
                "id": "p1", "revision": "1", "state": "sealed", "source_record": "r1", "source_revision": "1",
                "source_artifact_digest": record["artifact"]["digest"], "source_commitment": record["commitment"]["digest"],
                "authorized_audience": {"id": "aud:reviewer", "revision": "1"},
                "disclosure_policy": {"id": "policy:minimal", "revision": "1"},
                "evaluation_context": {"id": "context:case-7", "revision": "1"},
                "correlation_controls": ["audience-bound", "context-bound"], "claims": [projection_claim], "omitted_claims": ["c2"],
                "commitment": {"algorithm": "sha256", "digest": ""},
            }
            projection["commitment"]["digest"] = mod.commitment_for(projection)
            registry["records"] = [record]
            registry["projections"] = [projection]
        registry_path = root / "conformance/confidential-evidence.json"
        registry_path.write_text(json.dumps(registry), encoding="utf-8")
        return td, root, registry

    def run_check(self, root):
        return mod.Checker(root).run()

    def write_registry(self, root, registry):
        (root / "conformance/confidential-evidence.json").write_text(json.dumps(registry), encoding="utf-8")

    def resign(self, registry):
        for record in registry["records"]:
            record["commitment"]["digest"] = mod.commitment_for(record)
        for projection in registry["projections"]:
            source = next(r for r in registry["records"] if r["id"] == projection["source_record"])
            projection["source_artifact_digest"] = source["artifact"]["digest"]
            projection["source_commitment"] = source["commitment"]["digest"]
            projection["commitment"]["digest"] = mod.commitment_for(projection)

    def test_structural_registry(self):
        td, root, _ = self.repo()
        self.addCleanup(td.cleanup)
        report = self.run_check(root)
        expected = json.loads((HERE.parent / "fixtures/e14-a1/expected-report.json").read_text())
        self.assertEqual(expected, report)

    def test_valid_projection(self):
        td, root, _ = self.repo(True)
        self.addCleanup(td.cleanup)
        report = self.run_check(root)
        self.assertEqual("conformant", report["structural_result"])
        self.assertEqual("conformant", report["claim_boundary_result"])

    def test_artifact_digest_mismatch(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["records"][0]["artifact"]["digest"] = "0" * 64
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.RECORD.ARTIFACT.DIGEST" for f in report["findings"]))

    def test_semantic_strengthening_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["projections"][0]["claims"][0]["object"] = 99
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.CLAIM.SEMANTIC_DRIFT" for f in report["findings"]))

    def test_scope_broadening_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["projections"][0]["claims"][0]["scope"].append("region:world")
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.CLAIM.SCOPE_BROADENED" for f in report["findings"]))

    def test_assurance_increase_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["projections"][0]["claims"][0]["assurance"] = 4
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.CLAIM.ASSURANCE_STRENGTHENED" for f in report["findings"]))

    def test_added_evidence_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["projections"][0]["claims"][0]["evidence"].append("ev:new")
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.CLAIM.EVIDENCE_ADDED" for f in report["findings"]))

    def test_stale_source_revision_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["projections"][0]["source_revision"] = "0"
        registry["projections"][0]["commitment"]["digest"] = mod.commitment_for(registry["projections"][0])
        self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.SOURCE_REVISION" for f in report["findings"]))

    def test_revoked_source_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["records"][0]["revocation_state"] = "revoked"
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.SOURCE_REVOKED" for f in report["findings"]))

    def test_omission_accounting_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["projections"][0]["omitted_claims"] = []
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.OMISSION_ACCOUNTING" for f in report["findings"]))

    def test_projection_commitment_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["projections"][0]["commitment"]["digest"] = "0" * 64
        self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.PROJECTION.COMMITMENT" for f in report["findings"]))

    def test_path_escape_rejected(self):
        td, root, registry = self.repo(True)
        self.addCleanup(td.cleanup)
        registry["records"][0]["artifact"]["path"] = "../escape.bin"
        self.resign(registry); self.write_registry(root, registry)
        report = self.run_check(root)
        self.assertTrue(any(f["code"] == "E14.RECORD.ARTIFACT.PATH" for f in report["findings"]))


if __name__ == "__main__":
    unittest.main()
