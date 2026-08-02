from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve()
TOOL = HERE.parents[1] / "tools" / "eigiib_disclosure_authorization_check.py"
spec = importlib.util.spec_from_file_location("e14a2", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def upstream_registry():
    return {
        "standard": mod.UPSTREAM_STANDARD,
        "revision": "EIGIIB-E14-draft-1.0",
        "status": "structural-only",
        "records": [{
            "id": "record-1",
            "revision": "record-r1",
            "subject": "subject-A",
            "classification": "confidential",
            "source_authority": "fixture-authority",
            "artifact": {"path": "private/record.bin", "algorithm": "sha256", "digest": "c" * 64, "bytes": 3},
            "claims": [{
                "id": "claim-1", "type": "verification", "subject": "subject-A",
                "predicate": "passed", "object": True, "scope": ["build"],
                "assurance": 3, "evidence": ["ev-1"],
            }],
            "revocation_state": "active",
            "commitment": {"algorithm": "sha256", "digest": "a" * 64},
        }],
        "projections": [{
            "id": "projection-1",
            "revision": "projection-r1",
            "state": "sealed",
            "source_record": "record-1",
            "source_revision": "record-r1",
            "source_artifact_digest": "c" * 64,
            "source_commitment": "a" * 64,
            "authorized_audience": {"id": "audience-1", "revision": "audience-r1"},
            "disclosure_policy": {"id": "policy-1", "revision": "policy-r1"},
            "evaluation_context": {"id": "context-1", "revision": "context-r1"},
            "correlation_controls": ["audience-bound", "single-use"],
            "claims": [{
                "source_claim": "claim-1", "type": "verification", "subject": "subject-A",
                "predicate": "passed", "object": True, "scope": ["build"],
                "assurance": 2, "evidence": ["ev-1"],
            }],
            "omitted_claims": [],
            "commitment": {"algorithm": "sha256", "digest": "b" * 64},
        }],
    }


def authorization_registry():
    return {
        "standard": mod.STANDARD,
        "status": "structural-only",
        "upstream_registry": "conformance/confidential-evidence.json",
        "audiences": [{
            "id": "audience-1", "revision": "audience-r1", "state": "active",
            "subjects": ["subject-A"], "classifications": ["confidential"],
            "purposes": ["supplier-review"], "required_authentication": "mfa-bound-session",
        }],
        "disclosure_policies": [{
            "id": "policy-1", "revision": "policy-r1", "state": "active",
            "allowed_audiences": ["audience-1"],
            "allowed_classifications": ["confidential"],
            "allowed_purposes": ["supplier-review"],
            "allowed_claim_types": ["verification"],
            "allowed_predicates": ["passed"],
            "max_assurance": 2, "max_claims": 1,
            "required_correlation_controls": ["audience-bound", "single-use"],
            "allow_empty_projection": False,
        }],
        "evaluation_contexts": [{
            "id": "context-1", "revision": "context-r1", "state": "active",
            "purpose": "supplier-review", "action": mod.ACTION,
            "operation": "operation-7", "subject": "subject-A",
        }],
        "requests": [{
            "id": "request-1", "revision": "request-r1",
            "projection": "projection-1", "projection_revision": "projection-r1",
            "projection_commitment": "b" * 64,
            "source_record": "record-1", "source_revision": "record-r1",
            "source_commitment": "a" * 64,
            "audience": "audience-1", "audience_revision": "audience-r1",
            "policy": "policy-1", "policy_revision": "policy-r1",
            "context": "context-1", "context_revision": "context-r1",
            "purpose": "supplier-review", "action": mod.ACTION, "operation": "operation-7",
        }],
        "decisions": [{
            "id": "decision-1", "request": "request-1", "request_revision": "request-r1",
            "state": "permit", "projection_result": "admissible",
            "audience_result": "eligible", "policy_result": "permit",
            "context_result": "admissible", "evaluator": "fixture-evaluator",
            "reasons": ["all-gates-positive"], "evidence": ["evaluation-report-1"],
        }],
    }


class DisclosureAuthorizationTests(unittest.TestCase):
    def repo(self, registry=None, upstream=None):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        self.addCleanup(temporary.cleanup)
        for rel in [
            "extensions/E14-A2-DISCLOSURE-AUTHORIZATION-AUDIENCE-ELIGIBILITY-CONTEXT-REVALIDATION.md",
            "docs/E14-A2-HUMAN-MASTERY-GUIDE.md",
            "conformance/E14-A2-MANUAL-REVIEW.md",
        ]:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# fixture\n")
        profile = '''standard = "EIGIIB-1.0"
extensions = ["E14-1.0"]
revision = "EIGIIB-E14-draft-1.0"
required_authorities = ["confidential_evidence", "e14_a2_contract", "disclosure_authorization", "e14_a2_human_mastery"]

[authorities]
confidential_evidence = "conformance/confidential-evidence.json"
e14_a2_contract = "extensions/E14-A2-DISCLOSURE-AUTHORIZATION-AUDIENCE-ELIGIBILITY-CONTEXT-REVALIDATION.md"
disclosure_authorization = "conformance/disclosure-authorization.json"
e14_a2_human_mastery = "docs/E14-A2-HUMAN-MASTERY-GUIDE.md"

[[manual_gates]]
id = "e14-a2-disclosure-authorization-boundary-review"
status = "complete"
authority = "e14_a2_contract"
attestation = "conformance/E14-A2-MANUAL-REVIEW.md"
'''
        (root / "EIGIIB.toml").write_text(profile)
        conf = root / "conformance"
        conf.mkdir(exist_ok=True)
        (conf / "confidential-evidence.json").write_text(json.dumps(upstream if upstream is not None else upstream_registry()))
        (conf / "disclosure-authorization.json").write_text(json.dumps(registry if registry is not None else authorization_registry()))
        return root

    def check(self, registry=None, upstream=None):
        return mod.Checker(self.repo(registry, upstream)).run()

    @staticmethod
    def codes(result):
        return {finding["code"] for finding in result["findings"]}

    @staticmethod
    def set_decision(registry, state, projection, audience, policy, context, evidence=None):
        decision = registry["decisions"][0]
        decision.update({
            "state": state,
            "projection_result": projection,
            "audience_result": audience,
            "policy_result": policy,
            "context_result": context,
            "evidence": [] if evidence is None else evidence,
        })

    def test_structural_only_registry(self):
        registry = authorization_registry()
        for key in ("audiences", "disclosure_policies", "evaluation_contexts", "requests", "decisions"):
            registry[key] = []
        result = self.check(registry)
        self.assertEqual("conformant", result["structural_result"])
        self.assertEqual("not-evaluated", result["authorization_result"])

    def test_valid_permit(self):
        result = self.check()
        self.assertEqual("conformant", result["authorization_result"])
        self.assertEqual(1, result["decision_counts"]["permit"])

    def test_policy_denial_cannot_be_declared_permit(self):
        registry = authorization_registry()
        registry["disclosure_policies"][0]["allowed_predicates"] = ["different"]
        result = self.check(registry)
        self.assertIn("E14A2.DECISION.COMPONENT", self.codes(result))
        self.assertIn("E14A2.DECISION.DERIVATION", self.codes(result))

    def test_audience_ineligible_can_be_declared_deny(self):
        registry = authorization_registry()
        registry["audiences"][0]["subjects"] = ["other-subject"]
        self.set_decision(registry, "deny", "admissible", "ineligible", "permit", "admissible", ["denial-report"])
        result = self.check(registry)
        self.assertEqual("conformant", result["authorization_result"])
        self.assertEqual(1, result["decision_counts"]["deny"])

    def test_context_revision_change_requires_new_request(self):
        registry = authorization_registry()
        registry["evaluation_contexts"][0]["revision"] = "context-r2"
        result = self.check(registry)
        self.assertIn("E14A2.REQUEST.CONTEXT_REVISION", self.codes(result))

    def test_prepared_projection_is_held(self):
        upstream = upstream_registry()
        upstream["projections"][0]["state"] = "prepared"
        registry = authorization_registry()
        self.set_decision(registry, "held", "held", "eligible", "permit", "admissible")
        result = self.check(registry, upstream)
        self.assertEqual("conformant", result["authorization_result"])
        self.assertEqual(1, result["decision_counts"]["held"])

    def test_unavailable_source_is_unavailable(self):
        upstream = upstream_registry()
        upstream["records"][0]["revocation_state"] = "unavailable"
        registry = authorization_registry()
        self.set_decision(registry, "unavailable", "unavailable", "eligible", "permit", "admissible")
        result = self.check(registry, upstream)
        self.assertEqual("conformant", result["authorization_result"])

    def test_missing_correlation_control_derives_deny(self):
        upstream = upstream_registry()
        upstream["projections"][0]["correlation_controls"] = ["audience-bound"]
        registry = authorization_registry()
        self.set_decision(registry, "deny", "admissible", "eligible", "deny", "admissible", ["policy-report"])
        result = self.check(registry, upstream)
        self.assertEqual("conformant", result["authorization_result"])

    def test_assurance_above_policy_ceiling_derives_deny(self):
        registry = authorization_registry()
        registry["disclosure_policies"][0]["max_assurance"] = 1
        self.set_decision(registry, "deny", "admissible", "eligible", "deny", "admissible", ["policy-report"])
        result = self.check(registry)
        self.assertEqual("conformant", result["authorization_result"])

    def test_empty_projection_requires_explicit_permission(self):
        upstream = upstream_registry()
        upstream["projections"][0]["claims"] = []
        upstream["projections"][0]["omitted_claims"] = ["claim-1"]
        registry = authorization_registry()
        self.set_decision(registry, "deny", "admissible", "eligible", "deny", "admissible", ["policy-report"])
        result = self.check(registry, upstream)
        self.assertEqual("conformant", result["authorization_result"])

    def test_duplicate_decision_rejected(self):
        registry = authorization_registry()
        duplicate = deepcopy(registry["decisions"][0])
        duplicate["id"] = "decision-2"
        registry["decisions"].append(duplicate)
        result = self.check(registry)
        self.assertIn("E14A2.DECISION.DUPLICATE", self.codes(result))

    def test_permit_requires_material_evidence(self):
        registry = authorization_registry()
        registry["decisions"][0]["evidence"] = []
        result = self.check(registry)
        self.assertIn("E14A2.DECISION.MATERIAL_EVIDENCE", self.codes(result))

    def test_projection_audience_binding_mismatch_rejected(self):
        upstream = upstream_registry()
        upstream["projections"][0]["authorized_audience"]["revision"] = "audience-r2"
        result = self.check(upstream=upstream)
        self.assertIn("E14A2.REQUEST.PROJECTION_BINDING", self.codes(result))

    def test_context_operation_mismatch_derives_deny(self):
        registry = authorization_registry()
        registry["evaluation_contexts"][0]["operation"] = "different-operation"
        self.set_decision(registry, "deny", "admissible", "eligible", "permit", "inadmissible", ["context-report"])
        result = self.check(registry)
        self.assertEqual("conformant", result["authorization_result"])

    def test_contested_policy_is_held(self):
        registry = authorization_registry()
        registry["disclosure_policies"][0]["state"] = "contested"
        self.set_decision(registry, "held", "admissible", "eligible", "held", "admissible")
        result = self.check(registry)
        self.assertEqual("conformant", result["authorization_result"])


if __name__ == "__main__":
    unittest.main()
