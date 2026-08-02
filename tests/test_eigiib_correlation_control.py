from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

TOOL = Path(__file__).parents[1] / "tools" / "eigiib_correlation_control_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_a3", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
Checker = MODULE.Checker

A1_STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0+E14-1.0"
H64 = "a" * 64
P64 = "b" * 64


def record(ident="rec-1"):
    return {
        "id": ident,
        "revision": "r1",
        "subject": "subject:1",
        "classification": "confidential",
        "revocation_state": "active",
        "commitment": {"algorithm": "sha256", "digest": H64},
    }


def projection(ident="proj-1", audience="aud-1", purpose="audit", controls=None, domain_context="ctx-1"):
    return {
        "id": ident,
        "revision": "p1",
        "source_record": "rec-1",
        "source_revision": "r1",
        "source_commitment": H64,
        "state": "sealed",
        "commitment": {"algorithm": "sha256", "digest": P64 if ident == "proj-1" else "c" * 64},
        "authorized_audience": {"id": audience, "revision": "a1"},
        "disclosure_policy": {"id": "pol-1", "revision": "pol1"},
        "evaluation_context": {"id": domain_context, "revision": "c1"},
        "correlation_controls": controls or ["audience-bound", "single-use"],
        "claims": [],
    }


def audience(ident="aud-1"):
    return {"id": ident, "revision": "a1"}


def auth_request(ident="req-1", proj="proj-1", aud="aud-1", purpose="audit", operation="op-1"):
    digest = P64 if proj == "proj-1" else "c" * 64
    return {
        "id": ident,
        "revision": "ar1",
        "projection": proj,
        "projection_revision": "p1",
        "projection_commitment": digest,
        "source_record": "rec-1",
        "source_revision": "r1",
        "source_commitment": H64,
        "audience": aud,
        "audience_revision": "a1",
        "policy": "pol-1",
        "policy_revision": "pol1",
        "context": "ctx-1",
        "context_revision": "c1",
        "purpose": purpose,
        "action": "eigiib:e14:disclose-projection",
        "operation": operation,
    }


def auth_decision(ident="dec-1", request_id="req-1", state="permit"):
    return {
        "id": ident,
        "request": request_id,
        "request_revision": "ar1",
        "state": state,
        "projection_result": "admissible",
        "audience_result": "eligible",
        "policy_result": "permit",
        "context_result": "admissible",
        "evaluator": "test",
        "reasons": ["test"],
        "evidence": ["test:evidence"],
    }


def profile(mode="isolated", max_projection=1, max_source=2, shared=None, cross_aud=False, cross_purpose=False):
    return {
        "id": "prof-1",
        "revision": "cp1",
        "state": "active",
        "required_controls": ["audience-bound", "single-use"],
        "linkability_mode": mode,
        "max_uses_per_projection": max_projection,
        "max_uses_per_source_record": max_source,
        "require_distinct_operation_nonce": True,
        "allow_cross_audience_linkage": cross_aud,
        "allow_cross_purpose_linkage": cross_purpose,
        "allowed_shared_domains": shared or [],
    }


def budget(ident="bud-1", aud="aud-1", purpose="audit", domain="dom-1", max_uses=1):
    return {
        "id": ident,
        "revision": "b1",
        "state": "active",
        "profile": "prof-1",
        "profile_revision": "cp1",
        "source_record": "rec-1",
        "source_revision": "r1",
        "source_commitment": H64,
        "audience": aud,
        "audience_revision": "a1",
        "purpose": purpose,
        "linkability_domain": domain,
        "max_uses": max_uses,
    }


def enforcement_request(ident="er-1", decision="dec-1", auth="req-1", proj="proj-1", aud="aud-1", purpose="audit", operation="op-1", bud="bud-1", domain="dom-1", nonce="nonce-1"):
    digest = P64 if proj == "proj-1" else "c" * 64
    return {
        "id": ident,
        "revision": "er1",
        "authorization_decision": decision,
        "authorization_request": auth,
        "authorization_request_revision": "ar1",
        "projection": proj,
        "projection_revision": "p1",
        "projection_commitment": digest,
        "source_record": "rec-1",
        "source_revision": "r1",
        "source_commitment": H64,
        "audience": aud,
        "audience_revision": "a1",
        "purpose": purpose,
        "operation": operation,
        "control_profile": "prof-1",
        "control_profile_revision": "cp1",
        "budget": bud,
        "budget_revision": "b1",
        "linkability_domain": domain,
        "operation_nonce": nonce,
    }


def consumption(ident="con-1", request="er-1", state="committed", sequence=1, reasons=None):
    return {
        "id": ident,
        "revision": "c1",
        "enforcement_request": request,
        "enforcement_request_revision": "er1",
        "state": state,
        "sequence": sequence,
        "reasons": reasons or ["authorized-and-within-budget"],
        "evidence": [f"event:{ident}"],
    }


class CorrelationControlTests(unittest.TestCase):
    def base(self):
        a1 = {
            "standard": A1_STANDARD,
            "status": "structural-only",
            "records": [record()],
            "projections": [projection()],
        }
        a2 = {
            "standard": "EIGIIB-E14-A2-1.0",
            "status": "structural-only",
            "upstream_registry": "conformance/confidential-evidence.json",
            "audiences": [audience()],
            "disclosure_policies": [],
            "evaluation_contexts": [],
            "requests": [auth_request()],
            "decisions": [auth_decision()],
        }
        a3 = {
            "standard": "EIGIIB-E14-A3-1.0",
            "status": "structural-only",
            "upstream_projection_registry": "conformance/confidential-evidence.json",
            "upstream_authorization_registry": "conformance/disclosure-authorization.json",
            "control_profiles": [profile()],
            "budgets": [budget()],
            "enforcement_requests": [enforcement_request()],
            "consumptions": [consumption()],
        }
        return a1, a2, a3

    def run_case(self, a1, a2, a3):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (
                "conformance/confidential-evidence.json",
                "conformance/disclosure-authorization.json",
                "conformance/correlation-control.json",
                "conformance/E14-A3-MANUAL-REVIEW.md",
                "extensions/E14-A3-CORRELATION-CONTROL-SINGLE-USE-LINKABILITY-REPLAY.md",
                "docs/E14-A3-HUMAN-MASTERY-GUIDE.md",
            ):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / "conformance/confidential-evidence.json").write_text(json.dumps(a1), encoding="utf-8")
            (root / "conformance/disclosure-authorization.json").write_text(json.dumps(a2), encoding="utf-8")
            (root / "conformance/correlation-control.json").write_text(json.dumps(a3), encoding="utf-8")
            (root / "conformance/E14-A3-MANUAL-REVIEW.md").write_text("review", encoding="utf-8")
            (root / "extensions/E14-A3-CORRELATION-CONTROL-SINGLE-USE-LINKABILITY-REPLAY.md").write_text("contract", encoding="utf-8")
            (root / "docs/E14-A3-HUMAN-MASTERY-GUIDE.md").write_text("guide", encoding="utf-8")
            toml = '''extensions = ["E14-1.0"]
revision = "EIGIIB-E14-draft-1.0"
required_authorities = ["confidential_evidence", "disclosure_authorization", "e14_a3_contract", "correlation_control", "e14_a3_human_mastery"]
[authorities]
confidential_evidence = "conformance/confidential-evidence.json"
disclosure_authorization = "conformance/disclosure-authorization.json"
e14_a3_contract = "extensions/E14-A3-CORRELATION-CONTROL-SINGLE-USE-LINKABILITY-REPLAY.md"
correlation_control = "conformance/correlation-control.json"
e14_a3_human_mastery = "docs/E14-A3-HUMAN-MASTERY-GUIDE.md"
[[manual_gates]]
id = "e14-a3-correlation-control-boundary-review"
status = "complete"
authority = "e14_a3_contract"
attestation = "conformance/E14-A3-MANUAL-REVIEW.md"
'''
            (root / "EIGIIB.toml").write_text(toml, encoding="utf-8")
            return Checker(root).run()

    def assert_conformant(self, result):
        self.assertEqual(result["structural_result"], "conformant", result["findings"])

    def test_empty_registry_exact_report(self):
        a1, a2, a3 = self.base()
        a1["records"] = []; a1["projections"] = []
        a2["audiences"] = []; a2["requests"] = []; a2["decisions"] = []
        a3["control_profiles"] = []; a3["budgets"] = []; a3["enforcement_requests"] = []; a3["consumptions"] = []
        result = self.run_case(a1, a2, a3)
        expected = {
            "tool": "eigiib-correlation-control-check",
            "tool_version": "0.1.0",
            "standard": "EIGIIB-E14-A3-1.0",
            "structural_result": "conformant",
            "upstream_binding_result": "conformant",
            "correlation_control_result": "not-evaluated",
            "single_use_result": "not-evaluated",
            "cross_projection_linkability_result": "not-evaluated",
            "control_profile_count": 0,
            "budget_count": 0,
            "enforcement_request_count": 0,
            "consumption_count": 0,
            "consumption_counts": {"committed": 0, "held": 0, "rejected": 0, "unavailable": 0},
            "findings": [],
        }
        self.assertEqual(result, expected)

    def test_valid_committed_consumption(self):
        result = self.run_case(*self.base())
        self.assert_conformant(result)
        self.assertEqual(result["consumption_counts"]["committed"], 1)

    def test_authorization_deny_derives_rejected(self):
        a1, a2, a3 = self.base(); a2["decisions"][0]["state"] = "deny"
        a3["consumptions"][0] = consumption(state="rejected", reasons=["authorization-denied"])
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_authorization_held_derives_held(self):
        a1, a2, a3 = self.base(); a2["decisions"][0]["state"] = "held"
        a3["consumptions"][0] = consumption(state="held", reasons=["authorization-held"])
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_authorization_unavailable_derives_unavailable(self):
        a1, a2, a3 = self.base(); a2["decisions"][0]["state"] = "unavailable"
        a3["consumptions"][0] = consumption(state="unavailable", reasons=["authorization-unavailable"])
        self.assert_conformant(self.run_case(a1, a2, a3))

    def add_second_same_projection(self, a2, a3, nonce="nonce-2", state="committed", reasons=None):
        a2["requests"].append(auth_request("req-2", operation="op-2"))
        a2["decisions"].append(auth_decision("dec-2", "req-2"))
        a3["enforcement_requests"].append(enforcement_request("er-2", "dec-2", "req-2", operation="op-2", nonce=nonce))
        a3["consumptions"].append(consumption("con-2", "er-2", state, 2, reasons))

    def test_duplicate_nonce_is_rejected(self):
        a1, a2, a3 = self.base()
        a3["control_profiles"][0]["max_uses_per_projection"] = 3
        a3["control_profiles"][0]["max_uses_per_source_record"] = 3
        a3["budgets"][0]["max_uses"] = 3
        self.add_second_same_projection(a2, a3, nonce="nonce-1", state="rejected", reasons=["operation-nonce-replay"])
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_projection_budget_is_enforced(self):
        a1, a2, a3 = self.base()
        a3["budgets"][0]["max_uses"] = 2
        self.add_second_same_projection(a2, a3, state="rejected", reasons=["projection-budget-exhausted"])
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_source_record_budget_is_enforced(self):
        a1, a2, a3 = self.base()
        a1["projections"].append(projection("proj-2"))
        a3["control_profiles"][0]["max_uses_per_source_record"] = 1
        a3["budgets"].append(budget("bud-2", domain="dom-2", max_uses=1))
        a2["requests"].append(auth_request("req-2", "proj-2", operation="op-2"))
        a2["decisions"].append(auth_decision("dec-2", "req-2"))
        a3["enforcement_requests"].append(enforcement_request("er-2", "dec-2", "req-2", "proj-2", operation="op-2", bud="bud-2", domain="dom-2", nonce="nonce-2"))
        a3["consumptions"].append(consumption("con-2", "er-2", "rejected", 1, ["source-record-budget-exhausted"]))
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_explicit_budget_is_enforced(self):
        a1, a2, a3 = self.base()
        a3["control_profiles"][0]["max_uses_per_projection"] = 3
        a3["control_profiles"][0]["max_uses_per_source_record"] = 3
        self.add_second_same_projection(a2, a3, state="rejected", reasons=["budget-exhausted"])
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_isolated_domain_rejects_cross_projection_linkage(self):
        a1, a2, a3 = self.base()
        a1["projections"].append(projection("proj-2"))
        a3["control_profiles"][0]["max_uses_per_source_record"] = 3
        a3["budgets"][0]["max_uses"] = 2
        a2["requests"].append(auth_request("req-2", "proj-2", operation="op-2"))
        a2["decisions"].append(auth_decision("dec-2", "req-2"))
        a3["enforcement_requests"].append(enforcement_request("er-2", "dec-2", "req-2", "proj-2", operation="op-2", nonce="nonce-2"))
        a3["consumptions"].append(consumption("con-2", "er-2", "rejected", 2, ["linkability-domain-conflict"]))
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_pairwise_domain_rejects_cross_audience_linkage(self):
        a1, a2, a3 = self.base()
        a3["control_profiles"][0] = profile(mode="pairwise", max_projection=2, max_source=3)
        a1["projections"].append(projection("proj-2", audience="aud-2"))
        a2["audiences"].append(audience("aud-2"))
        a2["requests"].append(auth_request("req-2", "proj-2", "aud-2", operation="op-2"))
        a2["decisions"].append(auth_decision("dec-2", "req-2"))
        a3["budgets"].append(budget("bud-2", aud="aud-2", domain="dom-1", max_uses=1))
        a3["enforcement_requests"].append(enforcement_request("er-2", "dec-2", "req-2", "proj-2", "aud-2", operation="op-2", bud="bud-2", nonce="nonce-2"))
        a3["consumptions"].append(consumption("con-2", "er-2", "rejected", 1, ["linkability-domain-conflict"]))
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_declared_shared_domain_can_cross_audience_and_purpose(self):
        a1, a2, a3 = self.base()
        a3["control_profiles"][0] = profile(mode="declared-shared", max_projection=2, max_source=3, shared=["shared-1"], cross_aud=True, cross_purpose=True)
        a3["budgets"][0]["linkability_domain"] = "shared-1"
        a3["enforcement_requests"][0]["linkability_domain"] = "shared-1"
        a1["projections"].append(projection("proj-2", audience="aud-2", purpose="research"))
        a2["audiences"].append(audience("aud-2"))
        a2["requests"].append(auth_request("req-2", "proj-2", "aud-2", purpose="research", operation="op-2"))
        a2["decisions"].append(auth_decision("dec-2", "req-2"))
        a3["budgets"].append(budget("bud-2", aud="aud-2", purpose="research", domain="shared-1", max_uses=1))
        a3["enforcement_requests"].append(enforcement_request("er-2", "dec-2", "req-2", "proj-2", "aud-2", purpose="research", operation="op-2", bud="bud-2", domain="shared-1", nonce="nonce-2"))
        a3["consumptions"].append(consumption("con-2", "er-2", "committed", 1))
        self.assert_conformant(self.run_case(a1, a2, a3))

    def test_missing_required_control_invalidates_request(self):
        a1, a2, a3 = self.base()
        a3["control_profiles"][0]["required_controls"].append("pairwise-token")
        result = self.run_case(a1, a2, a3)
        self.assertEqual(result["structural_result"], "non-conformant")
        self.assertTrue(any(f["code"] == "E14A3.REQUEST.CONTROLS" for f in result["findings"]))

    def test_stale_authorization_request_revision_is_rejected(self):
        a1, a2, a3 = self.base(); a3["enforcement_requests"][0]["authorization_request_revision"] = "old"
        result = self.run_case(a1, a2, a3)
        self.assertEqual(result["structural_result"], "non-conformant")

    def test_sequence_gap_is_rejected(self):
        a1, a2, a3 = self.base(); a3["consumptions"][0]["sequence"] = 2
        result = self.run_case(a1, a2, a3)
        self.assertEqual(result["structural_result"], "non-conformant")
        self.assertTrue(any(f["code"] == "E14A3.CONSUMPTION.SEQUENCE_GAP" for f in result["findings"]))

    def test_duplicate_consumption_for_request_is_rejected(self):
        a1, a2, a3 = self.base()
        a3["consumptions"].append(consumption("con-2", "er-1", "rejected", 2, ["projection-budget-exhausted", "budget-exhausted"]))
        result = self.run_case(a1, a2, a3)
        self.assertEqual(result["structural_result"], "non-conformant")
        self.assertTrue(any(f["code"] == "E14A3.CONSUMPTION.DUPLICATE" for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
