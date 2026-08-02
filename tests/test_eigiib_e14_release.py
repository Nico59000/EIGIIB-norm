from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).parents[1] / "tools" / "eigiib_e14_release_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_a5", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
Checker = MODULE.Checker
H64, P64, D64 = "a" * 64, "b" * 64, "c" * 64


def seal(value):
    value = copy.deepcopy(value)
    value["commitment"] = {"algorithm": "sha256", "digest": "0" * 64}
    value["commitment"]["digest"] = Checker.canonical_digest(value)
    return value


def upstream():
    a1 = {
        "standard": MODULE.A1_STANDARD,
        "status": "structural-only",
        "records": [{"id": "rec-1", "revision": "r1", "commitment": {"algorithm": "sha256", "digest": H64}}],
        "projections": [{"id": "proj-1", "revision": "p1", "commitment": {"algorithm": "sha256", "digest": P64}}],
    }
    a2_request = {"id": "req-1", "revision": "ar1"}
    a2 = {
        "standard": "EIGIIB-E14-A2-1.0", "status": "structural-only",
        "requests": [a2_request], "decisions": [{"id": "dec-1", "request": "req-1", "state": "permit"}],
    }
    a3_request = {"id": "er-1", "revision": "er1"}
    a3 = {
        "standard": "EIGIIB-E14-A3-1.0", "status": "structural-only",
        "enforcement_requests": [a3_request], "consumptions": [{"id": "con-1", "revision": "c1", "state": "committed"}],
    }
    distribution = {
        "id": "dist-1", "revision": "d1", "commitment": {"algorithm": "sha256", "digest": D64},
        "audience": "aud-1", "purpose": "audit", "endpoint": "channel:1",
    }
    attempt = {
        "id": "att-1", "revision": "at1", "source_record": "rec-1", "source_revision": "r1", "source_commitment": H64,
        "projection": "proj-1", "projection_revision": "p1", "projection_commitment": P64,
        "authorization_request": "req-1", "authorization_request_revision": "ar1", "authorization_decision": "dec-1",
        "enforcement_request": "er-1", "enforcement_request_revision": "er1",
        "correlation_consumption": "con-1", "correlation_consumption_revision": "c1",
        "distribution": "dist-1", "distribution_revision": "d1", "distribution_commitment": D64,
    }
    a4 = {
        "standard": "EIGIIB-E14-A4-1.0", "status": "structural-only",
        "distribution_channels": [distribution], "disclosure_attempts": [attempt],
        "decisions": [{"id": "rd-1", "attempt": "att-1", "state": "admissible"}],
    }
    return a1, a2, a3, a4


def policy():
    return {
        "id": "rel-pol-1", "revision": "rp1", "state": "active",
        "allowed_audiences": ["aud-1"], "allowed_purposes": ["audit"], "allowed_endpoints": ["channel:1"],
        "required_transport_properties": ["encrypted", "endpoint-bound"], "max_payload_bytes": 4096,
        "require_recipient_authentication": True,
    }


def request(identifier="rr-1", nonce="nonce-1"):
    return {
        "id": identifier, "revision": "rr1", "action": MODULE.RELEASE_ACTION,
        "revocation_decision": "rd-1", "revocation_attempt": "att-1", "revocation_attempt_revision": "at1",
        "source_record": "rec-1", "source_revision": "r1", "source_commitment": H64,
        "projection": "proj-1", "projection_revision": "p1", "projection_commitment": P64,
        "authorization_request": "req-1", "authorization_request_revision": "ar1", "authorization_decision": "dec-1",
        "correlation_enforcement_request": "er-1", "correlation_enforcement_revision": "er1",
        "correlation_consumption": "con-1", "correlation_consumption_revision": "c1",
        "distribution": "dist-1", "distribution_revision": "d1", "distribution_commitment": D64,
        "audience": "aud-1", "audience_revision": "a1", "purpose": "audit", "endpoint": "channel:1",
        "policy": "rel-pol-1", "policy_revision": "rp1", "payload_bytes": 1024, "payload_sha256": P64,
        "release_nonce": nonce, "recipient_authentication_state": "authenticated",
        "recipient_authentication_evidence": ["recipient-proof:1"], "transport_state": "protected",
        "transport_properties": ["encrypted", "endpoint-bound"], "transport_security_evidence": ["transport-proof:1"],
    }


def receipt(event_id="re-1", request_id="rr-1", nonce="nonce-1"):
    return seal({
        "id": f"receipt-{event_id}", "revision": "rc1", "event": event_id, "request": request_id,
        "request_revision": "rr1", "release_nonce": nonce, "projection_commitment": P64,
        "distribution_commitment": D64, "audience": "aud-1", "endpoint": "channel:1",
        "payload_sha256": P64, "transport_session": f"session:{event_id}",
    })


def event(identifier="re-1", request_id="rr-1", sequence=1, state="released", receipt_id="receipt-re-1", **results):
    base = {
        "id": identifier, "request": request_id, "request_revision": "rr1", "sequence": sequence,
        "state": state, "upstream_result": "admissible", "policy_result": "permit",
        "recipient_result": "authenticated", "transport_result": "protected", "replay_result": "current",
        "evaluator": "test", "reasons": ["test"], "evidence": ["event-proof:1"] if state in {"released", "rejected"} else [],
        "receipt": receipt_id,
    }
    base.update(results)
    return base


def registry():
    return {
        "standard": MODULE.STANDARD, "status": "structural-only",
        "upstream_projection_registry": "conformance/confidential-evidence.json",
        "upstream_authorization_registry": "conformance/disclosure-authorization.json",
        "upstream_correlation_registry": "conformance/correlation-control.json",
        "upstream_revocation_registry": "conformance/disclosure-revocation.json",
        "release_policies": [policy()], "release_requests": [request()],
        "release_events": [event()], "release_receipts": [receipt()],
    }


class ReleaseTests(unittest.TestCase):
    def run_case(self, a1, a2, a3, a4, release, mutate_freeze=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jsons = {
                "conformance/confidential-evidence.json": a1,
                "conformance/disclosure-authorization.json": a2,
                "conformance/correlation-control.json": a3,
                "conformance/disclosure-revocation.json": a4,
                "conformance/e14-release-boundary.json": release,
                "conformance/e14-a5-verifier-matrix.json": {"standard": MODULE.STANDARD, "cases": []},
            }
            for rel, value in jsons.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(json.dumps(value), encoding="utf-8")
            required_files = {
                "extensions/E14-A5-INDEPENDENT-VERIFIER-MATRIX-RELEASE-BOUNDARY-FINAL-AUTHORITY-FREEZE.md": "contract\n",
                "docs/E14-A5-HUMAN-MASTERY-GUIDE.md": "guide\n",
                "docs/E14-FINAL-CLOSURE-REPORT.md": "report\n",
                "conformance/E14-A5-MANUAL-REVIEW.md": "review\n",
            }
            for rel, text in required_files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text, encoding="utf-8")
            toml = '''extensions=["E14-1.0"]
revision="EIGIIB-E14-1.0"
required_authorities=["confidential_evidence","disclosure_authorization","correlation_control","disclosure_revocation","e14_a5_contract","e14_release_boundary","e14_a5_verifier_matrix","e14_a5_authority_freeze","e14_a5_human_mastery","e14_final_closure_report"]
[authorities]
confidential_evidence="conformance/confidential-evidence.json"
disclosure_authorization="conformance/disclosure-authorization.json"
correlation_control="conformance/correlation-control.json"
disclosure_revocation="conformance/disclosure-revocation.json"
e14_a5_contract="extensions/E14-A5-INDEPENDENT-VERIFIER-MATRIX-RELEASE-BOUNDARY-FINAL-AUTHORITY-FREEZE.md"
e14_release_boundary="conformance/e14-release-boundary.json"
e14_a5_verifier_matrix="conformance/e14-a5-verifier-matrix.json"
e14_a5_authority_freeze="conformance/e14-a5-authority-freeze.json"
e14_a5_human_mastery="docs/E14-A5-HUMAN-MASTERY-GUIDE.md"
e14_final_closure_report="docs/E14-FINAL-CLOSURE-REPORT.md"
[[manual_gates]]
id="e14-a5-final-closure-boundary-review"
status="complete"
authority="e14_a5_contract"
attestation="conformance/E14-A5-MANUAL-REVIEW.md"
'''
            (root / "EIGIIB.toml").write_text(toml, encoding="utf-8")
            frozen_paths = {
                "EIGIIB.toml",
                "conformance/e14-release-boundary.json",
                "conformance/e14-a5-verifier-matrix.json",
                "extensions/E14-A5-INDEPENDENT-VERIFIER-MATRIX-RELEASE-BOUNDARY-FINAL-AUTHORITY-FREEZE.md",
                "docs/E14-A5-HUMAN-MASTERY-GUIDE.md",
                "docs/E14-FINAL-CLOSURE-REPORT.md",
                "conformance/E14-A5-MANUAL-REVIEW.md",
            }
            original = MODULE.EXPECTED_FREEZE_PATHS
            MODULE.EXPECTED_FREEZE_PATHS = frozen_paths
            entries = []
            for rel in sorted(frozen_paths):
                data = (root / rel).read_bytes()
                entries.append({"path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            freeze = {"standard": MODULE.STANDARD, "status": "frozen", "source_head": MODULE.A4_SOURCE_HEAD, "profile_revision": MODULE.PROFILE_REVISION, "authorities": entries}
            if mutate_freeze:
                mutate_freeze(freeze)
            (root / "conformance/e14-a5-authority-freeze.json").write_text(json.dumps(freeze), encoding="utf-8")
            try:
                return Checker(root).run()
            finally:
                MODULE.EXPECTED_FREEZE_PATHS = original

    def base(self):
        return (*upstream(), registry())

    def conformant(self, report):
        self.assertEqual(report["structural_result"], "conformant", report["findings"])

    def test_empty_registry_exact_report(self):
        a1, a2, a3, a4, release = self.base()
        a1["records"] = []; a1["projections"] = []
        a2["requests"] = []; a2["decisions"] = []
        a3["enforcement_requests"] = []; a3["consumptions"] = []
        a4["distribution_channels"] = []; a4["disclosure_attempts"] = []; a4["decisions"] = []
        for key in ("release_policies", "release_requests", "release_events", "release_receipts"):
            release[key] = []
        report = self.run_case(a1, a2, a3, a4, release)
        expected = {
            "tool": "eigiib-e14-release-check", "tool_version": "0.1.0", "standard": MODULE.STANDARD,
            "structural_result": "conformant", "upstream_binding_result": "conformant",
            "release_boundary_result": "not-evaluated", "authority_freeze_result": "conformant",
            "release_policy_count": 0, "release_request_count": 0, "release_event_count": 0, "release_receipt_count": 0,
            "release_event_counts": {"held": 0, "rejected": 0, "released": 0, "unavailable": 0}, "findings": [],
        }
        self.assertEqual(report, expected)

    def test_valid_released_event(self):
        self.conformant(self.run_case(*self.base()))

    def test_a4_rejection_dominates_unavailable_transport(self):
        a1, a2, a3, a4, release = self.base()
        a4["decisions"][0]["state"] = "rejected"
        release["release_requests"][0]["transport_state"] = "unavailable"
        release["release_events"][0] = event(state="rejected", receipt_id=None, upstream_result="rejected", transport_result="unavailable")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_policy_scope_denial(self):
        a1, a2, a3, a4, release = self.base()
        release["release_policies"][0]["allowed_endpoints"] = ["other"]
        release["release_events"][0] = event(state="rejected", receipt_id=None, policy_result="deny")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_recipient_contested_is_held(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"][0]["recipient_authentication_state"] = "contested"
        release["release_events"][0] = event(state="held", receipt_id=None, recipient_result="held")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_transport_unavailable(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"][0]["transport_state"] = "unavailable"
        release["release_events"][0] = event(state="unavailable", receipt_id=None, transport_result="unavailable")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_duplicate_released_nonce_is_rejected(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"].append(request("rr-2", "nonce-1"))
        release["release_events"].append(event("re-2", "rr-2", 2, "rejected", None, replay_result="replay-detected"))
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_stale_a4_attempt_revision_rejected_structurally(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"][0]["revocation_attempt_revision"] = "old"
        report = self.run_case(a1, a2, a3, a4, release)
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_receipt_commitment_tamper(self):
        a1, a2, a3, a4, release = self.base()
        release["release_receipts"][0]["transport_session"] = "tampered"
        report = self.run_case(a1, a2, a3, a4, release)
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_orphan_receipt_rejected(self):
        a1, a2, a3, a4, release = self.base()
        release["release_receipts"].append(receipt("orphan", "rr-1", "nonce-2"))
        report = self.run_case(a1, a2, a3, a4, release)
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_missing_recipient_evidence_is_rejected(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"][0]["recipient_authentication_evidence"] = []
        release["release_events"][0] = event(state="rejected", receipt_id=None, recipient_result="unauthenticated")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_missing_transport_evidence_is_rejected(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"][0]["transport_security_evidence"] = []
        release["release_events"][0] = event(state="rejected", receipt_id=None, transport_result="unprotected")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_missing_required_transport_property_denies_policy(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"][0]["transport_properties"] = ["encrypted"]
        release["release_events"][0] = event(state="rejected", receipt_id=None, policy_result="deny")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_payload_limit_denies_policy(self):
        a1, a2, a3, a4, release = self.base()
        release["release_requests"][0]["payload_bytes"] = 5000
        release["release_events"][0] = event(state="rejected", receipt_id=None, policy_result="deny")
        release["release_receipts"] = []
        self.conformant(self.run_case(a1, a2, a3, a4, release))

    def test_nonreleased_event_forbids_receipt(self):
        a1, a2, a3, a4, release = self.base()
        release["release_policies"][0]["state"] = "contested"
        release["release_events"][0] = event(state="held", policy_result="held")
        report = self.run_case(a1, a2, a3, a4, release)
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_event_sequence_gap_is_rejected(self):
        a1, a2, a3, a4, release = self.base()
        release["release_events"][0]["sequence"] = 2
        report = self.run_case(a1, a2, a3, a4, release)
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_duplicate_event_for_request_is_rejected(self):
        a1, a2, a3, a4, release = self.base()
        release["release_events"].append(event("re-2", "rr-1", 2, "rejected", None, replay_result="replay-detected"))
        report = self.run_case(a1, a2, a3, a4, release)
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_freeze_digest_tamper(self):
        report = self.run_case(*self.base(), mutate_freeze=lambda freeze: freeze["authorities"][0].update(sha256="0" * 64))
        self.assertEqual(report["authority_freeze_result"], "non-conformant")


if __name__ == "__main__":
    unittest.main()
