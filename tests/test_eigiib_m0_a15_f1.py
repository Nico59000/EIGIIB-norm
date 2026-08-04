import base64
import json
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from tests.m0_a15_f1_cases import (
    A15_HEAD, ROOT, CanonicalValueError, CaseBuilder, REGISTRY_IDS,
    canonical_bytes, digest_hex, evaluate, h, validate_evidence_schema,
    verify_case, verify_envelope,
)

class M0A15F1Tests(unittest.TestCase):
    def setUp(self):
        self.builder = CaseBuilder()
        self.case = self.builder.build()
        self.a14_result = {
            "verified": True,
            "sourceHead": "5936ed072187cd7fe72db2c33119c8db92d06570",
            "sourceTree": "8b77cadd56e5d51a08b94bbeee603d994ca7a5d2",
            "replayDigest": h(9000),
            "errors": [],
        }

    def replay(self, case=None):
        with patch("eigiib_m0_a15_f1_replay.verify_a14_replay", return_value=self.a14_result):
            return verify_case(case or self.case, ROOT)

    def test_positive_authenticated_history(self):
        result = self.replay()
        self.assertTrue(result["verified"], result["errors"])
        self.assertEqual(result["summary"]["splitBrainProofCount"], 1)

    def test_float_is_not_canonical(self):
        with self.assertRaises(CanonicalValueError):
            canonical_bytes({"value": 1.5})

    def test_signature_mutation_rejected(self):
        case = deepcopy(self.case)
        case["checkpoints"][0]["registryReceipts"][0]["signature"]["value"] = base64.b64encode(b"0" * 64).decode()
        self.assertTrue(any("signature-invalid" in error for error in self.replay(case)["errors"]))

    def test_key_id_mismatch_rejected(self):
        case = deepcopy(self.case)
        case["checkpoints"][0]["registryReceipts"][0]["signature"]["keyId"] = "wrong"
        self.assertTrue(any("key-id-mismatch" in error for error in self.replay(case)["errors"]))

    def test_receipt_chain_break_rejected(self):
        case = deepcopy(self.case)
        case["checkpoints"][1]["registryReceipts"][0]["payload"]["previousReceiptDigest"] = h(77)
        self.assertTrue(any("receipt-chain-broken" in error for error in self.replay(case)["errors"]))

    def test_fabricated_split_brain_proof_rejected(self):
        case = deepcopy(self.case)
        case["checkpoints"][2]["derivedSplitBrainProof"]["divergentRegistryIds"] = [REGISTRY_IDS[0]]
        self.assertIn("checkpoint-3-split-brain-proof-not-derived", self.replay(case)["errors"])

    def test_support_set_is_derived(self):
        case = deepcopy(self.case)
        case["checkpoints"][2]["reconciliationRecord"]["payload"]["supportingRegistryIds"] = [REGISTRY_IDS[0], REGISTRY_IDS[2]]
        self.assertIn("checkpoint-3-reconciliation-support-not-derived", self.replay(case)["errors"])

    def test_quarantine_set_is_derived(self):
        case = deepcopy(self.case)
        case["checkpoints"][2]["reconciliationRecord"]["payload"]["quarantinedRegistryIds"] = [REGISTRY_IDS[0]]
        self.assertIn("checkpoint-3-reconciliation-quarantine-not-derived", self.replay(case)["errors"])

    def test_common_ancestor_binding(self):
        case = deepcopy(self.case)
        case["checkpoints"][2]["reconciliationRecord"]["payload"]["commonAncestorCheckpointDigest"] = h(11)
        self.assertIn("checkpoint-3-reconciliation-common-ancestor-mismatch", self.replay(case)["errors"])

    def test_anti_rollback_required(self):
        case = deepcopy(self.case)
        case["checkpoints"][2]["reconciliationRecord"]["payload"]["staleViewsRejected"] = False
        self.assertIn("checkpoint-3-reconciliation-anti-rollback-invalid", self.replay(case)["errors"])

    def test_authoritative_readback_required(self):
        case = deepcopy(self.case)
        case["checkpoints"][2]["reconciliationRecord"]["readbacks"] = case["checkpoints"][2]["reconciliationRecord"]["readbacks"][1:]
        self.assertIn("checkpoint-3-authoritative-published-readback-missing", self.replay(case)["errors"])

    def test_quarantined_readback_required(self):
        case = deepcopy(self.case)
        case["checkpoints"][2]["reconciliationRecord"]["readbacks"] = case["checkpoints"][2]["reconciliationRecord"]["readbacks"][:1]
        self.assertIn("checkpoint-3-quarantined-registry-readback-missing", self.replay(case)["errors"])

    def test_witness_domain_bound_to_profile(self):
        case = deepcopy(self.case)
        case["checkpoints"][0]["witnessEndorsements"][0]["payload"]["controlDomainId"] = "invented-domain"
        self.assertTrue(any("control-domain-binding-mismatch" in error for error in self.replay(case)["errors"]))

    def test_witness_quorum_required_for_a14(self):
        case = deepcopy(self.case)
        case["a14Replay"]["witnessEndorsements"] = case["a14Replay"]["witnessEndorsements"][:3]
        self.assertIn("a14-replay-witness-quorum-not-met", self.replay(case)["errors"])

    def test_registry_independence_overlap_rejected(self):
        case = deepcopy(self.case)
        case["registries"][1]["providerOperator"] = case["registries"][0]["providerOperator"]
        self.assertIn("registry-independence-providerOperator-invalid", self.replay(case)["errors"])

    def test_observer_independence_overlap_rejected(self):
        case = deepcopy(self.case)
        case["readbackObservers"][1]["networkPath"] = case["readbackObservers"][0]["networkPath"]
        self.assertIn("observer-independence-networkPath-invalid", self.replay(case)["errors"])

    def test_minimum_span_required(self):
        case = deepcopy(self.case)
        case["checkpoints"][-1]["observedAt"] = "2026-02-15T00:00:00Z"
        self.assertIn("minimum-observed-span-not-met", self.replay(case)["errors"])

    def test_certificate_is_derived(self):
        case = deepcopy(self.case)
        case["longTermCertificate"]["payload"]["checkpointCount"] = 7
        self.assertIn("long-term-certificate-not-derived", self.replay(case)["errors"])

    def test_certificate_independent_readback_required(self):
        case = deepcopy(self.case)
        case["longTermCertificate"]["readbacks"] = case["longTermCertificate"]["readbacks"][:1]
        self.assertIn("long-term-certificate-independent-readback-missing", self.replay(case)["errors"])

    def test_governance_change_requires_reconciliation(self):
        case = deepcopy(self.case)
        for envelope in case["checkpoints"][4]["registryReceipts"]:
            envelope["payload"]["governanceSnapshotDigest"] = h(301)
        self.assertIn("checkpoint-5-governance-reconciliation-missing", self.replay(case)["errors"])

    def test_schema_rejects_additional_top_level_property(self):
        case = deepcopy(self.case)
        case["unexpected"] = True
        errors = validate_evidence_schema(ROOT, case)
        self.assertTrue(any(error.endswith("additionalProperties") for error in errors), errors)

    def test_crypto_verifier_accepts_valid_envelope(self):
        profile = self.case["registries"][0]
        envelope = self.case["checkpoints"][0]["registryReceipts"][0]
        digest, errors = verify_envelope(envelope, profile, "receipt")
        self.assertFalse(errors)
        self.assertEqual(digest, digest_hex(envelope["payload"]))

    def test_repository_baseline_when_exact_history_available(self):
        try:
            subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "-e", f"{A15_HEAD}^{{commit}}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception:
            self.skipTest("exact repository history not available in local isolated test workspace")
        report = evaluate(ROOT)
        expected = json.loads((ROOT / "tests/fixtures/m0-a15-f1/expected-baseline-report.json").read_text())
        self.assertEqual(report, expected)


if __name__ == "__main__":
    unittest.main()
