import base64
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(TESTS_DIR))

try:
    from m0_a15_f2_cases import build_activation_package
    from eigiib_m0_a15_f2_check import evaluate, validate_package_schema
    from eigiib_m0_a15_f2_replay import verify_activation_package
except ModuleNotFoundError as exc:
    if exc.name not in {"cryptography", "jsonschema", "referencing"}:
        raise
    raise unittest.SkipTest(
        f"M0-A15-F2 verification provider not installed: {exc.name}"
    ) from exc


class M0A15F2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package, cls.evaluation_at, cls.f1_report = build_activation_package(ROOT)

    def replay(self, package=None, at=None, f1_report=None):
        with patch(
            "eigiib_m0_a15_f2_replay._load_f1_report",
            return_value=f1_report or self.f1_report,
        ):
            return verify_activation_package(
                package or deepcopy(self.package),
                ROOT,
                self.evaluation_at if at is None else at,
            )

    def test_canonical_baseline_is_nf(self):
        expected = json.loads((ROOT / "tests/fixtures/m0-a15-f2/expected-baseline-report.json").read_text())
        self.assertEqual(evaluate(ROOT), expected)

    def test_exact_positive_activation_route_reaches_t(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "activation-package.json"
            path.write_text(json.dumps(self.package), encoding="utf-8")
            report = evaluate(ROOT, path, self.evaluation_at)
        self.assertEqual(report["htntLabel"], "T", report["findings"])
        self.assertEqual(report["summary"]["exactA14Replay"], "verified")

    def test_evaluation_time_is_required(self):
        result = self.replay(at="")
        self.assertIn("evaluation-time-required-and-invalid", result["errors"])

    def test_history_digest_mutation_rejected(self):
        case = deepcopy(self.package)
        case["historyDigest"] = "0" * 64
        self.assertIn("history-digest-mismatch", self.replay(case)["errors"])

    def test_carrier_must_be_external_https(self):
        case = deepcopy(self.package)
        case["carrier"]["locator"] = "https://example.invalid/history.json"
        self.assertIn("carrier-locator-not-external-https", self.replay(case)["errors"])

    def test_ingress_signature_mutation_rejected(self):
        case = deepcopy(self.package)
        case["ingressReceipt"]["signature"]["value"] = base64.b64encode(b"0" * 64).decode()
        self.assertIn("ingress-receipt-signature-invalid", self.replay(case)["errors"])

    def test_observer_control_domain_overlap_rejected(self):
        case = deepcopy(self.package)
        case["observers"][1]["controlDomainId"] = case["observers"][0]["controlDomainId"]
        self.assertIn("observer-independence-controlDomainId-overlap", self.replay(case)["errors"])

    def test_ingress_readback_quorum_required(self):
        case = deepcopy(self.package)
        case["ingressReadbacks"] = case["ingressReadbacks"][:1]
        self.assertIn("independent-ingress-readback-quorum-not-met", self.replay(case)["errors"])

    def test_activation_authority_signature_required(self):
        case = deepcopy(self.package)
        case["activation"]["envelope"]["signature"]["value"] = base64.b64encode(b"0" * 64).decode()
        self.assertIn("activation-signature-invalid", self.replay(case)["errors"])

    def test_activation_witness_quorum_required(self):
        case = deepcopy(self.package)
        case["activation"]["witnessEndorsements"] = case["activation"]["witnessEndorsements"][:2]
        self.assertIn("activation-witness-quorum-not-met", self.replay(case)["errors"])

    def test_activation_window_is_bounded(self):
        case = deepcopy(self.package)
        case["activation"]["envelope"]["payload"]["validUntil"] = "2026-04-02T02:00:00Z"
        self.assertIn("activation-validity-window-exceeded", self.replay(case)["errors"])

    def test_evaluation_outside_window_rejected(self):
        result = self.replay(at="2026-04-02T02:00:00Z")
        self.assertIn("evaluation-time-outside-activation-window", result["errors"])

    def test_activation_readback_quorum_required(self):
        case = deepcopy(self.package)
        case["activation"]["readbacks"] = case["activation"]["readbacks"][:1]
        self.assertIn("independent-activation-readback-quorum-not-met", self.replay(case)["errors"])

    def test_exact_f1_t_is_required(self):
        invalid_report = deepcopy(self.f1_report)
        invalid_report["htntLabel"] = "NT"
        invalid_report["findings"] = ["synthetic-f1-failure"]
        result = self.replay(f1_report=invalid_report)
        self.assertIn("f1-exact-replay-not-t", result["errors"])
        self.assertIn("f1:synthetic-f1-failure", result["errors"])

    def test_activation_nonce_is_exact_hex(self):
        case = deepcopy(self.package)
        case["activation"]["envelope"]["payload"]["activationNonce"] = "not-a-nonce"
        self.assertIn("activation-nonce-invalid", self.replay(case)["errors"])

    def test_source_f1_binding_is_exact(self):
        case = deepcopy(self.package)
        case["source"]["f1Head"] = "0" * 40
        self.assertIn("source-f1-binding-mismatch", self.replay(case)["errors"])

    def test_schema_rejects_unknown_top_level_property(self):
        case = deepcopy(self.package)
        case["unexpected"] = True
        errors = validate_package_schema(ROOT, case)
        self.assertTrue(any(error.endswith("additionalProperties") for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
