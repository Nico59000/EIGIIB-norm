from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import eigiib_m0_a11_check as CHECK  # noqa: E402
import eigiib_m0_a11_observe as OBS  # noqa: E402


class M0A11Tests(unittest.TestCase):
    def _copy_authority(self):
        holder = tempfile.TemporaryDirectory()
        target = Path(holder.name)
        for rel in ["conformance", "docs", "schemas", "tests/fixtures/m0-a11", "tools", ".github/workflows"]:
            src = ROOT / rel
            if src.exists():
                shutil.copytree(src, target / rel)
        return holder, target

    @staticmethod
    def _json(path: Path):
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _write(path: Path, value):
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def _evaluate(self, target: Path):
        return CHECK.evaluate_authority(target)

    def test_positive_preparatory_authority(self):
        report = self._evaluate(ROOT)
        expected = self._json(ROOT / "tests/fixtures/m0-a11/expected-report.json")
        self.assertEqual(expected, report, report["findings"])

    def test_m0_a10_head_substitution_is_rejected(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.AUTHORITY_PATH; doc = self._json(path)
        doc["source"]["m0A10Head"] = "0" * 40; self._write(path, doc)
        self.assertIn("M0A11.SOURCE.M0A10_HEAD", self._evaluate(target)["findings"])

    def test_premature_e17_adoption_is_rejected(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.AUTHORITY_PATH; doc = self._json(path)
        doc["entryGates"]["e17"]["decision"] = "adopted"; self._write(path, doc)
        self.assertIn("M0A11.E17.PREMATURE_ADOPTION", self._evaluate(target)["findings"])

    def test_external_placeholder_binding_is_rejected(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.REGISTRY_PATH; doc = self._json(path)
        doc["domains"][1]["bindingState"] = "bound"; doc["domains"][1]["providerBinding"] = "example-provider"
        self._write(path, doc)
        self.assertTrue(any(x.startswith("M0A11.REGISTRY.PREMATURE_BINDING") for x in self._evaluate(target)["findings"]))

    def test_unknown_control_dimension_cannot_be_claimed_independent(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.REGISTRY_PATH; doc = self._json(path)
        doc["independenceRules"]["unknownDimension"] = "independent"; self._write(path, doc)
        self.assertIn("M0A11.REGISTRY.RULE:unknownDimension", self._evaluate(target)["findings"])

    def test_same_execution_plane_rule_cannot_be_relaxed(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.REGISTRY_PATH; doc = self._json(path)
        doc["independenceRules"]["sameExecutionPlane"] = "independent"; self._write(path, doc)
        self.assertIn("M0A11.REGISTRY.RULE:sameExecutionPlane", self._evaluate(target)["findings"])

    def test_channel_cannot_claim_provisioned(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.CHANNEL_PATH; doc = self._json(path)
        doc["channels"][0]["lifecycleState"] = "provisioned"; self._write(path, doc)
        self.assertTrue(any(x.startswith("M0A11.CHANNEL.PREMATURE_STATE") for x in self._evaluate(target)["findings"]))

    def test_retention_intent_cannot_claim_applied_lock(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.CHANNEL_PATH; doc = self._json(path)
        doc["channels"][0]["retention"]["policyState"] = "locked"; self._write(path, doc)
        self.assertTrue(any(x.startswith("M0A11.CHANNEL.PREMATURE_RETENTION") for x in self._evaluate(target)["findings"]))

    def test_observer_role_separation_is_required(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.REGISTRY_PATH; doc = self._json(path)
        doc["domains"][3]["prohibitedRoles"] = []; self._write(path, doc)
        self.assertIn("M0A11.REGISTRY.OBSERVER_ROLE_SEPARATION", self._evaluate(target)["findings"])

    def test_campaign_cannot_activate_without_evidence(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.CAMPAIGN_PATH; doc = self._json(path)
        doc["activationState"] = "active"; doc["activatedAt"] = "2026-08-04T00:00:00Z"; self._write(path, doc)
        self.assertIn("M0A11.CAMPAIGN.PREMATURE_ACTIVATION", self._evaluate(target)["findings"])

    def test_lapse_threshold_inversion_is_rejected(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.CAMPAIGN_PATH; doc = self._json(path)
        doc["schedule"]["lapseAfterSeconds"] = 1; self._write(path, doc)
        findings = self._evaluate(target)["findings"]
        self.assertTrue("M0A11.CAMPAIGN.SCHEDULE" in findings or "M0A11.CAMPAIGN.LAPSE_THRESHOLDS" in findings)

    def _active_plan(self):
        plan = self._json(ROOT / CHECK.CAMPAIGN_PATH)
        plan["activationState"] = "active"; plan["activatedAt"] = "2026-08-04T00:00:00Z"
        return plan

    def _observation(self, plan, sequence, observed_at, previous):
        obs = {
            "standard": OBS.OBS_STANDARD,
            "campaignId": plan["campaignId"],
            "sequence": sequence,
            "observedAt": observed_at,
            "previousObservationDigest": previous,
            "observerDomainId": plan["observerDomainId"],
            "observerKeyId": "test-observer-key",
            "channels": [
                {"channelId": "immutable-channel-primary", "result": "exact-readback", "artifactSha256": CHECK.BUNDLE_SHA256},
                {"channelId": "immutable-channel-secondary", "result": "exact-readback", "artifactSha256": CHECK.BUNDLE_SHA256},
            ],
        }
        obs["observationDigest"] = OBS.observation_digest(obs)
        return obs

    def test_lapse_state_machine_current_grace_overdue_lapsed(self):
        plan = self._active_plan(); first = self._observation(plan, 1, "2026-08-04T00:00:00Z", None)
        ledger = {"campaignId": plan["campaignId"], "observations": [first]}
        self.assertEqual("current", OBS.evaluate(plan, ledger, OBS.parse_time("2026-08-04T12:00:00Z"))["state"])
        self.assertEqual("grace", OBS.evaluate(plan, ledger, OBS.parse_time("2026-08-05T03:00:00Z"))["state"])
        self.assertEqual("overdue", OBS.evaluate(plan, ledger, OBS.parse_time("2026-08-06T00:00:00Z"))["state"])
        self.assertEqual("lapsed", OBS.evaluate(plan, ledger, OBS.parse_time("2026-08-08T00:00:01Z"))["state"])

    def test_observation_sequence_gap_is_rejected(self):
        plan = self._active_plan(); first = self._observation(plan, 2, "2026-08-04T00:00:00Z", None)
        report = OBS.evaluate(plan, {"campaignId": plan["campaignId"], "observations": [first]}, OBS.parse_time("2026-08-04T01:00:00Z"))
        self.assertEqual("invalid", report["state"]); self.assertIn("M0A11.OBS.SEQUENCE:1", report["findings"])

    def test_observation_digest_chain_mismatch_is_rejected(self):
        plan = self._active_plan(); first = self._observation(plan, 1, "2026-08-04T00:00:00Z", None)
        second = self._observation(plan, 2, "2026-08-05T00:00:00Z", "0" * 64)
        report = OBS.evaluate(plan, {"campaignId": plan["campaignId"], "observations": [first, second]}, OBS.parse_time("2026-08-05T01:00:00Z"))
        self.assertEqual("invalid", report["state"]); self.assertIn("M0A11.OBS.PREVIOUS_DIGEST:2", report["findings"])

    def test_freeze_digest_substitution_is_rejected(self):
        holder, target = self._copy_authority(); self.addCleanup(holder.cleanup)
        path = target / CHECK.FREEZE_PATH; doc = self._json(path)
        doc["authorities"][0]["sha256"] = "f" * 64; self._write(path, doc)
        self.assertTrue(any(x.startswith("M0A11.FREEZE.SHA256") for x in self._evaluate(target)["findings"]))


if __name__ == "__main__":
    unittest.main()
