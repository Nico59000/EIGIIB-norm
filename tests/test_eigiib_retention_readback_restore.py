from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "e16a3check",
    SOURCE / "tools/eigiib_retention_readback_restore_check.py",
)
CHECK = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CHECK
spec.loader.exec_module(CHECK)


def committed(value):
    value = copy.deepcopy(value)
    value["commitment"] = {
        "algorithm": "sha256",
        "digest": CHECK.commitment_for(value),
    }
    return value


class RetentionReadbackRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        needed = CHECK.EXPECTED_FREEZE_PATHS | {
            "conformance/e16-a3-authority-freeze.json",
            "conformance/e16-a2-authority-freeze.json",
            "conformance/replica-placement.json",
        }
        for rel in needed:
            source = SOURCE / rel
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file():
                shutil.copyfile(source, target)
            else:
                target.write_text("fixture\n", encoding="utf-8")
        self.history = self.root / "history.json"
        self.history.write_text(
            json.dumps(
                {
                    "standard": CHECK.HISTORY_STANDARD,
                    "source_commit": CHECK.SOURCE_E16_A2_HEAD,
                    "overall_result": "conformant",
                    "e16_a1_history_result": "conformant",
                    "e16_a2_result": "conformant",
                    "e16_a2_tests_result": "conformant",
                }
            ),
            encoding="utf-8",
        )
        self.refresh_freeze()

    def tearDown(self):
        self.temp.cleanup()

    def refresh_freeze(self):
        entries = []
        for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS):
            raw = (self.root / rel).read_bytes()
            entries.append(
                {
                    "path": rel,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        (self.root / "conformance/e16-a3-authority-freeze.json").write_text(
            json.dumps(
                {
                    "standard": CHECK.FREEZE_STANDARD,
                    "status": "frozen",
                    "profile_revision": CHECK.PROFILE_REVISION,
                    "source_e16_a2_commit": CHECK.SOURCE_E16_A2_HEAD,
                    "authorities": entries,
                }
            ),
            encoding="utf-8",
        )

    def checker(self):
        return CHECK.Checker(
            self.root,
            history_report=Path("history.json"),
        )

    def test_empty_registry(self):
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["verification_result"], "not-evaluated")

    def test_history_failure(self):
        data = json.loads(self.history.read_text())
        data["overall_result"] = "non-conformant"
        self.history.write_text(json.dumps(data))
        self.assertEqual(
            self.checker().run()["historical_continuity_result"],
            "non-conformant",
        )

    def test_source_substitution(self):
        path = self.root / "conformance/e16-a3-adoption-transition.json"
        data = json.loads(path.read_text())
        data["source"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertTrue(
            any(
                finding["code"] == "E16A3.TRANSITION.SOURCE"
                for finding in report["findings"]
            )
        )

    def test_manifest_authority_substitution(self):
        path = self.root / "conformance/e16-a3-authority-manifest.json"
        data = json.loads(path.read_text())
        data["authorities"]["registry"] = "conformance/other.json"
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertTrue(
            any(
                finding["code"] == "E16A3.MANIFEST.AUTHORITIES"
                for finding in report["findings"]
            )
        )

    def test_freeze_mutation(self):
        (
            self.root / "docs/E16-A3-HUMAN-MASTERY-GUIDE.md"
        ).write_text("changed\n")
        self.assertEqual(
            self.checker().run()["authority_freeze_result"],
            "non-conformant",
        )

    def install_positive(self):
        digest = "a" * 64
        request = committed(
            {
                "id": "pr-1",
                "revision": "1",
                "content_sha256": digest,
                "content_bytes": 10,
            }
        )
        placement_observation = committed(
            {
                "id": "po-1",
                "revision": "1",
                "observation_state": "positive",
            }
        )
        placement_decision = committed(
            {
                "id": "pd-1",
                "revision": "1",
                "request": "pr-1",
                "request_revision": "1",
                "observation": "po-1",
                "observation_revision": "1",
                "state": "placement-observed",
            }
        )
        upstream_path = self.root / "conformance/replica-placement.json"
        upstream = json.loads(upstream_path.read_text())
        upstream.update(
            {
                "placement_requests": [request],
                "placement_observations": [placement_observation],
                "placement_decisions": [placement_decision],
            }
        )
        upstream_path.write_text(json.dumps(upstream))

        window = committed(
            {
                "id": "rw-1",
                "revision": "1",
                "source_placement_decision": "pd-1",
                "source_placement_decision_revision": "1",
                "source_placement_decision_commitment": placement_decision[
                    "commitment"
                ]["digest"],
                "source_request": "pr-1",
                "source_request_revision": "1",
                "content_sha256": digest,
                "content_bytes": 10,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-02-01T00:00:00Z",
                "clock_basis": {
                    "id": "clock-1",
                    "revision": "1",
                    "basis_type": "declared-utc",
                },
                "opening_observation_required": True,
                "closing_observation_required": True,
                "idempotency_key": "retain-1",
            }
        )
        opening = committed(
            {
                "id": "obs-open",
                "revision": "1",
                "retention_window": "rw-1",
                "retention_window_revision": "1",
                "retention_window_commitment": window["commitment"]["digest"],
                "placement_observation": "po-1",
                "placement_observation_revision": "1",
                "placement_observation_commitment": placement_observation[
                    "commitment"
                ]["digest"],
                "boundary_role": "opening",
                "observed_at": "2026-01-01T00:00:00Z",
                "observer": {
                    "id": "observer-open",
                    "revision": "1",
                    "control_domain": "observer-domain",
                },
                "method": {
                    "kind": "bounded-read",
                    "implementation": "fixture",
                },
                "observed_content_sha256": digest,
                "observed_content_bytes": 10,
                "observation_state": "positive",
                "evidence_refs": ["opening-evidence"],
            }
        )
        closing = committed(
            {
                "id": "obs-close",
                "revision": "1",
                "retention_window": "rw-1",
                "retention_window_revision": "1",
                "retention_window_commitment": window["commitment"]["digest"],
                "placement_observation": "po-1",
                "placement_observation_revision": "1",
                "placement_observation_commitment": placement_observation[
                    "commitment"
                ]["digest"],
                "boundary_role": "closing",
                "observed_at": "2026-02-01T00:00:00Z",
                "observer": {
                    "id": "observer-close",
                    "revision": "1",
                    "control_domain": "observer-domain",
                },
                "method": {
                    "kind": "bounded-read",
                    "implementation": "fixture",
                },
                "observed_content_sha256": digest,
                "observed_content_bytes": 10,
                "observation_state": "positive",
                "evidence_refs": ["closing-evidence"],
            }
        )
        readback = committed(
            {
                "id": "rb-1",
                "revision": "1",
                "retention_window": "rw-1",
                "retention_window_revision": "1",
                "retention_window_commitment": window["commitment"]["digest"],
                "closing_observation": "obs-close",
                "closing_observation_revision": "1",
                "closing_observation_commitment": closing["commitment"][
                    "digest"
                ],
                "reader": {
                    "id": "reader-1",
                    "revision": "1",
                    "control_domain": "reader-domain",
                },
                "custodian": {
                    "id": "custodian-1",
                    "revision": "1",
                    "control_domain": "custodian-domain",
                },
                "method": {
                    "kind": "independent-readback",
                    "implementation": "fixture",
                },
                "returned_content_sha256": digest,
                "returned_content_bytes": 10,
                "readback_state": "positive",
                "evidence_refs": ["readback-evidence"],
            }
        )
        attempt = committed(
            {
                "id": "ra-1",
                "revision": "1",
                "retention_window": "rw-1",
                "retention_window_revision": "1",
                "retention_window_commitment": window["commitment"]["digest"],
                "independent_readback": "rb-1",
                "independent_readback_revision": "1",
                "independent_readback_commitment": readback["commitment"][
                    "digest"
                ],
                "executor": {
                    "id": "executor-1",
                    "revision": "1",
                    "control_domain": "executor-domain",
                },
                "target_environment": {
                    "id": "restore-target-1",
                    "revision": "1",
                    "ephemeral": True,
                },
                "method": {
                    "kind": "restore",
                    "implementation": "fixture",
                },
                "restored_content_sha256": digest,
                "restored_content_bytes": 10,
                "attempt_state": "completed",
                "evidence_refs": ["restore-evidence"],
            }
        )
        verification = committed(
            {
                "id": "rv-1",
                "revision": "1",
                "restore_attempt": "ra-1",
                "restore_attempt_revision": "1",
                "restore_attempt_commitment": attempt["commitment"]["digest"],
                "verifier": {
                    "id": "verifier-1",
                    "revision": "1",
                    "control_domain": "verifier-domain",
                },
                "executor": {
                    "id": "executor-1",
                    "revision": "1",
                    "control_domain": "executor-domain",
                },
                "method": {
                    "kind": "digest-and-byte-count",
                    "implementation": "fixture",
                },
                "verified_content_sha256": digest,
                "verified_content_bytes": 10,
                "verification_state": "positive",
                "evidence_refs": ["verification-evidence"],
            }
        )
        gates = {
            "a2_placement": "permit",
            "retention_window": "permit",
            "opening_observation": "permit",
            "closing_observation": "permit",
            "independent_readback": "permit",
            "restore_attempt": "permit",
            "restore_verification": "permit",
        }
        decision = committed(
            {
                "id": "pvd-1",
                "revision": "1",
                "retention_window": "rw-1",
                "retention_window_revision": "1",
                "retention_window_commitment": window["commitment"]["digest"],
                "opening_observation": "obs-open",
                "opening_observation_revision": "1",
                "opening_observation_commitment": opening["commitment"][
                    "digest"
                ],
                "closing_observation": "obs-close",
                "closing_observation_revision": "1",
                "closing_observation_commitment": closing["commitment"][
                    "digest"
                ],
                "independent_readback": "rb-1",
                "independent_readback_revision": "1",
                "independent_readback_commitment": readback["commitment"][
                    "digest"
                ],
                "restore_attempt": "ra-1",
                "restore_attempt_revision": "1",
                "restore_attempt_commitment": attempt["commitment"]["digest"],
                "restore_verification": "rv-1",
                "restore_verification_revision": "1",
                "restore_verification_commitment": verification["commitment"][
                    "digest"
                ],
                "gates": gates,
                "state": "bounded-preservation-and-restore-verified",
                "reasons": ["all-gates-positive"],
                "evidence_refs": [
                    "opening-evidence",
                    "closing-evidence",
                    "readback-evidence",
                    "restore-evidence",
                    "verification-evidence",
                ],
            }
        )
        registry_path = (
            self.root / "conformance/retention-readback-restore.json"
        )
        registry = json.loads(registry_path.read_text())
        registry.update(
            {
                "retention_windows": [window],
                "preservation_observations": [opening, closing],
                "independent_readbacks": [readback],
                "restore_attempts": [attempt],
                "restore_verifications": [verification],
                "preservation_verification_decisions": [decision],
            }
        )
        registry_path.write_text(json.dumps(registry))
        self.refresh_freeze()

    def test_positive_verification(self):
        self.install_positive()
        report = self.checker().run()
        self.assertEqual(report["verification_result"], "conformant")
        self.assertEqual(
            report["decision_state_counts"][
                "bounded-preservation-and-restore-verified"
            ],
            1,
        )
        self.assertEqual(report["findings"], [])

    def test_negative_closing_precedes_unavailable_readback(self):
        self.install_positive()
        path = self.root / "conformance/retention-readback-restore.json"
        data = json.loads(path.read_text())
        data["preservation_observations"][1]["observation_state"] = "negative"
        data["preservation_observations"][1] = committed(
            {
                key: value
                for key, value in data["preservation_observations"][1].items()
                if key != "commitment"
            }
        )
        data["independent_readbacks"][0]["readback_state"] = "unavailable"
        data["independent_readbacks"][0][
            "closing_observation_commitment"
        ] = data["preservation_observations"][1]["commitment"]["digest"]
        data["independent_readbacks"][0] = committed(
            {
                key: value
                for key, value in data["independent_readbacks"][0].items()
                if key != "commitment"
            }
        )
        data["restore_attempts"][0][
            "independent_readback_commitment"
        ] = data["independent_readbacks"][0]["commitment"]["digest"]
        data["restore_attempts"][0]["attempt_state"] = "unavailable"
        data["restore_attempts"][0] = committed(
            {
                key: value
                for key, value in data["restore_attempts"][0].items()
                if key != "commitment"
            }
        )
        data["restore_verifications"][0][
            "restore_attempt_commitment"
        ] = data["restore_attempts"][0]["commitment"]["digest"]
        data["restore_verifications"][0]["verification_state"] = "unavailable"
        data["restore_verifications"][0] = committed(
            {
                key: value
                for key, value in data["restore_verifications"][0].items()
                if key != "commitment"
            }
        )
        decision = data["preservation_verification_decisions"][0]
        decision["closing_observation_commitment"] = data[
            "preservation_observations"
        ][1]["commitment"]["digest"]
        decision["independent_readback_commitment"] = data[
            "independent_readbacks"
        ][0]["commitment"]["digest"]
        decision["restore_attempt_commitment"] = data["restore_attempts"][0][
            "commitment"
        ]["digest"]
        decision["restore_verification_commitment"] = data[
            "restore_verifications"
        ][0]["commitment"]["digest"]
        decision["gates"]["closing_observation"] = "deny"
        decision["gates"]["independent_readback"] = "unavailable"
        decision["gates"]["restore_attempt"] = "deny"
        decision["gates"]["restore_verification"] = "deny"
        decision["state"] = "rejected"
        data["preservation_verification_decisions"][0] = committed(
            {
                key: value
                for key, value in decision.items()
                if key != "commitment"
            }
        )
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        report = self.checker().run()
        self.assertEqual(report["decision_state_counts"]["rejected"], 1)
        self.assertFalse(
            any(
                finding["code"] == "E16A3.DECISION.STATE"
                for finding in report["findings"]
            )
        )

    def test_readback_role_substitution_rejected(self):
        self.install_positive()
        path = self.root / "conformance/retention-readback-restore.json"
        data = json.loads(path.read_text())
        data["independent_readbacks"][0]["reader"]["control_domain"] = (
            "custodian-domain"
        )
        data["independent_readbacks"][0] = committed(
            {
                key: value
                for key, value in data["independent_readbacks"][0].items()
                if key != "commitment"
            }
        )
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(
            self.checker().run()["structural_result"],
            "non-conformant",
        )

    def test_restore_digest_mismatch_rejected(self):
        self.install_positive()
        path = self.root / "conformance/retention-readback-restore.json"
        data = json.loads(path.read_text())
        data["restore_attempts"][0]["restored_content_bytes"] = 11
        data["restore_attempts"][0] = committed(
            {
                key: value
                for key, value in data["restore_attempts"][0].items()
                if key != "commitment"
            }
        )
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(
            self.checker().run()["structural_result"],
            "non-conformant",
        )

    def test_boundary_time_mismatch_rejected(self):
        self.install_positive()
        path = self.root / "conformance/retention-readback-restore.json"
        data = json.loads(path.read_text())
        data["preservation_observations"][0]["observed_at"] = (
            "2026-01-02T00:00:00Z"
        )
        data["preservation_observations"][0] = committed(
            {
                key: value
                for key, value in data["preservation_observations"][0].items()
                if key != "commitment"
            }
        )
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(
            self.checker().run()["structural_result"],
            "non-conformant",
        )

    def test_duplicate_idempotency_rejected(self):
        self.install_positive()
        path = self.root / "conformance/retention-readback-restore.json"
        data = json.loads(path.read_text())
        second = copy.deepcopy(data["retention_windows"][0])
        second["id"] = "rw-2"
        second = committed(
            {
                key: value
                for key, value in second.items()
                if key != "commitment"
            }
        )
        data["retention_windows"].append(second)
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(
            self.checker().run()["structural_result"],
            "non-conformant",
        )


if __name__ == "__main__":
    unittest.main()
