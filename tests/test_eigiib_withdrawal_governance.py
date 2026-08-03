from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools/eigiib_withdrawal_governance_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_withdrawal_governance_check", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def committed(value: dict) -> dict:
    value = dict(value)
    value["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(value)}
    return value


class E15A4Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_root = Path(__file__).resolve().parents[1]
        for rel in CHECK.EXPECTED_FREEZE_PATHS:
            source = self.source_root / rel
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_file():
                shutil.copyfile(source, target)
            else:
                target.write_text(f"fixture:{rel}\n", encoding="utf-8")
        profile_path = self.root / "EIGIIB.toml"
        profile = profile_path.read_text(encoding="utf-8")
        profile = profile.replace('revision = "EIGIIB-E15-1.0"', 'revision = "EIGIIB-E15-draft-1.3"')
        profile_path.write_text(profile, encoding="utf-8")
        parent = json.loads((self.root / "conformance/publication-readback.json").read_text(encoding="utf-8"))
        for field in (
            "publisher_profiles", "readback_observer_profiles", "publication_policies",
            "external_publication_records", "bounded_persistence_observations",
            "independent_readbacks", "publication_lifecycle_decisions",
        ):
            parent[field] = []
        (self.root / "conformance/publication-readback.json").write_text(json.dumps(parent), encoding="utf-8")
        registry = json.loads((self.root / "conformance/withdrawal-governance.json").read_text(encoding="utf-8"))
        for field in (
            "withdrawal_authority_profiles", "distribution_operator_profiles",
            "distribution_target_profiles", "withdrawal_policies", "withdrawal_requests",
            "registry_tombstones", "distribution_stop_records",
            "post_withdrawal_observations", "withdrawal_lifecycle_decisions",
        ):
            registry[field] = []
        (self.root / "conformance/withdrawal-governance.json").write_text(json.dumps(registry), encoding="utf-8")
        self.history_path = self.root / "history.json"
        self.history_path.write_text(json.dumps({
            "tool": "eigiib-historical-e15-a3-replay", "tool_version": "0.1.0",
            "standard": CHECK.HISTORY_STANDARD, "source_commit": CHECK.SOURCE_E15_A3_HEAD,
            "materialization": "git-archive-isolated-tree", "ancestry_result": "conformant",
            "historical_e14_result": "conformant", "e15_a1_result": "conformant",
            "e15_a2_result": "conformant", "e15_a3_result": "conformant",
            "e15_a3_tests_result": "conformant", "overall_result": "conformant",
            "findings": [],
        }), encoding="utf-8")
        self.refresh_freeze()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def refresh_freeze(self) -> None:
        entries = []
        for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS):
            raw = (self.root / rel).read_bytes()
            entries.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        freeze = {
            "standard": CHECK.FREEZE_STANDARD,
            "status": "frozen",
            "source": {"e15_a3_head_commit": CHECK.SOURCE_E15_A3_HEAD},
            "profile_revision": CHECK.PROFILE_REVISION,
            "authorities": entries,
        }
        path = self.root / "conformance/e15-a4-authority-freeze.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(freeze), encoding="utf-8")

    def checker(self) -> CHECK.Checker:
        return CHECK.Checker(self.root, history_report=Path("history.json"))

    def test_empty_registry_is_conformant(self) -> None:
        report = self.checker().run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["withdrawal_governance_result"], "not-evaluated")

    def test_nonconformant_parent_history_is_rejected(self) -> None:
        data = json.loads(self.history_path.read_text())
        data["e15_a3_result"] = "non-conformant"
        data["overall_result"] = "non-conformant"
        self.history_path.write_text(json.dumps(data))
        self.assertEqual(self.checker().run()["historical_continuity_result"], "non-conformant")

    def test_parent_source_substitution_is_rejected(self) -> None:
        path = self.root / "conformance/e15-a4-adoption-transition.json"
        data = json.loads(path.read_text())
        data["source"]["head_commit"] = "0" * 40
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_frozen_authority_mutation_is_rejected(self) -> None:
        (self.root / "docs/E15-A4-HUMAN-MASTERY-GUIDE.md").write_text("changed\n")
        self.assertEqual(self.checker().run()["authority_freeze_result"], "non-conformant")

    def test_descendant_a3_test_profile_isolation_is_required(self) -> None:
        path = self.root / "conformance/e15-a4-adoption-transition.json"
        data = json.loads(path.read_text())
        data["historical_preservation"]["descendant_a3_test_profile_isolated"] = False
        path.write_text(json.dumps(data))
        self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def install_base(
        self,
        *,
        tombstone_requirement: str = "required",
        required_observations: int = 1,
        effective_at: str = "2026-08-03T00:05:00Z",
        request_state: str = "positive",
        request_event: str = "requested",
    ) -> dict:
        digest = "a" * 64
        parent_path = self.root / "conformance/publication-readback.json"
        parent = json.loads(parent_path.read_text())
        observer = committed({
            "id": "observer-1", "revision": "1", "kind": "independent-observer",
            "identity_authority": "trust-root-observer", "identity_state": "verified",
            "principal_id": "principal-observer", "provider_id": "provider-observer",
            "implementation_id": "impl-observer", "authentication_algorithms": ["ed25519"],
        })
        publication = committed({
            "id": "publication-1", "revision": "1", "payload_sha256": digest,
            "payload_bytes": 10, "locator": "fixture://registry/object-1",
        })
        parent_decision = committed({
            "id": "publication-decision-1", "publication": "publication-1",
            "publication_revision": "1", "lifecycle_state": "independently-read-back",
        })
        parent["readback_observer_profiles"] = [observer]
        parent["external_publication_records"] = [publication]
        parent["publication_lifecycle_decisions"] = [parent_decision]
        parent_path.write_text(json.dumps(parent))

        authority = committed({
            "id": "authority-1", "revision": "1", "kind": "governance-authority",
            "identity_authority": "trust-root-authority", "identity_state": "verified",
            "principal_id": "principal-authority", "provider_id": "provider-authority",
            "implementation_id": "impl-authority", "actions": [CHECK.WITHDRAWAL_ACTION],
            "authentication_algorithms": ["ed25519"],
        })
        operator = committed({
            "id": "operator-1", "revision": "1", "kind": "distribution-operator",
            "identity_authority": "trust-root-operator", "identity_state": "verified",
            "principal_id": "principal-operator", "provider_id": "provider-operator",
            "implementation_id": "impl-operator",
            "managed_targets": ["target-registry", "target-release"],
            "stop_mechanisms": ["registry-tombstone", "distribution-block", "release-unpublish"],
            "authentication_algorithms": ["ed25519"],
        })
        target_registry = committed({
            "id": "target-registry", "revision": "1", "kind": "registry",
            "locator": "fixture://registry/object-1", "locator_kind": "registry-reference",
            "tombstone_capable": True,
            "stop_mechanisms": ["registry-tombstone", "distribution-block"],
        })
        target_release = committed({
            "id": "target-release", "revision": "1", "kind": "release-service",
            "locator": "fixture://release/asset-1", "locator_kind": "release-asset",
            "tombstone_capable": False, "stop_mechanisms": ["release-unpublish"],
        })
        policy = committed({
            "id": "policy-1", "revision": "1", "state": "active",
            "allowed_authorities": ["authority-1"], "allowed_operators": ["operator-1"],
            "allowed_observers": ["observer-1"],
            "registered_targets": ["target-registry", "target-release"],
            "tombstone_targets": ["target-registry"],
            "stop_targets": ["target-registry", "target-release"],
            "tombstone_requirement": tombstone_requirement,
            "stop_coverage": "all-registered-stop-targets",
            "minimum_withdrawal_sequence": 1,
            "max_request_age_seconds": 7200,
            "max_tombstone_age_seconds": 7200,
            "max_stop_age_seconds": 7200,
            "max_post_observation_age_seconds": 7200,
            "required_post_withdrawal_observations_per_target": required_observations,
            "min_post_observation_interval_seconds": 0,
            "required_authentication_algorithms": ["ed25519"],
        })
        request = committed({
            "id": "request-1", "revision": "1",
            "source_publication": "publication-1", "source_publication_revision": "1",
            "source_publication_commitment_sha256": publication["commitment"]["digest"],
            "source_a3_decision": "publication-decision-1",
            "source_a3_decision_commitment_sha256": parent_decision["commitment"]["digest"],
            "authority": "authority-1", "authority_revision": "1",
            "policy": "policy-1", "policy_revision": "1",
            "withdrawal_sequence": 1, "withdrawal_idempotency_key": "withdrawal-key-1",
            "scope_targets": ["target-registry", "target-release"],
            "payload_sha256": digest, "payload_bytes": 10,
            "requested_at": "2026-08-03T00:00:00Z", "effective_at": effective_at,
            "valid_until": "2026-08-03T02:00:00Z",
            "request_state": request_state, "observed_event": request_event,
            "authentication": {"algorithm": "ed25519", "key_id": "authority-key", "signature_sha256": "b" * 64},
            "source_reference": "fixture://authority/request-1",
        })
        reg_path = self.root / "conformance/withdrawal-governance.json"
        reg = json.loads(reg_path.read_text())
        reg.update({
            "withdrawal_authority_profiles": [authority],
            "distribution_operator_profiles": [operator],
            "distribution_target_profiles": [target_registry, target_release],
            "withdrawal_policies": [policy], "withdrawal_requests": [request],
            "registry_tombstones": [], "distribution_stop_records": [],
            "post_withdrawal_observations": [], "withdrawal_lifecycle_decisions": [],
        })
        reg_path.write_text(json.dumps(reg))
        return reg

    def tombstone(
        self,
        *,
        identifier: str = "tombstone-1",
        generation: int = 1,
        state: str = "positive",
        event: str = "installed",
        predecessor: dict | None = None,
        payload: str = "a" * 64,
    ) -> dict:
        return committed({
            "id": identifier, "revision": "1", "withdrawal_request": "request-1",
            "request_revision": "1", "target": "target-registry", "target_revision": "1",
            "operator": "operator-1", "operator_revision": "1", "generation": generation,
            "predecessor_id": predecessor["id"] if predecessor else None,
            "predecessor_commitment_sha256": predecessor["commitment"]["digest"] if predecessor else None,
            "stop_mechanism": "registry-tombstone", "tombstone_state": state,
            "observed_event": event, "observed_at": f"2026-08-03T00:{9 + generation:02d}:00Z",
            "valid_until": "2026-08-03T02:00:00Z", "locator": "fixture://registry/object-1",
            "payload_sha256": payload,
            "authentication": {"algorithm": "ed25519", "key_id": "operator-key", "signature_sha256": "c" * 64},
            "source_reference": f"fixture://operator/{identifier}",
        })

    def stop(
        self,
        target: str,
        *,
        identifier: str | None = None,
        sequence: int = 1,
        state: str = "positive",
        event: str = "stopped",
        predecessor: dict | None = None,
        payload: str = "a" * 64,
    ) -> dict:
        identifier = identifier or f"stop-{target}-{sequence}"
        locator = "fixture://registry/object-1" if target == "target-registry" else "fixture://release/asset-1"
        mechanism = "distribution-block" if target == "target-registry" else "release-unpublish"
        return committed({
            "id": identifier, "revision": "1", "withdrawal_request": "request-1",
            "request_revision": "1", "target": target, "target_revision": "1",
            "operator": "operator-1", "operator_revision": "1", "stop_sequence": sequence,
            "predecessor_id": predecessor["id"] if predecessor else None,
            "predecessor_commitment_sha256": predecessor["commitment"]["digest"] if predecessor else None,
            "stop_mechanism": mechanism, "stop_state": state, "observed_event": event,
            "observed_at": f"2026-08-03T00:{10 + sequence:02d}:00Z",
            "valid_until": "2026-08-03T02:00:00Z", "locator": locator,
            "payload_sha256": payload,
            "authentication": {"algorithm": "ed25519", "key_id": "operator-key", "signature_sha256": "d" * 64},
            "source_reference": f"fixture://operator/{identifier}",
        })

    def observation(
        self,
        target: str,
        *,
        identifier: str | None = None,
        state: str = "positive",
        event: str | None = None,
        at: str = "2026-08-03T00:20:00Z",
        payload: str = "a" * 64,
    ) -> dict:
        identifier = identifier or f"observation-{target}"
        locator = "fixture://registry/object-1" if target == "target-registry" else "fixture://release/asset-1"
        if event is None:
            event = "tombstone-visible" if target == "target-registry" else "not-found"
        return committed({
            "id": identifier, "revision": "1", "withdrawal_request": "request-1",
            "request_revision": "1", "target": target, "target_revision": "1",
            "observer": "observer-1", "observer_revision": "1",
            "observation_state": state, "observed_event": event, "observed_at": at,
            "valid_until": "2026-08-03T02:00:00Z", "locator": locator,
            "payload_sha256": payload, "process_id": f"process-{identifier}",
            "network_path_id": f"path-{identifier}",
            "authentication": {"algorithm": "ed25519", "key_id": "observer-key", "signature_sha256": "e" * 64},
            "source_reference": f"fixture://observer/{identifier}",
        })

    def decision(
        self,
        tombstones: list[str],
        stops: list[str],
        observations: list[str],
        *,
        binding: str = "permit", authority: str = "permit", operator: str = "permit",
        observer: str = "permit", policy: str = "permit", freshness: str = "permit",
        request: str = "permit", tombstone: str = "permit", stop: str = "permit",
        post: str = "permit", anti_rollback: str = "permit", content: str = "permit",
        lifecycle: str = "post-withdrawal-observed", evaluated_at: str = "2026-08-03T00:30:00Z",
    ) -> dict:
        return committed({
            "id": "decision-1", "withdrawal_request": "request-1", "request_revision": "1",
            "sequence": 1, "registry_tombstones": tombstones, "distribution_stops": stops,
            "post_withdrawal_observations": observations,
            "binding_result": binding, "authority_result": authority, "operator_result": operator,
            "observer_result": observer, "policy_result": policy, "freshness_result": freshness,
            "request_result": request, "tombstone_result": tombstone,
            "distribution_stop_result": stop, "post_withdrawal_observation_result": post,
            "anti_rollback_result": anti_rollback, "content_identity_result": content,
            "lifecycle_state": lifecycle, "evaluated_at": evaluated_at,
            "reasons": ["typed-withdrawal-evaluation"], "evidence_refs": ["repository-fixture"],
        })

    def write_case(self, tombstones: list[dict], stops: list[dict], observations: list[dict], decision: dict) -> dict:
        path = self.root / "conformance/withdrawal-governance.json"
        current = json.loads(path.read_text())
        current["registry_tombstones"] = tombstones
        current["distribution_stop_records"] = stops
        current["post_withdrawal_observations"] = observations
        current["withdrawal_lifecycle_decisions"] = [decision]
        path.write_text(json.dumps(current))
        self.refresh_freeze()
        return self.checker().run()

    def full_evidence(self) -> tuple[list[dict], list[dict], list[dict]]:
        tombstones = [self.tombstone()]
        stops = [self.stop("target-registry"), self.stop("target-release")]
        observations = [self.observation("target-registry"), self.observation("target-release")]
        return tombstones, stops, observations

    def test_positive_withdrawal_tombstone_stops_and_post_observations(self) -> None:
        self.install_base()
        tombstones, stops, observations = self.full_evidence()
        report = self.write_case(tombstones, stops, observations, self.decision([tombstones[0]["id"]], [s["id"] for s in stops], [o["id"] for o in observations]))
        self.assertEqual(report["lifecycle_state_counts"]["post-withdrawal-observed"], 1)

    def test_missing_tombstone_remains_withdrawal_requested(self) -> None:
        self.install_base()
        report = self.write_case([], [], [], self.decision([], [], [], tombstone="held", stop="held", post="held", anti_rollback="held", lifecycle="withdrawal-requested"))
        self.assertEqual(report["lifecycle_state_counts"]["withdrawal-requested"], 1)

    def test_tombstone_without_stops_remains_tombstoned(self) -> None:
        self.install_base()
        tomb = self.tombstone()
        report = self.write_case([tomb], [], [], self.decision([tomb["id"]], [], [], stop="held", post="held", anti_rollback="held", lifecycle="tombstoned"))
        self.assertEqual(report["lifecycle_state_counts"]["tombstoned"], 1)

    def test_complete_stops_without_observations_remains_distribution_stopped(self) -> None:
        self.install_base()
        tomb = self.tombstone(); stops = [self.stop("target-registry"), self.stop("target-release")]
        report = self.write_case([tomb], stops, [], self.decision([tomb["id"]], [s["id"] for s in stops], [], post="held", lifecycle="distribution-stopped"))
        self.assertEqual(report["lifecycle_state_counts"]["distribution-stopped"], 1)

    def test_still_available_observation_is_rejected(self) -> None:
        self.install_base()
        tombstones, stops, observations = self.full_evidence()
        observations[1] = self.observation("target-release", state="negative", event="still-available")
        report = self.write_case(tombstones, stops, observations, self.decision([tombstones[0]["id"]], [s["id"] for s in stops], [o["id"] for o in observations], post="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_stale_tombstone_head_is_rejected(self) -> None:
        self.install_base()
        first = self.tombstone(); second = self.tombstone(identifier="tombstone-2", generation=2, state="negative", event="removed", predecessor=first)
        stops = [self.stop("target-registry"), self.stop("target-release")]
        observations = [self.observation("target-registry"), self.observation("target-release")]
        report = self.write_case([first, second], stops, observations, self.decision([first["id"]], [s["id"] for s in stops], [o["id"] for o in observations], anti_rollback="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_latest_removed_tombstone_is_rejected(self) -> None:
        self.install_base()
        first = self.tombstone(); second = self.tombstone(identifier="tombstone-2", generation=2, state="negative", event="removed", predecessor=first)
        stops = [self.stop("target-registry"), self.stop("target-release")]
        observations = [self.observation("target-registry"), self.observation("target-release")]
        report = self.write_case([first, second], stops, observations, self.decision([second["id"]], [s["id"] for s in stops], [o["id"] for o in observations], tombstone="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_stale_stop_head_is_rejected(self) -> None:
        self.install_base()
        tomb = self.tombstone(); first = self.stop("target-release"); second = self.stop("target-release", identifier="stop-release-2", sequence=2, state="negative", event="resumed", predecessor=first)
        other = self.stop("target-registry")
        observations = [self.observation("target-registry"), self.observation("target-release")]
        report = self.write_case([tomb], [other, first, second], observations, self.decision([tomb["id"]], [other["id"], first["id"]], [o["id"] for o in observations], anti_rollback="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_content_digest_mismatch_is_rejected(self) -> None:
        self.install_base()
        tombstones, stops, observations = self.full_evidence()
        observations[1] = self.observation("target-release", payload="f" * 64, state="negative", event="digest-mismatch")
        report = self.write_case(tombstones, stops, observations, self.decision([tombstones[0]["id"]], [s["id"] for s in stops], [o["id"] for o in observations], post="deny", content="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_unauthorized_authority_is_rejected(self) -> None:
        self.install_base()
        path = self.root / "conformance/withdrawal-governance.json"; reg = json.loads(path.read_text())
        policy = reg["withdrawal_policies"][0]; policy["allowed_authorities"] = ["other-authority"]
        reg["withdrawal_policies"][0] = committed({k: v for k, v in policy.items() if k != "commitment"}); path.write_text(json.dumps(reg))
        tombstones, stops, observations = self.full_evidence()
        report = self.write_case(tombstones, stops, observations, self.decision([tombstones[0]["id"]], [s["id"] for s in stops], [o["id"] for o in observations], binding="deny", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_operator_target_substitution_is_nonconformant(self) -> None:
        self.install_base()
        path = self.root / "conformance/withdrawal-governance.json"; reg = json.loads(path.read_text())
        operator = reg["distribution_operator_profiles"][0]; operator["managed_targets"] = ["target-registry"]
        reg["distribution_operator_profiles"][0] = committed({k: v for k, v in operator.items() if k != "commitment"}); path.write_text(json.dumps(reg))
        tombstones, stops, observations = self.full_evidence()
        report = self.write_case(tombstones, stops, observations, self.decision([tombstones[0]["id"]], [s["id"] for s in stops], [o["id"] for o in observations], binding="deny", lifecycle="rejected"))
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_pre_effective_evaluation_is_held(self) -> None:
        self.install_base(tombstone_requirement="optional", required_observations=0, effective_at="2026-08-03T01:00:00Z")
        report = self.write_case([], [], [], self.decision([], [], [], freshness="held", stop="held", anti_rollback="held", lifecycle="held", evaluated_at="2026-08-03T00:30:00Z"))
        self.assertEqual(report["lifecycle_state_counts"]["held"], 1)

    def test_duplicate_request_idempotency_key_is_nonconformant(self) -> None:
        self.install_base()
        path = self.root / "conformance/withdrawal-governance.json"; reg = json.loads(path.read_text())
        second = {k: v for k, v in reg["withdrawal_requests"][0].items() if k != "commitment"}
        second["id"] = "request-2"; second["withdrawal_sequence"] = 2
        reg["withdrawal_requests"].append(committed(second)); path.write_text(json.dumps(reg)); self.refresh_freeze()
        self.assertEqual(self.checker().run()["structural_result"], "non-conformant")

    def test_orphan_tombstone_is_rejected(self) -> None:
        self.install_base()
        tomb = self.tombstone()
        report = self.write_case([tomb], [], [], self.decision([], [], [], tombstone="held", stop="held", post="held", anti_rollback="deny", lifecycle="rejected"))
        self.assertEqual(report["structural_result"], "non-conformant")

    def test_contested_post_observation_is_contested(self) -> None:
        self.install_base()
        tombstones, stops, observations = self.full_evidence()
        observations[1] = self.observation("target-release", state="contested", event="unknown")
        report = self.write_case(tombstones, stops, observations, self.decision([tombstones[0]["id"]], [s["id"] for s in stops], [o["id"] for o in observations], post="held", lifecycle="contested"))
        self.assertEqual(report["lifecycle_state_counts"]["contested"], 1)

    def test_unavailable_post_observation_is_unavailable(self) -> None:
        self.install_base()
        tombstones, stops, observations = self.full_evidence()
        observations[1] = self.observation("target-release", state="unavailable", event="unreachable")
        report = self.write_case(tombstones, stops, observations, self.decision([tombstones[0]["id"]], [s["id"] for s in stops], [o["id"] for o in observations], post="unavailable", lifecycle="unavailable"))
        self.assertEqual(report["lifecycle_state_counts"]["unavailable"], 1)

    def test_cancelled_request_is_rejected(self) -> None:
        self.install_base(request_state="negative", request_event="cancelled")
        report = self.write_case([], [], [], self.decision([], [], [], request="deny", tombstone="held", stop="held", post="held", anti_rollback="held", lifecycle="rejected"))
        self.assertEqual(report["lifecycle_state_counts"]["rejected"], 1)

    def test_partial_stop_coverage_remains_tombstoned(self) -> None:
        self.install_base()
        tomb = self.tombstone(); stop = self.stop("target-registry")
        report = self.write_case([tomb], [stop], [], self.decision([tomb["id"]], [stop["id"]], [], stop="held", post="held", anti_rollback="held", lifecycle="tombstoned"))
        self.assertEqual(report["lifecycle_state_counts"]["tombstoned"], 1)


if __name__ == "__main__":
    unittest.main()
