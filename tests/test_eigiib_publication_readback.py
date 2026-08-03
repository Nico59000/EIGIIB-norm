from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools/eigiib_publication_readback_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_publication_readback_check", MODULE_PATH)
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECK
SPEC.loader.exec_module(CHECK)


def committed(value: dict) -> dict:
    value = dict(value)
    value["commitment"] = {"algorithm": "sha256", "digest": CHECK.commitment_for(value)}
    return value


class E15A3Test(unittest.TestCase):
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
        parent = json.loads((self.root / "conformance/delivery-evidence.json").read_text(encoding="utf-8"))
        for field in ("attester_profiles", "external_attestation_policies", "transfer_attempts", "external_delivery_evidence", "recipient_acknowledgements", "delivery_evidence_decisions"):
            parent[field] = []
        (self.root / "conformance/delivery-evidence.json").write_text(json.dumps(parent), encoding="utf-8")
        registry = json.loads((self.root / "conformance/publication-readback.json").read_text(encoding="utf-8"))
        for field in ("publisher_profiles", "readback_observer_profiles", "publication_policies", "external_publication_records", "bounded_persistence_observations", "independent_readbacks", "publication_lifecycle_decisions"):
            registry[field] = []
        (self.root / "conformance/publication-readback.json").write_text(json.dumps(registry), encoding="utf-8")
        self.history_path = self.root / "history.json"
        self.history_path.write_text(json.dumps({
            "tool": "eigiib-historical-e15-a2-replay", "tool_version": "0.1.0",
            "standard": CHECK.HISTORY_STANDARD, "source_commit": CHECK.SOURCE_E15_A2_HEAD,
            "materialization": "git-archive-isolated-tree", "ancestry_result": "conformant",
            "historical_e14_result": "conformant", "e15_a1_result": "conformant",
            "e15_a2_result": "conformant", "e15_a2_tests_result": "conformant",
            "overall_result": "conformant", "findings": [],
        }), encoding="utf-8")
        self.refresh_freeze()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def refresh_freeze(self) -> None:
        entries=[]
        for rel in sorted(CHECK.EXPECTED_FREEZE_PATHS):
            raw=(self.root/rel).read_bytes()
            entries.append({"path":rel,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
        freeze={"standard":CHECK.FREEZE_STANDARD,"status":"frozen","source":{"e15_a2_head_commit":CHECK.SOURCE_E15_A2_HEAD},"profile_revision":CHECK.PROFILE_REVISION,"authorities":entries}
        path=self.root/"conformance/e15-a3-authority-freeze.json"; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(freeze),encoding="utf-8")

    def checker(self) -> CHECK.Checker:
        return CHECK.Checker(self.root, history_report=Path("history.json"))

    def test_empty_registry_is_conformant(self) -> None:
        report=self.checker().run(); self.assertEqual(report["structural_result"],"conformant"); self.assertEqual(report["publication_readback_result"],"not-evaluated")

    def test_nonconformant_parent_history_is_rejected(self) -> None:
        data=json.loads(self.history_path.read_text()); data["e15_a2_result"]="non-conformant"; data["overall_result"]="non-conformant"; self.history_path.write_text(json.dumps(data)); self.assertEqual(self.checker().run()["historical_continuity_result"],"non-conformant")

    def test_parent_source_substitution_is_rejected(self) -> None:
        path=self.root/"conformance/e15-a3-adoption-transition.json"; data=json.loads(path.read_text()); data["source"]["head_commit"]="0"*40; path.write_text(json.dumps(data)); self.refresh_freeze(); self.assertEqual(self.checker().run()["structural_result"],"non-conformant")

    def test_frozen_authority_mutation_is_rejected(self) -> None:
        (self.root/"docs/E15-A3-HUMAN-MASTERY-GUIDE.md").write_text("changed\n"); self.assertEqual(self.checker().run()["authority_freeze_result"],"non-conformant")

    def test_descendant_a2_test_profile_isolation_is_required(self) -> None:
        path=self.root/"conformance/e15-a3-adoption-transition.json"; data=json.loads(path.read_text()); data["historical_preservation"]["descendant_a2_test_profile_isolated"]=False; path.write_text(json.dumps(data)); self.refresh_freeze(); self.assertEqual(self.checker().run()["structural_result"],"non-conformant")

    def install_base(self, *, min_observations: int=2, interval: int=300, readback_requirement: str="required", dimensions: list[str]|None=None) -> dict:
        digest="a"*64
        parent_path=self.root/"conformance/delivery-evidence.json"; parent=json.loads(parent_path.read_text())
        attempt=committed({"id":"attempt-1","revision":"1","payload_sha256":digest,"payload_bytes":10})
        decision=committed({"id":"delivery-decision-1","attempt":"attempt-1","attempt_revision":"1","sequence":1,"lifecycle_state":"externally-attested"})
        parent["transfer_attempts"]=[attempt]; parent["delivery_evidence_decisions"]=[decision]; parent_path.write_text(json.dumps(parent))
        publisher=committed({"id":"publisher-1","revision":"1","kind":"object-store","identity_authority":"trust-root-1","identity_state":"verified","principal_id":"principal-pub","provider_id":"provider-pub","implementation_id":"impl-pub","locator_kinds":["object-key"],"publication_mechanisms":["object-put"],"authentication_algorithms":["ed25519"]})
        observer=committed({"id":"observer-1","revision":"1","kind":"independent-observer","identity_authority":"trust-root-2","identity_state":"verified","principal_id":"principal-obs","provider_id":"provider-obs","implementation_id":"impl-obs","authentication_algorithms":["ed25519"]})
        policy=committed({"id":"policy-1","revision":"1","state":"active","allowed_publishers":["publisher-1"],"allowed_observers":["observer-1"],"allowed_locator_kinds":["object-key"],"allowed_publication_mechanisms":["object-put"],"required_authentication_algorithms":["ed25519"],"max_publication_age_seconds":7200,"min_persistence_observations":min_observations,"min_observation_interval_seconds":interval,"max_observation_age_seconds":7200,"readback_requirement":readback_requirement,"required_independence_dimensions":dimensions or ["principal","provider","implementation","process","network-path"],"max_readback_age_seconds":7200})
        publication=committed({"id":"publication-1","revision":"1","source_attempt":"attempt-1","source_attempt_revision":"1","source_delivery_decision":"delivery-decision-1","source_delivery_decision_commitment_sha256":decision["commitment"]["digest"],"publisher":"publisher-1","publisher_revision":"1","policy":"policy-1","policy_revision":"1","publication_sequence":1,"publication_idempotency_key":"publication-key-1","locator":"fixture://store/object-1","locator_kind":"object-key","publication_mechanism":"object-put","payload_sha256":digest,"payload_bytes":10,"issued_at":"2026-08-03T00:00:00Z","valid_until":"2026-08-03T02:00:00Z","publication_state":"positive","observed_event":"published","process_id":"process-pub","network_path_id":"path-pub","authentication":{"algorithm":"ed25519","key_id":"publisher-key","signature_sha256":"b"*64},"source_reference":"fixture://publisher/publication-1"})
        reg_path=self.root/"conformance/publication-readback.json"; reg=json.loads(reg_path.read_text()); reg.update({"publisher_profiles":[publisher],"readback_observer_profiles":[observer],"publication_policies":[policy],"external_publication_records":[publication],"bounded_persistence_observations":[],"independent_readbacks":[],"publication_lifecycle_decisions":[]}); reg_path.write_text(json.dumps(reg)); return reg

    def observation(self, identifier: str, at: str, *, state: str="positive", event: str="present", payload: str="a"*64) -> dict:
        return committed({"id":identifier,"revision":"1","publication":"publication-1","publication_revision":"1","observer":"observer-1","observer_revision":"1","observation_state":state,"observed_event":event,"observed_at":at,"valid_until":"2026-08-03T02:00:00Z","locator":"fixture://store/object-1","payload_sha256":payload,"authentication":{"algorithm":"ed25519","key_id":"observer-key","signature_sha256":"c"*64},"source_reference":f"fixture://observer/{identifier}"})

    def readback(self, *, state: str="positive", event: str="bytes-match", provider: str|None=None, payload: str="a"*64, bytes_read: int=10) -> dict:
        if provider is not None:
            path=self.root/"conformance/publication-readback.json"; reg=json.loads(path.read_text()); reg["readback_observer_profiles"][0]["provider_id"]=provider; reg["readback_observer_profiles"][0]=committed({k:v for k,v in reg["readback_observer_profiles"][0].items() if k!="commitment"}); path.write_text(json.dumps(reg))
        return committed({"id":"readback-1","revision":"1","publication":"publication-1","publication_revision":"1","observer":"observer-1","observer_revision":"1","readback_state":state,"observed_event":event,"read_at":"2026-08-03T00:20:00Z","valid_until":"2026-08-03T02:00:00Z","locator":"fixture://store/object-1","payload_sha256":payload,"bytes_read":bytes_read,"process_id":"process-read","network_path_id":"path-read","authentication":{"algorithm":"ed25519","key_id":"observer-key","signature_sha256":"d"*64},"source_reference":"fixture://observer/readback-1"})

    def decision(self, obs: list[str], reads: list[str], *, persistence: str="permit", readback: str="permit", independence: str="permit", content: str="permit", lifecycle: str="independently-read-back", freshness: str="permit", publisher: str="permit", observer: str="permit") -> dict:
        return committed({"id":"decision-1","publication":"publication-1","publication_revision":"1","sequence":1,"persistence_observations":obs,"independent_readbacks":reads,"binding_result":"permit","publisher_result":publisher,"observer_result":observer,"freshness_result":freshness,"publication_result":"permit","persistence_result":persistence,"readback_result":readback,"independence_result":independence,"content_identity_result":content,"lifecycle_state":lifecycle,"evaluated_at":"2026-08-03T00:30:00Z","reasons":["typed-publication-evaluation"],"evidence_refs":["repository-fixture"]})

    def write_case(self, reg: dict, observations: list[dict], readbacks: list[dict], decision: dict) -> dict:
        path=self.root/"conformance/publication-readback.json"; current=json.loads(path.read_text()); current["bounded_persistence_observations"]=observations; current["independent_readbacks"]=readbacks; current["publication_lifecycle_decisions"]=[decision]; path.write_text(json.dumps(current)); self.refresh_freeze(); return self.checker().run()

    def test_positive_publication_persistence_and_independent_readback(self) -> None:
        reg=self.install_base(); obs=[self.observation("obs-1","2026-08-03T00:05:00Z"),self.observation("obs-2","2026-08-03T00:10:00Z")]; rb=self.readback(); report=self.write_case(reg,obs,[rb],self.decision(["obs-1","obs-2"],["readback-1"])); self.assertEqual(report["lifecycle_state_counts"]["independently-read-back"],1)

    def test_insufficient_persistence_remains_publication_observed(self) -> None:
        reg=self.install_base(); obs=[self.observation("obs-1","2026-08-03T00:05:00Z")]; report=self.write_case(reg,obs,[],self.decision(["obs-1"],[],persistence="held",readback="held",independence="held",lifecycle="publication-observed")); self.assertEqual(report["lifecycle_state_counts"]["publication-observed"],1)

    def test_required_readback_missing_preserves_bounded_persistence(self) -> None:
        reg=self.install_base(); obs=[self.observation("obs-1","2026-08-03T00:05:00Z"),self.observation("obs-2","2026-08-03T00:10:00Z")]; report=self.write_case(reg,obs,[],self.decision(["obs-1","obs-2"],[],readback="held",independence="held",lifecycle="persistence-observed")); self.assertEqual(report["lifecycle_state_counts"]["persistence-observed"],1)

    def test_negative_observation_precedes_unavailable_readback(self) -> None:
        reg=self.install_base(min_observations=1); obs=[self.observation("obs-1","2026-08-03T00:05:00Z",state="negative",event="absent")]; rb=self.readback(state="unavailable",event="unreachable"); report=self.write_case(reg,obs,[rb],self.decision(["obs-1"],["readback-1"],persistence="deny",readback="unavailable",lifecycle="rejected")); self.assertEqual(report["lifecycle_state_counts"]["rejected"],1)

    def test_contested_readback_is_contested(self) -> None:
        reg=self.install_base(min_observations=1); obs=[self.observation("obs-1","2026-08-03T00:05:00Z")]; rb=self.readback(state="contested",event="unknown"); report=self.write_case(reg,obs,[rb],self.decision(["obs-1"],["readback-1"],readback="held",lifecycle="contested")); self.assertEqual(report["lifecycle_state_counts"]["contested"],1)

    def test_same_provider_fails_required_independence(self) -> None:
        reg=self.install_base(min_observations=1,dimensions=["provider"]); rb=self.readback(provider="provider-pub"); obs=[self.observation("obs-1","2026-08-03T00:05:00Z")]; report=self.write_case(reg,obs,[rb],self.decision(["obs-1"],["readback-1"],independence="deny",lifecycle="rejected")); self.assertEqual(report["lifecycle_state_counts"]["rejected"],1)

    def test_contested_publisher_holds_lifecycle(self) -> None:
        reg=self.install_base(min_observations=1,readback_requirement="optional"); path=self.root/"conformance/publication-readback.json"; current=json.loads(path.read_text()); publisher=current["publisher_profiles"][0]; publisher["identity_state"]="contested"; current["publisher_profiles"][0]=committed({k:v for k,v in publisher.items() if k!="commitment"}); path.write_text(json.dumps(current)); obs=[self.observation("obs-1","2026-08-03T00:05:00Z")]; report=self.write_case(reg,obs,[],self.decision(["obs-1"],[],readback="permit",independence="permit",publisher="held",lifecycle="held")); self.assertEqual(report["lifecycle_state_counts"]["held"],1)

    def test_readback_digest_mismatch_is_rejected(self) -> None:
        reg=self.install_base(min_observations=1); obs=[self.observation("obs-1","2026-08-03T00:05:00Z")]; rb=self.readback(payload="e"*64); report=self.write_case(reg,obs,[rb],self.decision(["obs-1"],["readback-1"],content="deny",lifecycle="rejected")); self.assertEqual(report["lifecycle_state_counts"]["rejected"],1)

    def test_readback_byte_count_mismatch_is_rejected(self) -> None:
        reg=self.install_base(min_observations=1); obs=[self.observation("obs-1","2026-08-03T00:05:00Z")]; rb=self.readback(bytes_read=9); report=self.write_case(reg,obs,[rb],self.decision(["obs-1"],["readback-1"],content="deny",lifecycle="rejected")); self.assertEqual(report["lifecycle_state_counts"]["rejected"],1)

    def test_observation_spacing_violation_is_rejected(self) -> None:
        reg=self.install_base(interval=300); obs=[self.observation("obs-1","2026-08-03T00:05:00Z"),self.observation("obs-2","2026-08-03T00:06:00Z")]; rb=self.readback(); report=self.write_case(reg,obs,[rb],self.decision(["obs-1","obs-2"],["readback-1"],persistence="deny",lifecycle="rejected")); self.assertEqual(report["lifecycle_state_counts"]["rejected"],1)

    def test_expired_publication_is_rejected(self) -> None:
        reg=self.install_base(min_observations=1); path=self.root/"conformance/publication-readback.json"; current=json.loads(path.read_text()); p=current["external_publication_records"][0]; p["valid_until"]="2026-08-03T00:25:00Z"; current["external_publication_records"][0]=committed({k:v for k,v in p.items() if k!="commitment"}); path.write_text(json.dumps(current)); obs=[self.observation("obs-1","2026-08-03T00:05:00Z")]; rb=self.readback(); report=self.write_case(reg,obs,[rb],self.decision(["obs-1"],["readback-1"],freshness="deny",lifecycle="rejected")); self.assertEqual(report["lifecycle_state_counts"]["rejected"],1)

    def test_duplicate_publication_idempotency_key_is_nonconformant(self) -> None:
        reg=self.install_base(readback_requirement="optional",min_observations=1); path=self.root/"conformance/publication-readback.json"; current=json.loads(path.read_text()); second={k:v for k,v in current["external_publication_records"][0].items() if k!="commitment"}; second.update({"id":"publication-2","publication_sequence":2}); current["external_publication_records"].append(committed(second)); path.write_text(json.dumps(current)); self.refresh_freeze(); self.assertEqual(self.checker().run()["structural_result"],"non-conformant")

    def test_orphan_observation_is_rejected(self) -> None:
        reg=self.install_base(min_observations=1,readback_requirement="optional"); obs=self.observation("obs-1","2026-08-03T00:05:00Z"); path=self.root/"conformance/publication-readback.json"; current=json.loads(path.read_text()); current["bounded_persistence_observations"]=[obs]; current["publication_lifecycle_decisions"]=[self.decision([],[],persistence="held",lifecycle="publication-observed")]; path.write_text(json.dumps(current)); self.refresh_freeze(); self.assertEqual(self.checker().run()["structural_result"],"non-conformant")

if __name__ == "__main__":
    unittest.main()
