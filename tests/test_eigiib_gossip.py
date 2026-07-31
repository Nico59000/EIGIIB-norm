from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "tools" / "eigiib_gossip_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_gossip_check", MODULE_PATH)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)

STANDARD = MOD.STANDARD


def e5_base():
    return {
        "standard": "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0",
        "revision": "test",
        "logs": [{"id": "A"}, {"id": "B"}],
        "entries": [
            {
                "id": "eA0",
                "log": "A",
                "index": 0,
                "bytes": {"utf8": "eigiib-e6-cross-log-v1:B:1:" + "d" * 64 + "\n"},
            }
        ],
        "checkpoints": [
            {"id": "cpA1", "log": "A", "size": 1, "root_hash": "a" * 64},
            {"id": "cpA2", "log": "A", "size": 2, "root_hash": "b" * 64},
            {"id": "cpA2fork", "log": "A", "size": 2, "root_hash": "c" * 64},
            {"id": "cpB1", "log": "B", "size": 1, "root_hash": "d" * 64},
        ],
        "inclusion_proofs": [
            {"id": "incA1B1", "entry": "eA0", "checkpoint": "cpA1", "path": []}
        ],
        "consistency_proofs": [
            {
                "id": "consA1A2",
                "older_checkpoint": "cpA1",
                "newer_checkpoint": "cpA2",
                "profile": "prefix-recompute-v1",
                "entries": [],
            }
        ],
        "witnesses": [],
        "observations": [],
        "witness_policies": [],
        "witness_decisions": [],
        "trust_history_events": [],
        "trust_history_policies": [],
        "trust_history_decisions": [],
    }


def e4_base():
    policy = {
        "id": "p",
        "purpose": "checkpoint",
        "roots": ["r"],
        "allowed_suites": ["s"],
        "max_path_length": 0,
        "threshold": {"count": 1, "distinct_by": "key"},
        "environment": "test",
        "require_crypto": True,
        "require_revocation_evaluation": False,
    }
    return {
        "standard": "EIGIIB-1.0+E4-1.0",
        "revision": "test",
        "principals": [
            {"id": "principal.one", "kind": "test", "display_name": "one"},
            {"id": "principal.two", "kind": "test", "display_name": "two"},
        ],
        "keys": [
            {"id": "k1", "principal": "principal.one"},
            {"id": "k2", "principal": "principal.two"},
        ],
        "roots": [],
        "policies": [policy],
        "delegations": [],
        "revocations": [],
        "attestations": [
            {
                "id": "att1",
                "bindings": [{"type": "local", "id": "e5-checkpoint:cpA2"}],
                "signatures": ["sig1"],
            },
            {
                "id": "att2",
                "bindings": [{"type": "local", "id": "e5-checkpoint:cpA2fork"}],
                "signatures": ["sig2"],
            },
        ],
        "signatures": [
            {"id": "sig1", "key": "k1"},
            {"id": "sig2", "key": "k1"},
        ],
        "decisions": [
            {"id": "dec1", "attestation": "att1", "policy": "p", "state": "authenticated"},
            {"id": "dec2", "attestation": "att2", "policy": "p", "state": "authenticated"},
        ],
    }


def e6_empty():
    return {
        "standard": STANDARD,
        "revision": "test",
        "peers": [],
        "transmissions": [],
        "views": [],
        "comparison_policies": [],
        "comparisons": [],
        "fork_evidence": [],
        "cross_log_links": [],
        "cross_log_policies": [],
        "cross_log_decisions": [],
        "accountability_policies": [],
        "accountability_decisions": [],
    }


class Repo:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "conformance").mkdir()
        self.write("conformance/transparency.json", e5_base())
        self.write("conformance/trust.json", e4_base())
        self.write("conformance/gossip.json", e6_empty())

    def write(self, path, data):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), encoding="utf-8")

    def read(self, path):
        return json.loads((self.root / path).read_text(encoding="utf-8"))

    def run(self):
        return MOD.Checker(
            self.root,
            Path("conformance/gossip.json"),
            Path("conformance/transparency.json"),
            Path("conformance/trust.json"),
        ).run()

    def close(self):
        self.tmp.cleanup()


class GossipTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.close()

    def add_direct_conflict(self, *, same_principal=True):
        if not same_principal:
            e4 = self.repo.read("conformance/trust.json")
            e4["signatures"][1]["key"] = "k2"
            self.repo.write("conformance/trust.json", e4)
        e6 = self.repo.read("conformance/gossip.json")
        e6["peers"] = [
            {"id": "o1", "role": "observer"},
            {"id": "o2", "role": "observer"},
        ]
        e6["views"] = [
            {"id": "v1", "observer": "o1", "checkpoint": "cpA2", "source": "test", "e4_decision": "dec1"},
            {"id": "v2", "observer": "o2", "checkpoint": "cpA2fork", "source": "test", "e4_decision": "dec2"},
        ]
        e6["comparison_policies"] = [
            {"id": "cmp", "require_authenticated_views": False, "allow_e5_consistency_reference": True, "preserve_unresolved": True}
        ]
        e6["comparisons"] = [
            {"id": "c1", "left_view": "v1", "right_view": "v2", "policy": "cmp", "state": "direct-conflict"}
        ]
        e6["fork_evidence"] = [
            {"id": "f1", "comparison": "c1", "views": ["v1", "v2"], "relation": "direct-conflict", "state": "authenticated-conflict", "evidence_sources": ["v1", "v2"]}
        ]
        e6["accountability_policies"] = [
            {"id": "ap", "require_direct_conflict": True, "require_authenticated_views": True, "attribution_mode": "single-principal-v1", "minimum_evidence_sources": 2}
        ]
        e6["accountability_decisions"] = [
            {"id": "ad", "policy": "ap", "fork_evidence": "f1", "state": "single-principal-equivocation", "attributed_principal": "principal.one"}
        ]
        self.repo.write("conformance/gossip.json", e6)

    def test_direct_conflict_and_single_principal_attribution(self):
        self.add_direct_conflict()
        report = self.repo.run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["fork_state"], "direct-conflict-observed")
        self.assertEqual(report["accountability_result"], "attributed")

    def test_same_view(self):
        e6 = self.repo.read("conformance/gossip.json")
        e6["peers"] = [{"id": "o1", "role": "observer"}, {"id": "o2", "role": "observer"}]
        e6["views"] = [
            {"id": "v1", "observer": "o1", "checkpoint": "cpA1", "source": "test"},
            {"id": "v2", "observer": "o2", "checkpoint": "cpA1", "source": "test"},
        ]
        e6["comparison_policies"] = [{"id": "p", "require_authenticated_views": False, "allow_e5_consistency_reference": True, "preserve_unresolved": True}]
        e6["comparisons"] = [{"id": "c", "left_view": "v1", "right_view": "v2", "policy": "p", "state": "same-view"}]
        self.repo.write("conformance/gossip.json", e6)
        self.assertEqual(self.repo.run()["structural_result"], "conformant")

    def test_different_sizes_require_e5_reference(self):
        e6 = self.repo.read("conformance/gossip.json")
        e6["peers"] = [{"id": "o1", "role": "observer"}, {"id": "o2", "role": "observer"}]
        e6["views"] = [
            {"id": "v1", "observer": "o1", "checkpoint": "cpA1", "source": "test"},
            {"id": "v2", "observer": "o2", "checkpoint": "cpA2", "source": "test"},
        ]
        e6["comparison_policies"] = [{"id": "p", "require_authenticated_views": False, "allow_e5_consistency_reference": True, "preserve_unresolved": True}]
        e6["comparisons"] = [{"id": "c", "left_view": "v1", "right_view": "v2", "policy": "p", "state": "compatible-by-e5-reference", "e5_consistency_proof": "consA1A2"}]
        self.repo.write("conformance/gossip.json", e6)
        self.assertEqual(self.repo.run()["structural_result"], "conformant")

    def test_different_size_is_not_direct_conflict(self):
        e6 = self.repo.read("conformance/gossip.json")
        e6["peers"] = [{"id": "o1", "role": "observer"}, {"id": "o2", "role": "observer"}]
        e6["views"] = [
            {"id": "v1", "observer": "o1", "checkpoint": "cpA1", "source": "test"},
            {"id": "v2", "observer": "o2", "checkpoint": "cpA2", "source": "test"},
        ]
        e6["comparison_policies"] = [{"id": "p", "require_authenticated_views": False, "allow_e5_consistency_reference": False, "preserve_unresolved": True}]
        e6["comparisons"] = [{"id": "c", "left_view": "v1", "right_view": "v2", "policy": "p", "state": "direct-conflict"}]
        self.repo.write("conformance/gossip.json", e6)
        report = self.repo.run()
        self.assertEqual(report["structural_result"], "non-conformant")
        self.assertTrue(any(x["code"] == "E6.COMPARISON.STATE" for x in report["findings"]))

    def test_cross_log_anchor(self):
        e6 = self.repo.read("conformance/gossip.json")
        e6["cross_log_links"] = [
            {"id": "x", "source_checkpoint": "cpA1", "source_entry": "eA0", "inclusion_proof": "incA1B1", "target_checkpoint": "cpB1"}
        ]
        e6["cross_log_policies"] = [
            {"id": "xp", "minimum_anchors": 1, "required_logs": ["A", "B"], "reciprocal": False, "require_authenticated_source_views": False}
        ]
        e6["cross_log_decisions"] = [{"id": "xd", "policy": "xp", "links": ["x"], "state": "anchored"}]
        self.repo.write("conformance/gossip.json", e6)
        report = self.repo.run()
        self.assertEqual(report["structural_result"], "conformant")
        self.assertEqual(report["cross_log_result"], "anchored")

    def test_no_false_single_principal_attribution(self):
        self.add_direct_conflict(same_principal=False)
        report = self.repo.run()
        self.assertEqual(report["structural_result"], "non-conformant")
        self.assertTrue(any(x["code"] == "E6.ACCOUNTABILITY.STATE" for x in report["findings"]))

    def test_cli_rejects_path_escape(self):
        rc = MOD.main([str(self.repo.root), "--registry", "../outside.json"])
        self.assertEqual(rc, 64)


if __name__ == "__main__":
    unittest.main()
