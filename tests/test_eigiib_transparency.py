from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "eigiib_transparency_check.py"
spec = importlib.util.spec_from_file_location("eigiib_transparency_check", MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader is not None
spec.loader.exec_module(mod)

STANDARD = mod.STANDARD


def base_registry():
    return {
        "standard": STANDARD,
        "revision": "fixture",
        "logs": [{
            "id": "log1", "purpose": "test", "tree_profile": mod.TREE_PROFILE,
            "operator": None, "status": "active", "history_coverage": []
        }],
        "entries": [], "checkpoints": [], "inclusion_proofs": [], "consistency_proofs": [],
        "witnesses": [], "observations": [], "witness_policies": [], "witness_decisions": [],
        "trust_history_events": [], "trust_history_policies": [], "trust_history_decisions": []
    }


def write_repo(reg, trust=None):
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)
    (root / "conformance").mkdir()
    (root / "conformance/transparency.json").write_text(json.dumps(reg), encoding="utf-8")
    trust = trust or {"decisions": []}
    (root / "conformance/trust.json").write_text(json.dumps(trust), encoding="utf-8")
    return td, root


def entry(i, text):
    return {"id": f"e{i}", "log": "log1", "index": i, "bytes": {"utf8": text}, "kind": "test"}


def cp(cid, size, payloads):
    return {"id": cid, "log": "log1", "size": size, "root_hash": mod.merkle_root([x.encode() for x in payloads[:size]]).hex()}


def inclusion_path(payloads, index):
    leaves = [mod.leaf_hash(x.encode()) for x in payloads]
    def rec(vals, idx):
        if len(vals) == 1:
            return []
        k = mod.largest_power_two_less_than(len(vals))
        if idx < k:
            sibling = mod.merkle_root_from_leaf_hashes(vals[k:]).hex()
            return rec(vals[:k], idx) + [{"side": "right", "hash": sibling}]
        sibling = mod.merkle_root_from_leaf_hashes(vals[:k]).hex()
        return rec(vals[k:], idx-k) + [{"side": "left", "hash": sibling}]
    return rec(leaves, index)


class E5Tests(unittest.TestCase):
    def run_checker(self, reg, trust=None):
        td, root = write_repo(reg, trust)
        self.addCleanup(td.cleanup)
        return mod.Checker(root, Path("conformance/transparency.json"), Path("conformance/trust.json")).run()

    def test_valid_inclusion_and_consistency(self):
        p = ["a", "b", "c", "d"]
        r = base_registry()
        r["entries"] = [entry(i, x) for i, x in enumerate(p)]
        r["checkpoints"] = [cp("c2", 2, p), cp("c4", 4, p)]
        r["inclusion_proofs"] = [{"id": "ip", "entry": "e2", "checkpoint": "c4", "path": inclusion_path(p, 2)}]
        r["consistency_proofs"] = [{"id": "co", "profile": mod.CONSISTENCY_PROFILE, "older_checkpoint": "c2", "newer_checkpoint": "c4", "entries": ["e0","e1","e2","e3"]}]
        out = self.run_checker(r)
        self.assertEqual(out["structural_result"], "conformant")
        self.assertEqual(out["append_only_result"], "verified")
        self.assertEqual(out["findings"], [])

    def test_tampered_inclusion_fails(self):
        p = ["a", "b"]
        r = base_registry()
        r["entries"] = [entry(i, x) for i, x in enumerate(p)]
        r["checkpoints"] = [cp("c2", 2, p)]
        bad = inclusion_path(p, 0)
        bad[0]["hash"] = "00" * 32
        r["inclusion_proofs"] = [{"id": "ip", "entry": "e0", "checkpoint": "c2", "path": bad}]
        out = self.run_checker(r)
        self.assertEqual(out["structural_result"], "non-conformant")
        self.assertTrue(any(x["code"] == "E5.INCLUSION.INVALID" for x in out["findings"]))

    def test_invalid_consistency_fails(self):
        p = ["a", "b", "c"]
        r = base_registry()
        r["entries"] = [entry(i, x) for i, x in enumerate(p)]
        old = cp("c2", 2, p)
        new = cp("c3", 3, p)
        old["root_hash"] = "11" * 32
        r["checkpoints"] = [old, new]
        r["consistency_proofs"] = [{"id":"co","profile":mod.CONSISTENCY_PROFILE,"older_checkpoint":"c2","newer_checkpoint":"c3","entries":["e0","e1","e2"]}]
        out = self.run_checker(r)
        self.assertEqual(out["structural_result"], "non-conformant")
        self.assertTrue(any(x["code"] in {"E5.CONSISTENCY.INVALID", "E5.CHECKPOINT.ROOT_MISMATCH"} for x in out["findings"]))

    def test_same_size_split_view_detected(self):
        p = ["a"]
        r = base_registry()
        r["entries"] = [entry(0, "a")]
        good = cp("c1a", 1, p)
        bad = dict(good, id="c1b", root_hash="22" * 32)
        r["checkpoints"] = [good, bad]
        out = self.run_checker(r)
        self.assertEqual(out["fork_state"], "observed")
        self.assertTrue(any(x["code"] == "E5.FORK.SAME_SIZE" for x in out["findings"]))

    def test_witness_domain_quorum_enforced(self):
        p = ["a"]
        r = base_registry()
        r["entries"] = [entry(0, "a")]
        r["checkpoints"] = [cp("c1", 1, p)]
        r["witnesses"] = [
            {"id":"w1","principal":"p1","domain":"same","operator_relation":None,"status":"active","test_only":True},
            {"id":"w2","principal":"p2","domain":"same","operator_relation":None,"status":"active","test_only":True},
        ]
        r["observations"] = [
            {"id":"o1","witness":"w1","checkpoint":"c1","result":"observed","observed_at":None,"e4_decision":None},
            {"id":"o2","witness":"w2","checkpoint":"c1","result":"observed","observed_at":None,"e4_decision":None},
        ]
        r["witness_policies"] = [{"id":"wp","log":"log1","minimum":2,"distinct_by":"domain","require_authenticated":False,"required_domains":[]}]
        r["witness_decisions"] = [{"id":"wd","checkpoint":"c1","policy":"wp","state":"witnessed","observations":["o1","o2"]}]
        out = self.run_checker(r)
        self.assertTrue(any(x["code"] == "E5.WITNESS_DECISION.QUORUM" for x in out["findings"]))

    def test_authenticated_witness_requires_e4_decision(self):
        p = ["a"]
        r = base_registry()
        r["entries"] = [entry(0, "a")]
        r["checkpoints"] = [cp("c1", 1, p)]
        r["witnesses"] = [{"id":"w1","principal":"p1","domain":"d1","operator_relation":None,"status":"active","test_only":True}]
        r["observations"] = [{"id":"o1","witness":"w1","checkpoint":"c1","result":"observed","observed_at":None,"e4_decision":"missing"}]
        r["witness_policies"] = [{"id":"wp","log":"log1","minimum":1,"distinct_by":"witness","require_authenticated":True,"required_domains":[]}]
        r["witness_decisions"] = [{"id":"wd","checkpoint":"c1","policy":"wp","state":"witnessed","observations":["o1"]}]
        out = self.run_checker(r, {"decisions": []})
        self.assertTrue(any(x["code"] == "E5.WITNESS_DECISION.AUTH" for x in out["findings"]))

    def test_path_escape_rejected(self):
        r = base_registry()
        r["entries"] = [{"id":"e0","log":"log1","index":0,"bytes":{"path":"../escape"},"kind":"test"}]
        out = self.run_checker(r)
        self.assertTrue(any(x["code"] == "E5.PATH.ESCAPE" for x in out["findings"]))


if __name__ == "__main__":
    unittest.main()
