import copy
import hashlib
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "tools"))
import eigiib_interop_chain_hardening_check as hardening


class P1A4HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        implementations = []
        for index, (role, rel) in enumerate(hardening.IMPLEMENTATION_CONTRACT):
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = f"implementation-{index}\n".encode()
            path.write_bytes(raw)
            implementations.append({
                "role": role,
                "path": rel,
                "identity": {
                    "algorithm": "sha256",
                    "digest": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                },
            })
        self.manifest = {
            "standard": hardening.STANDARD,
            "profile": hardening.PROFILE,
            "baselineChainIdentity": copy.deepcopy(hardening.BASELINE_CHAIN_IDENTITY),
            "implementations": implementations,
            "claimBoundary": {
                "authority": "p1_chain_contract",
                "doesNotImply": hardening.BOUNDARIES[:],
            },
        }

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def positive_baseline():
        return {
            "tool": "eigiib-interop-chain",
            "tool_version": "0.1.0",
            "standard": "EIGIIB-P1-A4-1.0",
            "structural_result": "conformant",
            "manifest_binding_result": "conformant",
            "p1a1_replay_result": "conformant",
            "p1a2_replay_result": "conformant",
            "p1a3_replay_result": "conformant",
            "cross_capsule_binding_result": "conformant",
            "end_to_end_result": "conformant",
            "chain_identity": copy.deepcopy(hardening.BASELINE_CHAIN_IDENTITY),
        }

    @staticmethod
    def codes(out):
        return {item["code"] for item in out["findings"]}

    def validate(self, manifest=None, runner=None):
        return hardening.validate_hardening(
            self.root,
            manifest if manifest is not None else self.manifest,
            runner or self.positive_baseline,
        )

    def test_positive_exact_closure(self):
        out = self.validate()
        self.assertEqual(out["hardening_result"], "conformant")
        self.assertEqual(out["implementation_binding_result"], "valid")
        self.assertEqual(out["baseline_replay_result"], "valid")

    def test_implementation_byte_mutation(self):
        path = self.root / hardening.IMPLEMENTATION_CONTRACT[2][1]
        path.write_bytes(path.read_bytes() + b"mutation")
        out = self.validate()
        self.assertIn("P1A4H.IMPLEMENTATION.IDENTITY_MISMATCH", self.codes(out))
        self.assertEqual(out["baseline_replay_result"], "not-evaluated")

    def test_fixed_order_required(self):
        obj = copy.deepcopy(self.manifest)
        obj["implementations"][0], obj["implementations"][1] = obj["implementations"][1], obj["implementations"][0]
        self.assertIn("P1A4H.IMPLEMENTATION.ORDER", self.codes(self.validate(obj)))

    def test_fixed_path_required(self):
        obj = copy.deepcopy(self.manifest)
        obj["implementations"][0]["path"] = "tools/other.py"
        self.assertIn("P1A4H.IMPLEMENTATION.PATH", self.codes(self.validate(obj)))

    def test_weakened_boundary_rejected(self):
        obj = copy.deepcopy(self.manifest)
        obj["claimBoundary"]["doesNotImply"].pop()
        self.assertIn("P1A4H.BOUNDARY.WEAKENED", self.codes(self.validate(obj)))

    def test_baseline_failure_is_separate(self):
        bad = self.positive_baseline()
        bad["end_to_end_result"] = "non-conformant"
        out = self.validate(runner=lambda: bad)
        self.assertEqual(out["implementation_binding_result"], "valid")
        self.assertEqual(out["baseline_replay_result"], "invalid")
        self.assertIn("P1A4H.BASELINE.RESULT", self.codes(out))

    def test_symlink_escape_rejected(self):
        rel = hardening.IMPLEMENTATION_CONTRACT[0][1]
        path = self.root / rel
        path.unlink()
        outside = pathlib.Path(self.tmp.name).parent / "p1a4-outside.py"
        outside.write_text("outside\n", encoding="utf-8")
        path.symlink_to(outside)
        try:
            out = self.validate()
            self.assertIn("P1A4H.IMPLEMENTATION.FILE", self.codes(out))
        finally:
            outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
