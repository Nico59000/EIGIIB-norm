from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
TOOL = HERE.parent.parent / "tools" / "eigiib_provenance_check.py"
SPEC = importlib.util.spec_from_file_location("eigiib_provenance_check", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Repo:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "conformance").mkdir()
        (self.root / "artifacts").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "docs" / "authority.md").write_text("# Authority\n", encoding="utf-8")
        (self.root / "conformance" / "e1.json").write_text(
            json.dumps(
                {
                    "standard": "EIGIIB-1.0+E1-1.0",
                    "revision": "r1",
                    "policies": [],
                    "claims": [],
                    "evidence": [
                        {
                            "id": "evidence:test",
                            "subject": "fixture",
                            "revision": "r1",
                            "kind": "reproducibility-replay",
                            "procedure": "fixture",
                            "result": "pass",
                            "scope": {"platform": ["test"]},
                            "provenance": "fixture",
                            "artifacts": [],
                        }
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self.write_profile()

    def cleanup(self):
        self.tmp.cleanup()

    def write_profile(self):
        (self.root / "EIGIIB.toml").write_text(
            '''standard = "EIGIIB-1.0"
extensions = ["E1-1.0", "E2-1.0", "E3-1.0"]
conformance_target = "EIGIIB-C2"
revision = "r1"
registry = "conformance/e1.json"

[authorities]
standard = "docs/authority.md"
build = "docs/authority.md"
provenance = "conformance/provenance.json"
''',
            encoding="utf-8",
        )

    def artifact(self, aid: str, role: str, path: str, data: bytes):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return {
            "id": aid,
            "role": role,
            "kind": "file",
            "path": path,
            "size": len(data),
            "digests": {"sha256": sha(data)},
            "availability": "local",
            "identity_state": "verified",
        }

    def valid_registry(self):
        a_in = self.artifact("input", "source", "artifacts/in.txt", b"input\n")
        a_out = self.artifact("expected", "result", "artifacts/out.bin", b"result\n")
        a_replay = self.artifact("replay", "result", "artifacts/replay.bin", b"result\n")
        return {
            "standard": "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0",
            "revision": "r1",
            "artifacts": [a_in, a_out, a_replay],
            "environments": [{"id": "env", "properties": {"runtime": "test"}}],
            "equivalence_policies": [],
            "procedures": [
                {
                    "id": "build",
                    "authority": "build",
                    "implementation_artifacts": [],
                    "determinism": "deterministic",
                }
            ],
            "events": [
                {
                    "id": "event",
                    "subject": "fixture",
                    "source_revision": "r1",
                    "procedure": "build",
                    "environment": "env",
                    "inputs": [{"role": "source", "artifact": "input"}],
                    "outputs": [{"role": "result", "artifact": "expected"}],
                    "result": "success",
                }
            ],
            "replays": [
                {
                    "id": "replay-1",
                    "target_event": "event",
                    "procedure": "build",
                    "environment": "env",
                    "input_bindings": [{"role": "source", "artifact": "input"}],
                    "observed_outputs": [{"role": "result", "artifact": "replay"}],
                    "relation": "byte-exact",
                    "result": "match",
                    "independence": "separate-run",
                }
            ],
            "evidence_bindings": [
                {
                    "evidence_id": "evidence:test",
                    "artifacts": ["expected", "replay"],
                    "production_events": ["event"],
                    "replays": ["replay-1"],
                }
            ],
        }

    def write_registry(self, obj):
        (self.root / "conformance" / "provenance.json").write_text(
            json.dumps(obj, indent=2) + "\n", encoding="utf-8"
        )

    def report(self):
        return MODULE.Checker(self.root, Path("EIGIIB.toml")).run()


class E3Tests(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.cleanup()

    def test_valid_exact_replay(self):
        self.repo.write_registry(self.repo.valid_registry())
        report = self.repo.report()
        self.assertEqual(report["result"], "conformant", report["findings"])

    def test_local_digest_mismatch(self):
        reg = self.repo.valid_registry()
        reg["artifacts"][0]["digests"]["sha256"] = "0" * 64
        self.repo.write_registry(reg)
        codes = {x["code"] for x in self.repo.report()["findings"]}
        self.assertIn("M-E3-ARTIFACT.MISMATCH", codes)

    def test_cycle_rejected(self):
        reg = self.repo.valid_registry()
        reg["events"].append(
            {
                "id": "event-2",
                "subject": "fixture",
                "source_revision": "r1",
                "procedure": "build",
                "environment": "env",
                "inputs": [{"role": "source", "artifact": "expected"}],
                "outputs": [{"role": "result", "artifact": "input"}],
                "result": "success",
            }
        )
        self.repo.write_registry(reg)
        codes = {x["code"] for x in self.repo.report()["findings"]}
        self.assertIn("M-E3-CYCLE", codes)

    def test_declared_byte_match_must_match_digest(self):
        reg = self.repo.valid_registry()
        replay_path = self.repo.root / "artifacts" / "replay.bin"
        replay_path.write_bytes(b"different\n")
        reg["artifacts"][2]["size"] = len(b"different\n")
        reg["artifacts"][2]["digests"]["sha256"] = sha(b"different\n")
        self.repo.write_registry(reg)
        codes = {x["code"] for x in self.repo.report()["findings"]}
        self.assertIn("M-E3-REPLAY.MISMATCH", codes)

    def test_replay_must_use_distinct_artifact_instance(self):
        reg = self.repo.valid_registry()
        reg["replays"][0]["observed_outputs"][0]["artifact"] = "expected"
        self.repo.write_registry(reg)
        codes = {x["code"] for x in self.repo.report()["findings"]}
        self.assertIn("M-E3-REPLAY.INSTANCE", codes)

    def test_dangling_e1_binding_rejected(self):
        reg = self.repo.valid_registry()
        reg["evidence_bindings"][0]["evidence_id"] = "evidence:missing"
        self.repo.write_registry(reg)
        codes = {x["code"] for x in self.repo.report()["findings"]}
        self.assertIn("M-E3-BINDING.EVIDENCE", codes)

    def test_registry_cannot_hash_itself(self):
        reg = self.repo.valid_registry()
        reg["artifacts"].append(
            {
                "id": "self",
                "role": "registry",
                "kind": "manifest",
                "path": "conformance/provenance.json",
                "size": 0,
                "digests": {"sha256": "0" * 64},
                "availability": "local",
                "identity_state": "verified",
            }
        )
        self.repo.write_registry(reg)
        codes = {x["code"] for x in self.repo.report()["findings"]}
        self.assertIn("M-E3-ARTIFACT.SELF", codes)


if __name__ == "__main__":
    unittest.main()
