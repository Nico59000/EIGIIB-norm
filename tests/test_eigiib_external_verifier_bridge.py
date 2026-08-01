from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools/eigiib_external_verifier_bridge.py"
SPEC = importlib.util.spec_from_file_location("eigiib_external_verifier_bridge", MODULE_PATH)
assert SPEC and SPEC.loader
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)


class ExternalVerifierBridgeTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_members(self) -> None:
        with self.assertRaises(ValueError):
            bridge.strict_json_loads(b'{"a":1,"a":2}', "TEST")

    def test_projection_is_closed(self) -> None:
        source = {field: field for field in bridge.PROJECTION_FIELDS}
        source["tool"] = "ignored"
        self.assertEqual(set(bridge.projection(source)), set(bridge.PROJECTION_FIELDS))

    def test_manifest_validation_rejects_wrong_baseline_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests/fixtures/p1-a5").mkdir(parents=True)
            (root / "tests/fixtures/p1-a6").mkdir(parents=True)
            expected_projection = b'{"end_to_end_result":"conformant"}\n'
            expected_external = b'{"end_to_end_result":"conformant"}\n'
            projection_path = root / "tests/fixtures/p1-a5/expected-independent-result.json"
            external_path = root / "tests/fixtures/p1-a6/expected-external-result.json"
            projection_path.write_bytes(expected_projection)
            external_path.write_bytes(expected_external)
            manifest = {
                "standard": bridge.STANDARD,
                "profile": bridge.PROFILE,
                "status": "fixture-observation",
                "baseline": {
                    "standard": "EIGIIB-P1-A5-1.0",
                    "hardeningChecker": "tools/eigiib_verifier_matrix_hardening_check.py",
                    "expectedProjection": {
                        "path": "tests/fixtures/p1-a5/expected-independent-result.json",
                        "identity": bridge.identity(expected_projection),
                    },
                    "chainIdentity": bridge.CHAIN_IDENTITY,
                },
                "externalObservation": {
                    "id": "veraison-go-cose-p1-a3",
                    "module": "github.com/veraison/go-cose",
                    "version": "v1.3.0",
                    "entrypoint": "external/cmd/eigiib-p1-external",
                    "scope": "p1-a3-cose-sign1-and-receipt",
                    "networkMode": "dependency-download-only",
                    "runtimeNetworkOperations": False,
                },
                "expectedResult": {
                    "path": "tests/fixtures/p1-a6/expected-external-result.json",
                    "identity": bridge.identity(expected_external),
                },
                "requiredRunners": ["ubuntu-latest"],
                "claimBoundary": {
                    "authority": "p1_external_bridge_contract",
                    "doesNotImply": bridge.BOUNDARIES,
                },
            }
            with self.assertRaisesRegex(ValueError, "baseline"):
                bridge.validate_manifest(root.resolve(), manifest)

    @mock.patch.object(bridge, "run_json")
    @mock.patch.object(bridge, "validate_manifest")
    @mock.patch.object(bridge, "strict_json_loads")
    def test_check_repository_accepts_equivalent_routes(
        self,
        strict_loads: mock.Mock,
        validate_manifest: mock.Mock,
        run_json: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests/fixtures/p1-a6").mkdir(parents=True)
            (root / "conformance").mkdir()
            (root / "tests/fixtures/p1-a6/bridge.json").write_text("{}", encoding="utf-8")
            (root / "conformance/p1-a6-external-native.json").write_text("{}", encoding="utf-8")
            expected = {field: "conformant" for field in bridge.PROJECTION_FIELDS}
            expected["chain_identity"] = bridge.CHAIN_IDENTITY
            expected_path = root / "tests/fixtures/p1-a6/expected-external-result.json"
            expected_path.write_text("{}", encoding="utf-8")
            validate_manifest.return_value = (expected_path, expected, expected_path)
            strict_loads.side_effect = [
                {},
                {
                    "standard": bridge.STANDARD,
                    "status": "structural-only",
                    "profile": bridge.PROFILE,
                    "bridge_manifest": "tests/fixtures/p1-a6/bridge.json",
                    "baseline": "P1-A5-H0.2",
                    "external_library": "github.com/veraison/go-cose@v1.3.0",
                    "observation_scope": "p1-a3-cose-sign1-and-receipt",
                    "required_runners": bridge.RUNNERS,
                    "runtime_network_operations": [],
                    "production_replays": [],
                },
            ]
            hardened = {
                "hardening_result": "conformant",
                "implementation_binding_result": "valid",
                "baseline_matrix_result": "conformant",
            }
            external = dict(expected)
            external.update(
                {
                    "structural_result": "conformant",
                    "external_observation_result": "conformant",
                    "external_library_result": "valid",
                    "end_to_end_result": "conformant",
                }
            )
            run_json.side_effect = [(0, hardened, ""), (0, external, "")]
            output = bridge.check_repository(root)
            self.assertEqual(output["structural_result"], "conformant")
            self.assertEqual(output["projection_equivalence_result"], "equivalent")


if __name__ == "__main__":
    unittest.main()
