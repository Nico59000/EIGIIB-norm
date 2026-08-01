import copy
import pathlib

from p1a4_test_support import P1A4Fixture, p1a4


class P1A4ReplayTests(P1A4Fixture):
    def test_p1a1_rebuild_failure(self):
        self.assertIn("P1A4.REPLAY.P1A1_REBUILD", self.codes(self.validate(bytes_runner=lambda c, r: (0, b"wrong", ""))))

    def test_p1a1_checker_failure(self):
        def runner(command, cwd):
            if command[1] == p1a4.CHECKER_CONTRACT["p1-a1"][0]:
                return 1, {"tool_version": "0.2.0", "structural_result": "non-conformant", "findings": [{"code": "X"}]}, ""
            return self.fake_json(command, cwd)
        self.assertIn("P1A4.REPLAY.P1A1", self.codes(self.validate(json_runner=runner)))

    def test_p1a2_checker_failure(self):
        def runner(command, cwd):
            if command[1] == p1a4.CHECKER_CONTRACT["p1-a2"][0]:
                return 0, {"tool_version": "0.1.1", "structural_result": "conformant", "signature_result": "invalid", "findings": []}, ""
            return self.fake_json(command, cwd)
        self.assertIn("P1A4.REPLAY.P1A2", self.codes(self.validate(json_runner=runner)))

    def test_p1a3_checker_failure(self):
        def runner(command, cwd):
            if command[1] == p1a4.CHECKER_CONTRACT["p1-a3-h0.2"][0]:
                return 1, {"tool_version": "0.2.0", "hardening_result": "non-conformant", "findings": []}, ""
            return self.fake_json(command, cwd)
        self.assertIn("P1A4.REPLAY.P1A3", self.codes(self.validate(json_runner=runner)))

    def test_checker_version_mismatch(self):
        def runner(command, cwd):
            if command[1] == p1a4.CHECKER_CONTRACT["p1-a2"][0]:
                return 0, {"tool_version": "9.9.9", "structural_result": "conformant", "signature_result": "valid", "findings": []}, ""
            return self.fake_json(command, cwd)
        self.assertIn("P1A4.REPLAY.P1A2", self.codes(self.validate(json_runner=runner)))

    def test_repository_state_mismatch(self):
        state = copy.deepcopy(self.state); state["network_mode"] = "live"
        self._write_json("conformance/p1-a4-chain.json", state)
        out = p1a4.check_repository(self.root, json_runner=self.fake_json, bytes_runner=self.fake_bytes)
        self.assertIn("P1A4.REPO.STATE", self.codes(out))

    def test_symlink_escape(self):
        path = self.root / p1a4.COMPONENT_PATHS["m0-a2-report"]
        path.unlink()
        outside = pathlib.Path(self.tmp.name).parent / "p1a4-outside.json"
        outside.write_text("{}")
        path.symlink_to(outside)
        try:
            self.assertIn("P1A4.COMPONENT.PATH", self.codes(self.validate()))
        finally:
            outside.unlink(missing_ok=True)
