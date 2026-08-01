import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import eigiib_interop_chain as baseline
import eigiib_interop_chain_hardening_check as hardening


class P1A4GateProbe(unittest.TestCase):
    def test_report_gate_outputs(self):
        baseline_out = baseline.check_repository(ROOT, "openssl")
        hardening_out = hardening.check_repository(ROOT, "openssl")
        self.fail(
            "P1-A4 gate probe: "
            + json.dumps(
                {"baseline": baseline_out, "hardening": hardening_out},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
