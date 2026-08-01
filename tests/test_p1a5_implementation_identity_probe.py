from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "p1a5h_probe", ROOT / "tools/eigiib_verifier_matrix_hardening_check.py"
)
module = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class P1A5ImplementationIdentityProbe(unittest.TestCase):
    def test_report_exact_implementation_identities(self):
        rows = []
        for role, relative in module.IMPLEMENTATIONS:
            raw = (ROOT / relative).read_bytes()
            rows.append(
                {
                    "role": role,
                    "path": relative,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        self.fail("P1-A5 exact implementation identities: " + json.dumps(rows, separators=(",", ":")))


if __name__ == "__main__":
    unittest.main()
