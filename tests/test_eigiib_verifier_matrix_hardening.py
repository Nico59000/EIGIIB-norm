from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "p1a5h", ROOT / "tools/eigiib_verifier_matrix_hardening_check.py"
)
p1a5h = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = p1a5h
SPEC.loader.exec_module(p1a5h)


class P1A5HardeningTests(unittest.TestCase):
    def test_duplicate_json_member_rejected(self):
        with self.assertRaises(ValueError):
            p1a5h.strict_json_loads(b'{"a":1,"a":2}', "TEST")

    def test_identity_is_byte_sensitive(self):
        self.assertNotEqual(p1a5h.identity(b"a"), p1a5h.identity(b"a\n"))

    def test_path_escape_rejected(self):
        with self.assertRaises(ValueError):
            p1a5h.confined_regular_file(ROOT, "../../escape")

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target"
            target.write_text("x")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(ValueError):
                p1a5h.confined_regular_file(root, "link")

    def test_toolchain_substitution_rejected_before_identity_walk(self):
        manifest = {
            "standard": p1a5h.STANDARD,
            "profile": p1a5h.PROFILE,
            "baselineChainIdentity": p1a5h.BASELINE_CHAIN_IDENTITY,
            "toolchainDeclaration": {
                "goVersion": "substituted",
                "pythonVersion": "3.13",
                "opensslMode": "system-provider-reference-route-only",
                "actions": p1a5h.ACTION_PINS,
                "runners": p1a5h.RUNNERS,
            },
            "implementations": [],
            "claimBoundary": {
                "authority": "p1_verifier_matrix_contract",
                "doesNotImply": p1a5h.BOUNDARIES,
            },
        }
        with self.assertRaisesRegex(ValueError, "toolchain declaration"):
            p1a5h.validate_manifest(ROOT, manifest)

    def test_role_order_is_closed(self):
        self.assertEqual(p1a5h.IMPLEMENTATIONS[0], ("go-module", "independent/go.mod"))
        self.assertEqual(
            p1a5h.IMPLEMENTATIONS[-1],
            ("hardening-checker", "tools/eigiib_verifier_matrix_hardening_check.py"),
        )


if __name__ == "__main__":
    unittest.main()
