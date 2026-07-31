from __future__ import annotations

import base64
import importlib.util
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve()
TOOL = HERE.parents[1] / "tools" / "eigiib_in_toto_capsule.py"
spec = importlib.util.spec_from_file_location("p1a1_hardened", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class CapsuleHardeningTests(unittest.TestCase):
    def test_duplicate_source_key_rejected(self):
        raw = b'{"standard":"EIGIIB-M0-A2-1.0","overall_result":"conformant","overall_result":"non-conformant"}'
        with self.assertRaises(ValueError):
            mod.build_capsule(raw, "aggregate.json")

    def test_duplicate_capsule_key_rejected_by_strict_loader(self):
        raw = b'{"standard":"EIGIIB-P1-A1-1.0","standard":"EIGIIB-P1-A1-1.0"}'
        with self.assertRaises(mod.DuplicateKeyError):
            mod._strict_json_loads(raw)

    def test_noncanonical_base64_rejected(self):
        src = b'{"standard":"EIGIIB-M0-A2-1.0","overall_result":"conformant","x":"aa"}'
        capsule = mod.build_capsule(src, "aggregate.json")
        data = capsule["statement"]["predicate"]["aggregateReport"]["data"]
        self.assertTrue(data.endswith("fQ=="))
        capsule["statement"]["predicate"]["aggregateReport"]["data"] = data[:-4] + "fR=="
        codes = {f["code"] for f in mod.validate_capsule(capsule, src)["findings"]}
        self.assertIn("P1A1.REPORT.BASE64_NONCANONICAL", codes)

    def test_canonical_base64_accepted(self):
        src = b'{"standard":"EIGIIB-M0-A2-1.0","overall_result":"conformant","x":"aa"}'
        capsule = mod.build_capsule(src, "aggregate.json")
        self.assertEqual("conformant", mod.validate_capsule(capsule, src)["structural_result"])

    def test_exact_bytes_survive_hardening(self):
        src = b'{"standard":"EIGIIB-M0-A2-1.0","overall_result":"incomplete","x":"aa"}'
        capsule = mod.build_capsule(src, "aggregate.json")
        data = capsule["statement"]["predicate"]["aggregateReport"]["data"]
        self.assertEqual(src, base64.b64decode(data, validate=True))


if __name__ == "__main__":
    unittest.main()
