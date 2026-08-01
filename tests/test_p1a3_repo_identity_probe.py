import hashlib
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class P1A3RepositoryIdentityProbe(unittest.TestCase):
    def test_report_exact_p1a2_identity(self):
        raw = (ROOT / "tests/fixtures/p1-a2/bundle.json").read_bytes()
        self.fail(f"P1-A2 exact repository identity: bytes={len(raw)} sha256={hashlib.sha256(raw).hexdigest()}")
