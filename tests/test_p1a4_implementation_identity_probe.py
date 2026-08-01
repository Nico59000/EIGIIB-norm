import hashlib
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATHS = [
    "tools/eigiib_in_toto_capsule.py",
    "tools/eigiib_sigstore_bundle.py",
    "tools/eigiib_scitt_receipt.py",
    "tools/eigiib_scitt_receipt_hardening_check.py",
    "tools/eigiib_interop_chain.py",
    "tools/eigiib_interop_chain_contract.py",
    "tools/eigiib_interop_chain_validation.py",
    "tools/eigiib_interop_chain_hardening_check.py",
]

class P1A4ImplementationIdentityProbe(unittest.TestCase):
    def test_report_exact_implementation_identities(self):
        rows = []
        for rel in PATHS:
            raw = (ROOT / rel).read_bytes()
            rows.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        self.fail("P1-A4 exact implementation identities: " + json.dumps(rows, separators=(",", ":")))
