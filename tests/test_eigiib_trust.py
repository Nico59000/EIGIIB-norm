from __future__ import annotations
import hashlib, importlib.util, json, shutil, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOD_PATH = ROOT / "tools" / "eigiib_trust_check.py"
spec = importlib.util.spec_from_file_location("eigiib_trust_check", MOD_PATH)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

FIX = ROOT / "tests" / "fixtures" / "e4"

def registry(root: Path, *, test_only=True, environment="test", decision="authenticated"):
    pub_rel = "public.pem"
    stmt_rel = "statement.json"
    sig_rel = "statement.sig.b64"
    shutil.copy(FIX / "test-root-public.pem", root / pub_rel)
    shutil.copy(FIX / "statement.json", root / stmt_rel)
    shutil.copy(FIX / "statement.sig.b64", root / sig_rel)
    fp = hashlib.sha256((root / pub_rel).read_bytes()).hexdigest()
    obj = {
      "standard":"EIGIIB-1.0+E4-1.0", "revision":"fixture",
      "principals":[{"id":"p.test","kind":"test","display_name":"E4 test principal"}],
      "keys":[{"id":"k.test","principal":"p.test","suite":"ed25519-openssl-raw-v1","public_key":pub_rel,"fingerprint":{"algorithm":"sha256","digest":fp},"usages":["provenance"],"status":"active","test_only":test_only}],
      "roots":[{"id":"r.test","key":"k.test","principal":"p.test","purposes":["provenance"],"scope":{},"environment":environment}],
      "policies":[{"id":"pol.test","purpose":"provenance","roots":["r.test"],"allowed_suites":["ed25519-openssl-raw-v1"],"max_path_length":0,"threshold":{"count":1,"distinct_by":"key"},"environment":environment,"require_crypto":True,"require_revocation_evaluation":False}],
      "delegations":[], "revocations":[],
      "attestations":[{"id":"a.test","purpose":"provenance","statement":stmt_rel,"bindings":[],"signatures":["s.test"]}],
      "signatures":[{"id":"s.test","attestation":"a.test","key":"k.test","suite":"ed25519-openssl-raw-v1","signature":sig_rel,"signature_encoding":"base64"}],
      "decisions":[{"id":"d.test","attestation":"a.test","policy":"pol.test","state":decision}]
    }
    (root / "trust.json").write_text(json.dumps(obj, indent=2), encoding="utf-8")
    return obj

class E4Tests(unittest.TestCase):
    def run_checker(self, root: Path, provider="openssl"):
        return mod.Checker(root, Path("trust.json"), provider).run()

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_valid_test_root_signature(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); registry(root)
            rep=self.run_checker(root)
            self.assertEqual(rep["structural_result"], "conformant")
            self.assertEqual(rep["crypto_result"], "verified")
            self.assertFalse(rep["findings"])

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_tampered_statement_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); registry(root); (root/"statement.json").write_bytes(b"tampered")
            rep=self.run_checker(root)
            self.assertEqual(rep["structural_result"], "non-conformant")
            self.assertTrue(any(f["code"]=="E4-DECISION.OVERCLAIM" for f in rep["findings"]))

    def test_fingerprint_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); obj=registry(root, decision="unavailable")
            obj["keys"][0]["fingerprint"]["digest"]="00"*32
            (root/"trust.json").write_text(json.dumps(obj), encoding="utf-8")
            rep=self.run_checker(root,"none")
            self.assertTrue(any(f["code"]=="E4-KEY.FINGERPRINT" for f in rep["findings"]))

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_test_key_cannot_satisfy_production(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); registry(root, test_only=True, environment="production")
            rep=self.run_checker(root)
            self.assertEqual(rep["structural_result"], "non-conformant")
            self.assertTrue(any(f["code"]=="E4-DECISION.OVERCLAIM" for f in rep["findings"]))

    def test_missing_crypto_is_not_false_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); registry(root, decision="unavailable")
            rep=self.run_checker(root,"none")
            self.assertEqual(rep["crypto_result"], "not-evaluated")
            self.assertFalse(any(f["code"]=="E4-DECISION.OVERCLAIM" for f in rep["findings"]))

    def test_delegation_cycle_detected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); obj=registry(root, decision="partially-evaluated")
            obj["keys"].append(dict(obj["keys"][0], id="k.two"))
            obj["delegations"]=[
              {"id":"d1","from_key":"k.test","to_key":"k.two","purposes":["provenance"],"scope":{},"max_remaining_depth":1,"attestation":"a.test"},
              {"id":"d2","from_key":"k.two","to_key":"k.test","purposes":["provenance"],"scope":{},"max_remaining_depth":1,"attestation":"a.test"}
            ]
            (root/"trust.json").write_text(json.dumps(obj),encoding="utf-8")
            rep=self.run_checker(root,"none")
            self.assertTrue(any(f["code"]=="E4-DELEGATION.CYCLE" for f in rep["findings"]))

    def test_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); obj=registry(root, decision="unavailable")
            obj["keys"][0]["public_key"]="../escape.pem"
            (root/"trust.json").write_text(json.dumps(obj),encoding="utf-8")
            rep=self.run_checker(root,"none")
            self.assertTrue(any(f["code"]=="E4-PATH.ESCAPE" for f in rep["findings"]))

if __name__ == "__main__": unittest.main()
