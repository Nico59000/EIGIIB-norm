import base64
import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import eigiib_sigstore_bundle as m


class P1A2SigstoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p1 = (ROOT / 'tests/fixtures/p1-a1/capsule.json').read_bytes()
        cls.key = ROOT / 'tests/fixtures/p1-a2/public-key.pem'
        cls.bundle = json.loads((ROOT / 'tests/fixtures/p1-a2/bundle.json').read_text())

    def verify(self, obj=None, p1=None, key=None):
        return m.validate_capsule(copy.deepcopy(obj or self.bundle), key or self.key, self.p1 if p1 is None else p1)

    def codes(self, out):
        return {f['code'] for f in out['findings']}

    def test_valid_fixture(self):
        out = self.verify()
        self.assertEqual(out['structural_result'], 'conformant')
        self.assertEqual(out['signature_result'], 'valid')
        self.assertEqual(out['trust_result'], 'not-evaluated-by-p1-a2')

    def test_assemble_reproduces_fixture(self):
        sig = self.bundle['bundle']['dsseEnvelope']['signatures'][0]['sig']
        out = m.assemble_capsule(self.p1, sig, self.key)
        self.assertEqual(out, self.bundle)

    def test_mutated_signature_rejected(self):
        obj = copy.deepcopy(self.bundle)
        sig = bytearray(base64.b64decode(obj['bundle']['dsseEnvelope']['signatures'][0]['sig']))
        sig[0] ^= 1
        obj['bundle']['dsseEnvelope']['signatures'][0]['sig'] = base64.b64encode(sig).decode()
        out = self.verify(obj)
        self.assertIn('P1A2.SIGNATURE.INVALID', self.codes(out))
        self.assertEqual(out['signature_result'], 'invalid')

    def test_mutated_payload_rejected(self):
        obj = copy.deepcopy(self.bundle)
        payload = bytearray(base64.b64decode(obj['bundle']['dsseEnvelope']['payload']))
        payload[-1] ^= 1
        obj['bundle']['dsseEnvelope']['payload'] = base64.b64encode(payload).decode()
        out = self.verify(obj)
        self.assertIn('P1A2.SIGNATURE.INVALID', self.codes(out))
        self.assertIn('P1A2.BINDING.STATEMENT_MISMATCH', self.codes(out))

    def test_payload_type_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['bundle']['dsseEnvelope']['payloadType'] = 'application/json'
        out = self.verify(obj)
        self.assertIn('P1A2.DSSE.PAYLOAD_TYPE', self.codes(out))

    def test_multiple_signatures_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['bundle']['dsseEnvelope']['signatures'].append(copy.deepcopy(obj['bundle']['dsseEnvelope']['signatures'][0]))
        out = self.verify(obj)
        self.assertIn('P1A2.DSSE.SIGNATURES', self.codes(out))

    def test_tlog_material_rejected_at_p1a2(self):
        obj = copy.deepcopy(self.bundle)
        obj['bundle']['verificationMaterial']['tlogEntries'] = []
        out = self.verify(obj)
        self.assertIn('P1A2.BUNDLE.VM', self.codes(out))

    def test_timestamp_material_rejected_at_p1a2(self):
        obj = copy.deepcopy(self.bundle)
        obj['bundle']['verificationMaterial']['timestampVerificationData'] = {'rfc3161Timestamps': []}
        out = self.verify(obj)
        self.assertIn('P1A2.BUNDLE.VM', self.codes(out))

    def test_key_hint_mismatch_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['bundle']['verificationMaterial']['publicKeyIdentifier']['hint'] = 'wrong'
        out = self.verify(obj)
        self.assertIn('P1A2.KEY.HINT_MISMATCH', self.codes(out))

    def test_dsse_keyid_mismatch_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['bundle']['dsseEnvelope']['signatures'][0]['keyid'] = 'wrong'
        out = self.verify(obj)
        self.assertIn('P1A2.DSSE.KEYID_MISMATCH', self.codes(out))

    def test_key_binding_mismatch_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['binding']['publicKeySpki']['digest'] = '0' * 64
        out = self.verify(obj)
        self.assertIn('P1A2.BINDING.KEY_MISMATCH', self.codes(out))

    def test_statement_binding_mismatch_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['binding']['p1A1Statement']['bytes'] += 1
        out = self.verify(obj)
        self.assertIn('P1A2.BINDING.STATEMENT_MISMATCH', self.codes(out))

    def test_p1a1_source_mismatch_rejected(self):
        p1 = json.loads(self.p1)
        p1['statement']['predicate']['aggregateResult']['value'] = 'non-conformant'
        raw = json.dumps(p1, indent=2, sort_keys=True).encode() + b'\n'
        out = self.verify(p1=raw)
        self.assertIn('P1A2.P1A1.MISMATCH', self.codes(out))

    def test_boundary_weakening_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['claimBoundary']['doesNotImply'] = obj['claimBoundary']['doesNotImply'][:-1]
        out = self.verify(obj)
        self.assertIn('P1A2.BOUNDARY.WEAKENED', self.codes(out))

    def test_unknown_top_level_field_rejected(self):
        obj = copy.deepcopy(self.bundle)
        obj['trusted'] = True
        out = self.verify(obj)
        self.assertIn('P1A2.CAPSULE.FIELD', self.codes(out))

    def test_noncanonical_payload_base64_rejected(self):
        obj = copy.deepcopy(self.bundle)
        value = obj['bundle']['dsseEnvelope']['payload']
        obj['bundle']['dsseEnvelope']['payload'] = value.rstrip('=')
        out = self.verify(obj)
        self.assertIn('P1A2.DSSE.PAYLOAD', self.codes(out))

    def test_duplicate_json_members_rejected(self):
        with self.assertRaises(ValueError):
            m.strict_json_loads(b'{"a":1,"a":2}')

    def test_non_ed25519_public_key_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            priv = pathlib.Path(td) / 'ec.pem'
            pub = pathlib.Path(td) / 'ec.pub.pem'
            subprocess.run(['openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(priv)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['openssl','pkey','-in',str(priv),'-pubout','-out',str(pub)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            out = self.verify(key=pub)
            self.assertIn('P1A2.KEY.INVALID', self.codes(out))


if __name__ == '__main__':
    unittest.main()
