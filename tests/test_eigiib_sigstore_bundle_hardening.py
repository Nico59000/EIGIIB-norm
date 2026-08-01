import base64
import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import eigiib_sigstore_bundle as m


class P1A2HardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / 'tests/fixtures/p1-a1/capsule.json').read_bytes()
        cls.key = ROOT / 'tests/fixtures/p1-a2/public-key.pem'
        cls.bundle = json.loads((ROOT / 'tests/fixtures/p1-a2/bundle.json').read_text())

    def codes(self, out):
        return {item['code'] for item in out['findings']}

    def test_exact_p1a1_source_required(self):
        out = m.validate_capsule(copy.deepcopy(self.bundle), self.key, None)
        self.assertIn('P1A2.P1A1.REQUIRED', self.codes(out))
        self.assertEqual(out['signature_result'], 'valid')

    def test_noncanonical_statement_payload_rejected(self):
        obj = copy.deepcopy(self.bundle)
        statement = json.loads(base64.b64decode(obj['bundle']['dsseEnvelope']['payload']))
        pretty = (json.dumps(statement, indent=2, sort_keys=True) + '\n').encode()
        obj['bundle']['dsseEnvelope']['payload'] = base64.b64encode(pretty).decode()
        out = m.validate_capsule(obj, self.key, self.raw)
        self.assertIn('P1A2.STATEMENT.NONCANONICAL', self.codes(out))

    def test_assemble_delegates_to_p1a1_checker(self):
        src = json.loads(self.raw)
        src['statement']['predicate']['claimBoundary']['doesNotImply'] = []
        sig = self.bundle['bundle']['dsseEnvelope']['signatures'][0]['sig']
        with self.assertRaisesRegex(ValueError, 'P1A2.P1A1.UPSTREAM'):
            m.assemble_capsule((json.dumps(src, sort_keys=True) + '\n').encode(), sig, self.key)


if __name__ == '__main__':
    unittest.main()
