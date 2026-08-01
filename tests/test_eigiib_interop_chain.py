import copy
import json

from p1a4_test_support import P1A4Fixture, p1a4


class P1A4ManifestTests(P1A4Fixture):
    def test_valid_chain(self):
        out = self.validate()
        self.assertEqual(out["end_to_end_result"], "conformant")
        self.assertEqual([out["p1a1_replay_result"], out["p1a2_replay_result"], out["p1a3_replay_result"]],
                         ["conformant", "conformant", "conformant"])

    def test_extra_manifest_field(self):
        obj = copy.deepcopy(self.manifest); obj["extra"] = True
        self.assertIn("P1A4.MANIFEST.FIELD", self.codes(self.validate(obj)))

    def test_component_order(self):
        obj = copy.deepcopy(self.manifest); obj["components"][0], obj["components"][1] = obj["components"][1], obj["components"][0]
        self.assertIn("P1A4.COMPONENT.ORDER", self.codes(self.validate(obj)))

    def test_component_contract_path(self):
        obj = copy.deepcopy(self.manifest); obj["components"][0]["path"] = "other.json"; self.refresh(obj)
        self.assertIn("P1A4.COMPONENT.CONTRACT", self.codes(self.validate(obj)))

    def test_chain_identity(self):
        obj = copy.deepcopy(self.manifest); obj["replay"]["chainIdentity"]["digest"] = "f" * 64
        self.assertIn("P1A4.CHAIN.IDENTITY_MISMATCH", self.codes(self.validate(obj)))

    def test_weakened_boundary(self):
        obj = copy.deepcopy(self.manifest); obj["claimBoundary"]["doesNotImply"].pop(); self.refresh(obj)
        self.assertIn("P1A4.BOUNDARY.WEAKENED", self.codes(self.validate(obj)))

    def test_source_identity_mismatch(self):
        path = self.root / p1a4.COMPONENT_PATHS["m0-a2-report"]
        path.write_bytes(path.read_bytes() + b" ")
        self.assertIn("P1A4.COMPONENT.IDENTITY_MISMATCH", self.codes(self.validate()))

    def test_m0a2_p1a1_binding(self):
        path = self.root / p1a4.COMPONENT_PATHS["p1-a1-statement"]
        obj = json.loads(path.read_text()); obj["statement"]["predicate"]["aggregateReport"]["identity"]["digest"] = "f" * 64
        self._write_json(p1a4.COMPONENT_PATHS["p1-a1-statement"], obj)
        self.assertIn("P1A4.BINDING.M0A2_P1A1", self.codes(self.validate()))

    def test_p1a1_p1a2_binding(self):
        path = self.root / p1a4.COMPONENT_PATHS["p1-a2-bundle"]
        obj = json.loads(path.read_text()); obj["binding"]["p1A1Statement"]["digest"] = "f" * 64
        raw = self._write_json(p1a4.COMPONENT_PATHS["p1-a2-bundle"], obj)
        self.manifest["components"][2]["identity"] = p1a4.identity(raw); self.refresh(self.manifest)
        self.assertIn("P1A4.BINDING.P1A1_P1A2", self.codes(self.validate()))

    def test_p1a2_key_binding(self):
        path = self.root / p1a4.COMPONENT_PATHS["p1-a2-bundle"]
        obj = json.loads(path.read_text()); obj["binding"]["publicKeySpki"]["digest"] = "f" * 64
        raw = self._write_json(p1a4.COMPONENT_PATHS["p1-a2-bundle"], obj)
        self.manifest["components"][2]["identity"] = p1a4.identity(raw); self.refresh(self.manifest)
        self.assertIn("P1A4.BINDING.P1A2_KEY", self.codes(self.validate()))

    def test_p1a2_p1a3_binding(self):
        path = self.root / p1a4.COMPONENT_PATHS["p1-a3-signed-statement"]
        obj = json.loads(path.read_text()); obj["binding"]["p1A2Bundle"]["digest"] = "f" * 64
        self._write_json(p1a4.COMPONENT_PATHS["p1-a3-signed-statement"], obj)
        self.assertIn("P1A4.BINDING.P1A2_P1A3", self.codes(self.validate()))

    def test_signed_statement_and_receipt_bindings(self):
        path = self.root / p1a4.COMPONENT_PATHS["p1-a3-signed-statement"]
        obj = json.loads(path.read_text()); obj["signedStatement"]["identity"]["digest"] = "f" * 64
        obj["receipt"]["identity"]["digest"] = "e" * 64
        self._write_json(p1a4.COMPONENT_PATHS["p1-a3-signed-statement"], obj)
        codes = self.codes(self.validate())
        self.assertTrue({"P1A4.BINDING.SIGNED_STATEMENT", "P1A4.BINDING.RECEIPT"}.issubset(codes))

    def test_issuer_and_ts_bindings(self):
        path = self.root / p1a4.COMPONENT_PATHS["p1-a3-signed-statement"]
        obj = json.loads(path.read_text()); obj["signedStatement"]["issuerKeySpki"]["digest"] = "f" * 64
        obj["receipt"]["transparencyServiceKeySpki"]["digest"] = "e" * 64
        self._write_json(p1a4.COMPONENT_PATHS["p1-a3-signed-statement"], obj)
        codes = self.codes(self.validate())
        self.assertTrue({"P1A4.BINDING.ISSUER_KEY", "P1A4.BINDING.TS_KEY"}.issubset(codes))
