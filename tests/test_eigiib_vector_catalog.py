import importlib.util
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "tools" / "eigiib_vector_catalog_check.py"
spec = importlib.util.spec_from_file_location("vec", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def vector(vid, contract, fixture, result_field, result, codes=None):
    return {
        "id": vid,
        "contract": contract,
        "purpose": "test vector",
        "fixture_sha256": __import__("hashlib").sha256(mod.canonical_bytes(fixture)).hexdigest(),
        "fixture": fixture,
        "expect": {
            "result_field": result_field,
            "result": result,
            "error_codes": codes or [],
        },
    }


def a2_fixture():
    return {"graph": {}, "component_reports": {}}


def a3_fixture():
    return {"authorities": [], "registry": {}, "evidence_files": {}}


def base_catalog():
    return {
        "standard": "EIGIIB-M0-A4-1.0",
        "revision": "test",
        "canonicalization": "m0-a4-json-sha256-v1",
        "supported_contracts": ["M0-A2", "M0-A3"],
        "vectors": [
            vector("a2-ok", "M0-A2", a2_fixture(), "overall_result", "conformant"),
            vector("a3-ok", "M0-A3", a3_fixture(), "structural_result", "conformant"),
        ],
    }


def redigest(vector_obj):
    vector_obj["fixture_sha256"] = __import__("hashlib").sha256(mod.canonical_bytes(vector_obj["fixture"])).hexdigest()


class VectorCatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "conformance").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_obj(self, obj):
        (self.root / "conformance/conformance-vectors.json").write_text(json.dumps(obj))
        return mod.Checker(self.root, Path("conformance/conformance-vectors.json")).run()

    def assert_code(self, result, code):
        self.assertTrue(any(f["code"] == code for f in result["findings"]), result)

    def test_baseline_conformant(self):
        r = self.run_obj(base_catalog())
        self.assertEqual(r["structural_result"], "conformant")
        self.assertEqual(r["vector_count"], 2)
        self.assertEqual(r["contract_counts"], {"M0-A2": 1, "M0-A3": 1})

    def test_wrong_canonicalization_rejected(self):
        o = base_catalog(); o["canonicalization"] = "other"
        self.assert_code(self.run_obj(o), "M0A4.CANONICALIZATION")

    def test_contract_set_is_closed(self):
        o = base_catalog(); o["supported_contracts"] = ["M0-A2"]
        self.assert_code(self.run_obj(o), "M0A4.CONTRACTS")

    def test_duplicate_vector_id_rejected(self):
        o = base_catalog(); o["vectors"].append(deepcopy(o["vectors"][0]))
        self.assert_code(self.run_obj(o), "M0A4.VECTOR.DUPLICATE")

    def test_digest_mismatch_rejected(self):
        o = base_catalog(); o["vectors"][0]["fixture_sha256"] = "0" * 64
        self.assert_code(self.run_obj(o), "M0A4.VECTOR.DIGEST")

    def test_float_fixture_rejected(self):
        o = base_catalog(); o["vectors"][0]["fixture"]["graph"] = {"ratio": 1.5}; redigest(o["vectors"][0])
        self.assert_code(self.run_obj(o), "M0A4.VECTOR.FLOAT")

    def test_a2_adapter_shape_is_checked(self):
        o = base_catalog(); o["vectors"][0]["fixture"] = {"graph": {}}; redigest(o["vectors"][0])
        self.assert_code(self.run_obj(o), "M0A4.A2.FIELDS")

    def test_a2_report_items_are_objects(self):
        o = base_catalog(); o["vectors"][0]["fixture"]["component_reports"] = {"E2": "bad"}; redigest(o["vectors"][0])
        self.assert_code(self.run_obj(o), "M0A4.A2.REPORT_ITEM")

    def test_a3_adapter_shape_is_checked(self):
        o = base_catalog(); o["vectors"][1]["fixture"] = {"evidence_files": {}}; redigest(o["vectors"][1])
        self.assert_code(self.run_obj(o), "M0A4.A3.FIELDS")

    def test_a3_authorities_are_unique_strings(self):
        o = base_catalog(); o["vectors"][1]["fixture"]["authorities"] = ["e1", "e1"]; redigest(o["vectors"][1])
        self.assert_code(self.run_obj(o), "M0A4.A3.AUTHORITY_DUPLICATE")

    def test_result_field_is_contract_specific(self):
        o = base_catalog(); o["vectors"][0]["expect"]["result_field"] = "structural_result"
        self.assert_code(self.run_obj(o), "M0A4.VECTOR.RESULT_FIELD")

    def test_result_vocabulary_is_contract_specific(self):
        o = base_catalog(); o["vectors"][1]["expect"]["result"] = "incomplete"
        self.assert_code(self.run_obj(o), "M0A4.VECTOR.RESULT")

    def test_error_codes_must_be_sorted_unique(self):
        o = base_catalog(); o["vectors"][0]["expect"]["error_codes"] = ["Z", "A", "Z"]
        self.assert_code(self.run_obj(o), "M0A4.VECTOR.ERROR_CODES_ORDER")

    def test_a3_materialized_evidence_path_cannot_escape(self):
        o = base_catalog(); o["vectors"][1]["fixture"]["evidence_files"] = {"../x": "bad"}; redigest(o["vectors"][1])
        self.assert_code(self.run_obj(o), "M0A4.A3.EVIDENCE_PATH")

    def test_each_supported_contract_requires_coverage(self):
        o = base_catalog(); o["vectors"] = [o["vectors"][0]]
        self.assert_code(self.run_obj(o), "M0A4.CONTRACT.COVERAGE")


if __name__ == "__main__":
    unittest.main()
