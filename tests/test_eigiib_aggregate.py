import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "tools" / "eigiib_aggregate.py"
spec = importlib.util.spec_from_file_location("agg", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def graph():
    return {
        "nodes": [
            {"id": "Core"},
            {"id": "E1"},
            {"id": "E2", "checker": "tools/eigiib_check.py"},
            {"id": "E3", "checker": "tools/eigiib_provenance_check.py"},
        ],
        "hardening_profiles": [
            {"id": "E3-H0.2", "checker": "tools/eigiib_provenance_hardening.py"}
        ],
    }


def report(*, structural="conformant", overall=None, result=None, hardening=None, findings=None):
    obj = {
        "tool": "x",
        "tool_version": "1",
        "standard": "S",
        "findings": findings or [],
    }
    if overall is not None:
        obj["overall_result"] = overall
    elif result is not None:
        obj["result"] = result
    elif hardening is not None:
        obj["hardening_result"] = hardening
    else:
        obj["structural_result"] = structural
    return obj


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "conformance").mkdir()
        (self.root / ".eigiib-results/components").mkdir(parents=True)
        (self.root / "conformance/extension-graph.json").write_text(json.dumps(graph()))

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, cid, obj):
        p = self.root / ".eigiib-results/components" / (cid.lower() + ".json")
        p.write_text(json.dumps(obj))

    def fill(self, *, e2="conformant"):
        self.write("M0-A1", report())
        self.write("E2", report(overall=e2))
        self.write("E3", report())
        self.write("E3-H0.2", report())

    def run_obj(self):
        return mod.Aggregator(
            self.root,
            Path(".eigiib-results/components"),
            Path("conformance/extension-graph.json"),
        ).run()

    def test_expected_ids_derived_from_graph(self):
        a = mod.Aggregator(self.root, Path(".eigiib-results/components"), Path("conformance/extension-graph.json"))
        self.assertEqual(a.expected_ids(graph()), ["M0-A1", "E2", "E3", "E3-H0.2"])

    def test_all_conformant(self):
        self.fill()
        r = self.run_obj()
        self.assertEqual(r["overall_result"], "conformant")
        self.assertEqual(r["summary"]["expected"], 4)
        self.assertEqual(r["summary"]["pass"], 4)

    def test_e2_documented_deviation_is_preserved(self):
        self.fill(e2="conformant-with-documented-deviations")
        r = self.run_obj()
        self.assertEqual(r["overall_result"], "conformant-with-documented-deviations")
        self.assertEqual(r["summary"]["qualified"], 1)

    def test_legacy_result_carrier_is_explicitly_supported(self):
        self.fill()
        self.write("E3", report(result="conformant"))
        r = self.run_obj()
        c = next(x for x in r["components"] if x["id"] == "E3")
        self.assertEqual(c["result_field"], "result")
        self.assertEqual(c["classification"], "pass")

    def test_hardening_result_carrier_is_explicitly_supported(self):
        self.fill()
        self.write("E3-H0.2", report(hardening="conformant"))
        r = self.run_obj()
        c = next(x for x in r["components"] if x["id"] == "E3-H0.2")
        self.assertEqual(c["result_field"], "hardening_result")
        self.assertEqual(c["classification"], "pass")

    def test_missing_report_is_incomplete_not_component_failure(self):
        self.fill()
        (self.root / ".eigiib-results/components/e3.json").unlink()
        r = self.run_obj()
        self.assertEqual(r["overall_result"], "incomplete")
        self.assertTrue(any(f["code"] == "M0A2.RESULT.MISSING" for f in r["findings"]))

    def test_component_failure_propagates(self):
        self.fill()
        self.write("E3", report(structural="non-conformant"))
        self.assertEqual(self.run_obj()["overall_result"], "non-conformant")

    def test_incomplete_component_propagates_without_success(self):
        self.fill(e2="partially-evaluated")
        self.assertEqual(self.run_obj()["overall_result"], "incomplete")

    def test_unsupported_result_field_rejected(self):
        self.fill()
        self.write("E3", {"tool": "x", "tool_version": "1", "standard": "S", "findings": []})
        r = self.run_obj()
        self.assertEqual(r["overall_result"], "non-conformant")
        self.assertTrue(any(f["code"] == "M0A2.RESULT.FIELD" for f in r["findings"]))

    def test_unexpected_json_rejected(self):
        self.fill()
        (self.root / ".eigiib-results/components/stale.json").write_text("{}")
        r = self.run_obj()
        self.assertEqual(r["overall_result"], "non-conformant")
        self.assertTrue(any(f["code"] == "M0A2.RESULTS.EXTRA" for f in r["findings"]))

    def test_hash_and_size_bind_exact_report(self):
        self.fill()
        r = self.run_obj()
        c = next(x for x in r["components"] if x["id"] == "E3")
        self.assertEqual(len(c["sha256"]), 64)
        self.assertGreater(c["bytes"], 0)

    def test_only_finding_counts_are_copied(self):
        self.fill()
        self.write("E3", report(findings=[{"severity": "warning", "code": "W", "path": "", "message": "detail remains in owner"}]))
        r = self.run_obj()
        c = next(x for x in r["components"] if x["id"] == "E3")
        self.assertEqual(c["finding_counts"]["warning"], 1)
        self.assertNotIn("detail remains in owner", json.dumps(r))

    def test_malformed_json_is_incomplete(self):
        self.fill()
        (self.root / ".eigiib-results/components/e3.json").write_text("{")
        r = self.run_obj()
        self.assertEqual(r["overall_result"], "incomplete")
        self.assertTrue(any(f["code"] == "M0A2.RESULT.PARSE" for f in r["findings"]))

    def test_results_path_confined(self):
        r = mod.Aggregator(self.root, Path("../escape"), Path("conformance/extension-graph.json")).run()
        self.assertEqual(r["overall_result"], "non-conformant")
        self.assertTrue(any(f["code"] == "M0A2.RESULTS.PATH" for f in r["findings"]))


if __name__ == "__main__":
    unittest.main()
