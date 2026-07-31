from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve()
TOOL = HERE.parents[1] / "tools" / "eigiib_extension_graph_check.py"
spec = importlib.util.spec_from_file_location("m0graph", TOOL)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


CANONICAL = ["Core"] + [f"E{i}" for i in range(1, 12)]


def base_manifest():
    nodes = []
    for i, nid in enumerate(CANONICAL):
        node = {
            "id": nid,
            "kind": "core" if nid == "Core" else "extension",
            "title": nid,
            "theme": "theme",
            "authority_key": "standard" if nid == "Core" else nid.lower(),
            "authority": "EIGIIB-STANDARD.md" if nid == "Core" else f"extensions/{nid}.md",
            "depends_on": [] if i == 0 else [CANONICAL[i - 1]],
            "consumes_authorities": [],
            "does_not_reprove": [],
        }
        if nid != "Core":
            node.update({
                "schema": f"schemas/{nid}.json",
                "checker": f"tools/{nid}.py",
                "registry_authority_key": f"r{nid.lower()}",
                "registry": f"conformance/{nid}.json",
            })
        nodes.append(node)
    return {
        "standard": "EIGIIB-M0-A1-1.0",
        "status": "structural",
        "authority": "conformance/extension-graph.json",
        "source_of_truth_for": ["functional extension graph"],
        "derived_fields": ["used_by"],
        "functional_layers": [
            {"id": "all", "label": "all", "description": "fixture", "nodes": CANONICAL[:]}
        ],
        "nodes": nodes,
        "hardening_profiles": [],
    }


class GraphTests(unittest.TestCase):
    def repo(self, mutate=None):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        m = base_manifest()
        if mutate:
            mutate(m)

        auth = {"standard": "EIGIIB-STANDARD.md", "extension_graph": "conformance/extension-graph.json"}
        required = ["standard", "extension_graph"]
        for n in m.get("nodes", []):
            if not isinstance(n, dict):
                continue
            k, p = n.get("authority_key"), n.get("authority")
            if isinstance(k, str) and isinstance(p, str):
                auth[k] = p
            rk, rp = n.get("registry_authority_key"), n.get("registry")
            if isinstance(rk, str) and isinstance(rp, str):
                auth[rk] = rp

        lines = ['standard = "EIGIIB-1.0"', 'required_authorities = [' +
                 ", ".join(json.dumps(x) for x in required) + "]", "", "[authorities]"]
        lines += [f"{k} = {json.dumps(v)}" for k, v in auth.items()]
        (root / "EIGIIB.toml").write_text("\n".join(lines) + "\n")

        for n in m.get("nodes", []):
            if not isinstance(n, dict):
                continue
            for key in ("authority", "schema", "checker", "registry"):
                rel = n.get(key)
                if isinstance(rel, str):
                    p = root / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text("{}\n" if p.suffix == ".json" else "# fixture\n")
        for hp in m.get("hardening_profiles", []):
            if not isinstance(hp, dict):
                continue
            for key in ("authority", "schema", "checker"):
                rel = hp.get(key)
                if isinstance(rel, str):
                    p = root / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text("{}\n" if p.suffix == ".json" else "# fixture\n")
            for rel in hp.get("tests", []):
                if isinstance(rel, str):
                    p = root / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text("# fixture\n")

        p = root / "conformance/extension-graph.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(m))
        return td, root, m

    def check(self, mutate=None):
        td, root, _ = self.repo(mutate)
        self.addCleanup(td.cleanup)
        return mod.Checker(root).run()

    def test_valid_graph(self):
        r = self.check()
        self.assertEqual("conformant", r["structural_result"])
        self.assertIn("E1", r["derived_used_by"]["Core"])

    def test_missing_required_node(self):
        r = self.check(lambda m: m["nodes"].pop())
        self.assertEqual("non-conformant", r["structural_result"])

    def test_duplicate_node(self):
        def mut(m): m["nodes"].append(dict(m["nodes"][0]))
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.NODES.DUPLICATE" for f in r["findings"]))

    def test_unresolved_dependency(self):
        def mut(m): m["nodes"][-1]["depends_on"] = ["NOPE"]
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.NODES.DEPENDS_REF" for f in r["findings"]))

    def test_cycle(self):
        def mut(m): m["nodes"][0]["depends_on"] = ["E11"]
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.GRAPH.CYCLE" for f in r["findings"]))

    def test_layer_duplicate_membership(self):
        def mut(m):
            m["functional_layers"].append({"id":"second","label":"second","description":"x","nodes":["E1"]})
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.LAYERS.MULTIPLE" for f in r["findings"]))

    def test_missing_artifact(self):
        td, root, _ = self.repo()
        self.addCleanup(td.cleanup)
        (root / "tools/E11.py").unlink()
        r = mod.Checker(root).run()
        self.assertTrue(any(f["code"] == "M0.NODES.PATH_MISSING" for f in r["findings"]))

    def test_authority_binding(self):
        td, root, _ = self.repo()
        self.addCleanup(td.cleanup)
        text = (root / "EIGIIB.toml").read_text().replace('e11 = "extensions/E11.md"', 'e11 = "extensions/WRONG.md"')
        (root / "EIGIIB.toml").write_text(text)
        r = mod.Checker(root).run()
        self.assertTrue(any(f["code"] == "M0.NODES.AUTHORITY_BINDING" for f in r["findings"]))

    def test_unknown_consumed_authority(self):
        def mut(m): m["nodes"][-1]["consumes_authorities"] = ["not-an-authority"]
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.NODES.CONSUMES_REF" for f in r["findings"]))

    def test_used_by_must_be_derived(self):
        def mut(m): m["nodes"][-1]["used_by"] = []
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.NODES.DERIVED_FIELD" for f in r["findings"]))

    def test_hardening_target_and_attachment(self):
        def mut(m):
            hp = {
                "id":"E11-H0.2","applies_to":"E11","authority":"extensions/h.md",
                "schema":"schemas/h.json","checker":"tools/h.py","tests":["tests/h.py"]
            }
            m["hardening_profiles"].append(hp)
            m["nodes"][-1]["hardening_profiles"]=["E11-H0.2"]
        r = self.check(mut)
        self.assertEqual("conformant", r["structural_result"])

    def test_hardening_wrong_target(self):
        def mut(m):
            hp = {
                "id":"H","applies_to":"E10","authority":"extensions/h.md",
                "schema":"schemas/h.json","checker":"tools/h.py","tests":["tests/h.py"]
            }
            m["hardening_profiles"].append(hp)
            m["nodes"][-1]["hardening_profiles"]=["H"]
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.NODES.HARDENING_TARGET" for f in r["findings"]))

    def test_unattached_hardening_rejected(self):
        def mut(m):
            hp = {
                "id":"H","applies_to":"E11","authority":"extensions/h.md",
                "schema":"schemas/h.json","checker":"tools/h.py","tests":["tests/h.py"]
            }
            m["hardening_profiles"].append(hp)
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.HARDENING.UNATTACHED" for f in r["findings"]))

    def test_forward_layer_dependency_rejected(self):
        def mut(m):
            m["functional_layers"] = [
                {"id":"early","label":"early","description":"x","nodes":["Core","E1"]},
                {"id":"late","label":"late","description":"x","nodes":[f"E{i}" for i in range(2,12)]},
            ]
            m["nodes"][1]["depends_on"] = ["E2"]
        r = self.check(mut)
        self.assertTrue(any(f["code"] == "M0.LAYERS.FORWARD_DEPENDENCY" for f in r["findings"]))


if __name__ == "__main__":
    unittest.main()
