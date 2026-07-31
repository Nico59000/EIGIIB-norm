#!/usr/bin/env python3
"""EIGIIB M0-A1 extension graph manifest checker.

Static only: validates the repository-local functional graph and its artifact
bindings. Reverse `used_by` edges are derived in the report and are forbidden
as stored manifest facts.
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-M0-A1-1.0"
REQUIRED_NODES = ["Core"] + [f"E{i}" for i in range(1, 12)]
ALLOWED_TOP = {
    "standard", "status", "authority", "source_of_truth_for", "derived_fields",
    "functional_layers", "nodes", "hardening_profiles",
}
DERIVED_NODE_FIELDS = {"used_by"}


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


class Checker:
    def __init__(self, root: Path, manifest: Path = Path("conformance/extension-graph.json")):
        self.root = root.resolve()
        self.manifest_path = manifest
        self.findings: list[Finding] = []
        self.obj: dict[str, Any] = {}
        self.profile: dict[str, Any] = {}
        self.reverse: dict[str, list[str]] = {}

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def confined(self, rel: str, code: str) -> Path | None:
        p = (self.root / rel).resolve(strict=False)
        try:
            p.relative_to(self.root)
        except ValueError:
            self.add("error", f"{code}.PATH", "path escapes repository", rel)
            return None
        return p

    def load(self) -> bool:
        p = self.confined(str(self.manifest_path), "M0.GRAPH")
        if p is None or not p.exists():
            self.add("error", "M0.GRAPH.MISSING", "extension graph manifest is missing", str(self.manifest_path))
            return False
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "M0.GRAPH.PARSE", str(exc), str(self.manifest_path))
            return False
        if not isinstance(obj, dict):
            self.add("error", "M0.GRAPH.TYPE", "manifest root must be an object", str(self.manifest_path))
            return False
        self.obj = obj

        profile_path = self.root / "EIGIIB.toml"
        try:
            self.profile = tomllib.loads(profile_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "M0.PROFILE.PARSE", str(exc), "EIGIIB.toml")
            return False
        return True

    def check_shape(self) -> None:
        unknown = set(self.obj) - ALLOWED_TOP
        for field in sorted(unknown):
            self.add("error", "M0.GRAPH.FIELD", f"unknown top-level field {field}", field)
        for field in ALLOWED_TOP:
            if field not in self.obj:
                self.add("error", "M0.GRAPH.REQUIRED", f"missing top-level field {field}", field)

        if self.obj.get("standard") != STANDARD:
            self.add("error", "M0.GRAPH.STANDARD", f"standard must be {STANDARD}", "standard")
        if self.obj.get("status") != "structural":
            self.add("error", "M0.GRAPH.STATUS", "status must be structural", "status")
        if self.obj.get("authority") != str(self.manifest_path):
            self.add("error", "M0.GRAPH.AUTHORITY", "authority must equal manifest path", "authority")
        if self.obj.get("derived_fields") != ["used_by"]:
            self.add("error", "M0.GRAPH.DERIVED", "derived_fields must contain only used_by", "derived_fields")

    @staticmethod
    def index(items: Any, label: str, add) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        if not isinstance(items, list):
            add("error", f"M0.{label}.TYPE", f"{label.lower()} must be an array", label.lower())
            return out
        for i, item in enumerate(items):
            loc = f"{label.lower()}[{i}]"
            if not isinstance(item, dict):
                add("error", f"M0.{label}.ITEM", "item must be an object", loc)
                continue
            ident = item.get("id")
            if not isinstance(ident, str) or not ident:
                add("error", f"M0.{label}.ID", "item id must be a non-empty string", loc)
                continue
            if ident in out:
                add("error", f"M0.{label}.DUPLICATE", f"duplicate id {ident}", loc)
                continue
            out[ident] = item
        return out

    def check_nodes(self) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        nodes = self.index(self.obj.get("nodes"), "NODES", self.add)
        profiles = self.index(self.obj.get("hardening_profiles"), "HARDENING", self.add)

        missing = [n for n in REQUIRED_NODES if n not in nodes]
        extra = [n for n in nodes if n not in REQUIRED_NODES]
        for n in missing:
            self.add("error", "M0.NODES.REQUIRED", f"required node {n} missing", "nodes")
        for n in extra:
            self.add("error", "M0.NODES.EXTRA", f"unexpected canonical node {n}", f"node:{n}")

        authorities = self.profile.get("authorities", {})
        if not isinstance(authorities, dict):
            self.add("error", "M0.PROFILE.AUTHORITIES", "[authorities] must be a table", "EIGIIB.toml")
            authorities = {}

        for nid, node in nodes.items():
            loc = f"node:{nid}"
            if DERIVED_NODE_FIELDS & set(node):
                self.add("error", "M0.NODES.DERIVED_FIELD", "used_by is derived and must not be stored", loc)

            expected_kind = "core" if nid == "Core" else "extension"
            if node.get("kind") != expected_kind:
                self.add("error", "M0.NODES.KIND", f"{nid} kind must be {expected_kind}", loc)

            for key in ("title", "theme", "authority_key", "authority"):
                if not isinstance(node.get(key), str) or not node[key]:
                    self.add("error", "M0.NODES.FIELD", f"{key} must be a non-empty string", loc)

            auth_key = node.get("authority_key")
            authority = node.get("authority")
            if isinstance(auth_key, str) and authorities.get(auth_key) != authority:
                self.add("error", "M0.NODES.AUTHORITY_BINDING",
                         f"authority {auth_key!r} does not match EIGIIB.toml", loc)

            for path_key in ("authority", "schema", "checker", "registry"):
                rel = node.get(path_key)
                if rel is None:
                    continue
                if not isinstance(rel, str) or not rel:
                    self.add("error", "M0.NODES.PATH_TYPE", f"{path_key} must be a non-empty string", loc)
                    continue
                p = self.confined(rel, "M0.NODES")
                if p is not None and not p.is_file():
                    self.add("error", "M0.NODES.PATH_MISSING", f"{path_key} path does not exist", rel)

            reg_key = node.get("registry_authority_key")
            registry = node.get("registry")
            if reg_key is not None or registry is not None:
                if not isinstance(reg_key, str) or not isinstance(registry, str):
                    self.add("error", "M0.NODES.REGISTRY_BINDING",
                             "registry and registry_authority_key must appear together", loc)
                elif authorities.get(reg_key) != registry:
                    self.add("error", "M0.NODES.REGISTRY_AUTHORITY",
                             f"registry authority {reg_key!r} does not match EIGIIB.toml", loc)

            deps = node.get("depends_on", [])
            if not isinstance(deps, list) or any(not isinstance(x, str) for x in deps):
                self.add("error", "M0.NODES.DEPENDS_TYPE", "depends_on must be an array of ids", loc)
            else:
                for dep in deps:
                    if dep not in nodes:
                        self.add("error", "M0.NODES.DEPENDS_REF", f"dependency {dep} does not resolve", loc)
                    if dep == nid:
                        self.add("error", "M0.NODES.SELF_DEPENDENCY", "node cannot depend on itself", loc)

            consumes = node.get("consumes_authorities", [])
            if not isinstance(consumes, list) or any(not isinstance(x, str) for x in consumes):
                self.add("error", "M0.NODES.CONSUMES_TYPE", "consumes_authorities must be an array of authority keys", loc)
            else:
                for key in consumes:
                    if key not in authorities:
                        self.add("error", "M0.NODES.CONSUMES_REF", f"authority {key} does not resolve", loc)

            nonreprove = node.get("does_not_reprove", [])
            if not isinstance(nonreprove, list) or any(not isinstance(x, str) or not x for x in nonreprove):
                self.add("error", "M0.NODES.NONREPROVE", "does_not_reprove must be an array of non-empty strings", loc)

            hp = node.get("hardening_profiles", [])
            if hp is not None:
                if not isinstance(hp, list) or any(not isinstance(x, str) for x in hp):
                    self.add("error", "M0.NODES.HARDENING_TYPE", "hardening_profiles must be an array of ids", loc)
                else:
                    for hid in hp:
                        if hid not in profiles:
                            self.add("error", "M0.NODES.HARDENING_REF", f"hardening profile {hid} does not resolve", loc)
                        elif profiles[hid].get("applies_to") != nid:
                            self.add("error", "M0.NODES.HARDENING_TARGET",
                                     f"hardening profile {hid} does not apply to {nid}", loc)

        for hid, hp in profiles.items():
            loc = f"hardening:{hid}"
            target = hp.get("applies_to")
            if target not in nodes or target == "Core":
                self.add("error", "M0.HARDENING.TARGET", f"invalid applies_to target {target}", loc)
            for path_key in ("authority", "schema", "checker"):
                rel = hp.get(path_key)
                if not isinstance(rel, str) or not rel:
                    self.add("error", "M0.HARDENING.FIELD", f"{path_key} must be a non-empty string", loc)
                    continue
                p = self.confined(rel, "M0.HARDENING")
                if p is not None and not p.is_file():
                    self.add("error", "M0.HARDENING.PATH_MISSING", f"{path_key} path does not exist", rel)
            test_paths = hp.get("tests")
            if not isinstance(test_paths, list) or not test_paths or any(not isinstance(x, str) or not x for x in test_paths):
                self.add("error", "M0.HARDENING.TESTS", "tests must be a non-empty array of paths", loc)
            else:
                for rel in test_paths:
                    p = self.confined(rel, "M0.HARDENING")
                    if p is not None and not p.is_file():
                        self.add("error", "M0.HARDENING.PATH_MISSING", "tests path does not exist", rel)

        for hid, hp in profiles.items():
            target = hp.get("applies_to")
            if target in nodes:
                attached = nodes[target].get("hardening_profiles", [])
                if hid not in attached:
                    self.add("error", "M0.HARDENING.UNATTACHED",
                             f"hardening profile {hid} is not attached by target node {target}", f"hardening:{hid}")

        return nodes, profiles

    def check_layers(self, nodes: dict[str, dict[str, Any]]) -> None:
        layers = self.obj.get("functional_layers")
        if not isinstance(layers, list):
            self.add("error", "M0.LAYERS.TYPE", "functional_layers must be an array", "functional_layers")
            return
        seen_layer_ids: set[str] = set()
        membership: dict[str, str] = {}
        for i, layer in enumerate(layers):
            loc = f"functional_layers[{i}]"
            if not isinstance(layer, dict):
                self.add("error", "M0.LAYERS.ITEM", "layer must be an object", loc)
                continue
            lid = layer.get("id")
            if not isinstance(lid, str) or not lid:
                self.add("error", "M0.LAYERS.ID", "layer id must be non-empty", loc)
                continue
            if lid in seen_layer_ids:
                self.add("error", "M0.LAYERS.DUPLICATE", f"duplicate layer id {lid}", loc)
            seen_layer_ids.add(lid)
            members = layer.get("nodes")
            if not isinstance(members, list) or not members:
                self.add("error", "M0.LAYERS.NODES", "layer nodes must be a non-empty array", loc)
                continue
            for nid in members:
                if nid not in nodes:
                    self.add("error", "M0.LAYERS.REF", f"layer node {nid} does not resolve", loc)
                    continue
                if nid in membership:
                    self.add("error", "M0.LAYERS.MULTIPLE",
                             f"node {nid} appears in more than one functional layer", loc)
                membership[nid] = lid
        for nid in nodes:
            if nid not in membership:
                self.add("error", "M0.LAYERS.MISSING", f"node {nid} is not assigned to a functional layer", f"node:{nid}")

        layer_order = {layer.get("id"): i for i, layer in enumerate(layers) if isinstance(layer, dict) and isinstance(layer.get("id"), str)}
        for nid, node in nodes.items():
            here = layer_order.get(membership.get(nid))
            if here is None:
                continue
            for dep in node.get("depends_on", []):
                dep_layer = layer_order.get(membership.get(dep))
                if dep_layer is not None and dep_layer > here:
                    self.add("error", "M0.LAYERS.FORWARD_DEPENDENCY",
                             f"{nid} depends on later functional layer node {dep}", f"node:{nid}")

    def check_acyclic(self, nodes: dict[str, dict[str, Any]]) -> None:
        graph = {nid: [d for d in node.get("depends_on", []) if d in nodes] for nid, node in nodes.items()}
        color = {nid: 0 for nid in graph}
        stack: list[str] = []

        def visit(nid: str) -> None:
            color[nid] = 1
            stack.append(nid)
            for dep in graph[nid]:
                if color[dep] == 0:
                    visit(dep)
                elif color[dep] == 1:
                    try:
                        start = stack.index(dep)
                        cycle = stack[start:] + [dep]
                    except ValueError:
                        cycle = [dep, nid, dep]
                    self.add("error", "M0.GRAPH.CYCLE", "dependency cycle: " + " -> ".join(cycle), f"node:{nid}")
            stack.pop()
            color[nid] = 2

        for nid in graph:
            if color[nid] == 0:
                visit(nid)

        reverse = {nid: [] for nid in graph}
        for nid, deps in graph.items():
            for dep in deps:
                reverse[dep].append(nid)
        self.reverse = {nid: sorted(vals, key=lambda x: (len(x), x)) for nid, vals in reverse.items()}

    def check_profile_binding(self) -> None:
        authorities = self.profile.get("authorities", {})
        required = self.profile.get("required_authorities", [])
        manifest_key = "extension_graph"
        manifest_path = str(self.manifest_path)
        if authorities.get(manifest_key) != manifest_path:
            self.add("error", "M0.PROFILE.GRAPH_AUTHORITY",
                     f"EIGIIB.toml must bind {manifest_key} to {manifest_path}", "EIGIIB.toml")
        if manifest_key not in required:
            self.add("error", "M0.PROFILE.GRAPH_REQUIRED",
                     "extension_graph must be a required authority", "EIGIIB.toml")

    def run(self) -> dict[str, Any]:
        if self.load():
            self.check_shape()
            nodes, _profiles = self.check_nodes()
            self.check_layers(nodes)
            self.check_acyclic(nodes)
            self.check_profile_binding()
        errors = any(f.severity == "error" for f in self.findings)
        return {
            "tool": "eigiib_extension_graph_check.py",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if errors else "conformant",
            "node_count": len(self.obj.get("nodes", [])) if isinstance(self.obj.get("nodes"), list) else 0,
            "hardening_profile_count": len(self.obj.get("hardening_profiles", [])) if isinstance(self.obj.get("hardening_profiles"), list) else 0,
            "derived_used_by": self.reverse,
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--manifest", default="conformance/extension-graph.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = Checker(Path(args.root), Path(args.manifest)).run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
