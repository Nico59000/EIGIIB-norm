#!/usr/bin/env python3
"""Reference replay harness for M0-A4 portable vectors using repository-owned Python checkers."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-M0-A4-1.0"


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Replay:
    def __init__(self, root: Path, catalog: Path):
        self.root = root.resolve()
        self.catalog_path = catalog
        self.findings: list[Finding] = []
        self.vector_results: list[dict[str, Any]] = []

    def add(self, severity: str, code: str, message: str, path: str = "") -> None:
        self.findings.append(Finding(severity, code, path, message))

    def load_catalog(self) -> dict[str, Any] | None:
        p = (self.root / self.catalog_path).resolve(strict=False)
        try:
            p.relative_to(self.root)
        except ValueError:
            self.add("error", "M0A4.REPLAY.CATALOG_PATH", "catalog escapes repository root", str(self.catalog_path))
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("error", "M0A4.REPLAY.CATALOG", str(exc), str(self.catalog_path))
            return None

    @staticmethod
    def error_codes(result: dict[str, Any]) -> list[str]:
        findings = result.get("findings")
        if not isinstance(findings, list):
            return []
        return sorted({
            item.get("code")
            for item in findings
            if isinstance(item, dict) and item.get("severity") == "error" and isinstance(item.get("code"), str)
        })

    def run_a2(self, fixture: dict[str, Any], module) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "conformance").mkdir()
            result_dir = root / ".eigiib-results/components"
            result_dir.mkdir(parents=True)
            (root / "conformance/extension-graph.json").write_text(
                json.dumps(fixture["graph"]), encoding="utf-8"
            )
            for component_id, report in fixture["component_reports"].items():
                (result_dir / (component_id.lower() + ".json")).write_text(
                    json.dumps(report), encoding="utf-8"
                )
            return module.Aggregator(
                root,
                Path(".eigiib-results/components"),
                Path("conformance/extension-graph.json"),
            ).run()

    def run_a3(self, fixture: dict[str, Any], module) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "conformance").mkdir()
            (root / "conformance/interop-profiles.json").write_text(
                json.dumps(fixture["registry"]), encoding="utf-8"
            )
            authorities = fixture.get("authorities", [])
            lines = ["[authorities]"]
            for authority in authorities:
                lines.append(f'{authority} = "fixture/{authority}"')
            (root / "EIGIIB.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
            for rel, content in fixture.get("evidence_files", {}).items():
                path = Path(rel)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError(f"fixture evidence path escapes root: {rel}")
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            return module.Checker(
                root,
                Path("conformance/interop-profiles.json"),
                Path("EIGIIB.toml"),
            ).run()

    def run(self) -> dict[str, Any]:
        catalog = self.load_catalog()
        if catalog is None:
            return self.result()

        try:
            catalog_mod = load_module(self.root / "tools/eigiib_vector_catalog_check.py", "m0a4_catalog_replay")
            catalog_result = catalog_mod.Checker(self.root, self.catalog_path).run()
        except Exception as exc:
            self.add("error", "M0A4.REPLAY.CATALOG_CHECK", str(exc), "tools/eigiib_vector_catalog_check.py")
            return self.result()
        if catalog_result.get("structural_result") != "conformant":
            self.add("error", "M0A4.REPLAY.CATALOG_NONCONFORMANT", "vector catalog must pass M0-A4 structural checking before replay", str(self.catalog_path))
            return self.result()

        try:
            a2 = load_module(self.root / "tools/eigiib_aggregate.py", "m0a2_vector_replay")
            a3 = load_module(self.root / "tools/eigiib_interop_profiles_check.py", "m0a3_vector_replay")
        except Exception as exc:
            self.add("error", "M0A4.REPLAY.IMPORT", str(exc), "tools")
            return self.result()

        for vector in catalog.get("vectors", []):
            vid = vector["id"]
            contract = vector["contract"]
            fixture = vector["fixture"]
            expect = vector["expect"]
            try:
                if contract == "M0-A2":
                    observed = self.run_a2(fixture, a2)
                elif contract == "M0-A3":
                    observed = self.run_a3(fixture, a3)
                else:
                    raise ValueError(f"unsupported contract {contract}")
                observed_result = observed.get(expect["result_field"])
                observed_codes = self.error_codes(observed)
                passed = observed_result == expect["result"] and observed_codes == expect["error_codes"]
                self.vector_results.append({
                    "id": vid,
                    "contract": contract,
                    "passed": passed,
                    "observed_result": observed_result,
                    "observed_error_codes": observed_codes,
                })
                if not passed:
                    self.add(
                        "error",
                        "M0A4.REPLAY.MISMATCH",
                        f"expected {expect['result']!r}/{expect['error_codes']!r}, observed {observed_result!r}/{observed_codes!r}",
                        f"vector:{vid}",
                    )
            except Exception as exc:
                self.vector_results.append({
                    "id": vid,
                    "contract": contract,
                    "passed": False,
                    "observed_result": None,
                    "observed_error_codes": [],
                })
                self.add("error", "M0A4.REPLAY.EXCEPTION", str(exc), f"vector:{vid}")
        return self.result()

    def result(self) -> dict[str, Any]:
        failed = any(f.severity == "error" for f in self.findings)
        passed_count = sum(1 for item in self.vector_results if item.get("passed"))
        return {
            "tool": "eigiib-vector-reference-replay",
            "tool_version": TOOL_VERSION,
            "standard": STANDARD,
            "structural_result": "non-conformant" if failed else "conformant",
            "vector_count": len(self.vector_results),
            "passed": passed_count,
            "failed": len(self.vector_results) - passed_count,
            "vectors": self.vector_results,
            "findings": [asdict(f) for f in sorted(self.findings)],
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--catalog", default="conformance/conformance-vectors.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = Replay(Path(args.root), Path(args.catalog)).run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["structural_result"] == "non-conformant" else 0


if __name__ == "__main__":
    raise SystemExit(main())
