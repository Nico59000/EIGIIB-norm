#!/usr/bin/env python3
"""Materialize and replay the exact historical E14-A5-F1 authority."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E15-A1-HISTORICAL-E14-REPLAY-1.0"
SOURCE_COMMIT = "472e14fbb3d92205eabf10438e90295e19125ea4"

COMPONENTS = {
    "e14": ("tools/eigiib_confidential_evidence_check.py", [".", "--json"], "tests/fixtures/e14-a1/expected-report.json"),
    "e14-a2": ("tools/eigiib_disclosure_authorization_check.py", [".", "--json"], "tests/fixtures/e14-a2/expected-report.json"),
    "e14-a3": ("tools/eigiib_correlation_control_check.py", [".", "--json"], "tests/fixtures/e14-a3/expected-report.json"),
    "e14-a4": ("tools/eigiib_disclosure_revocation_check.py", [".", "--json"], "tests/fixtures/e14-a4/expected-report.json"),
    "e14-a5": ("tools/eigiib_e14_release_check.py", [".", "--json"], "tests/fixtures/e14-a5/expected-release-report.json"),
}
MATRIX = ("tools/eigiib_e14_release_matrix.py", [".", "--json"], "tests/fixtures/e14-a5/expected-matrix-report.json")


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def run_command(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)


def parse_json_output(proc: subprocess.CompletedProcess[str], label: str) -> dict[str, Any]:
    if proc.returncode != 0:
        raise RuntimeError(f"{label} exited {proc.returncode}: {proc.stderr}")
    value = json.loads(proc.stdout)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} did not emit a JSON object")
    return value


def safe_extract(archive: Path, target: Path) -> None:
    with tarfile.open(archive, "r:") as tf:
        tf.extractall(target, filter="data")


def replay(root: Path, source_commit: str = SOURCE_COMMIT, output_dir: Path | None = None,
           matrix_output: Path | None = None) -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []
    component_results: dict[str, str] = {}
    reports: dict[str, dict[str, Any]] = {}
    matrix_report: dict[str, Any] | None = None

    exact = run_command(["git", "rev-parse", "--verify", f"{source_commit}^{{commit}}"], root)
    if exact.returncode != 0 or exact.stdout.strip() != source_commit:
        findings.append(Finding("error", "E15A1.HISTORY.SOURCE", "", "exact E14 source commit is unavailable"))
    ancestor = run_command(["git", "merge-base", "--is-ancestor", source_commit, "HEAD"], root)
    if ancestor.returncode != 0:
        findings.append(Finding("error", "E15A1.HISTORY.ANCESTRY", "", "E14 source commit is not an ancestor of HEAD"))

    if not findings:
        with tempfile.TemporaryDirectory(prefix="eigiib-e14-history-") as td:
            td_path = Path(td)
            archive = td_path / "e14.tar"
            tree = td_path / "tree"
            tree.mkdir()
            archived = run_command(["git", "archive", "--format=tar", f"--output={archive}", source_commit], root)
            if archived.returncode != 0:
                findings.append(Finding("error", "E15A1.HISTORY.ARCHIVE", "", archived.stderr.strip()))
            else:
                try:
                    safe_extract(archive, tree)
                except Exception as exc:
                    findings.append(Finding("error", "E15A1.HISTORY.EXTRACT", "", str(exc)))

            if not findings:
                for cid, (tool, args, fixture) in COMPONENTS.items():
                    try:
                        report = parse_json_output(run_command([sys.executable, tool, *args], tree), cid)
                        expected = json.loads((tree / fixture).read_text(encoding="utf-8"))
                        if report != expected:
                            raise RuntimeError("report differs from frozen fixture")
                        reports[cid] = report
                        component_results[cid] = "conformant"
                    except Exception as exc:
                        findings.append(Finding("error", "E15A1.HISTORY.COMPONENT", cid, str(exc)))
                        component_results[cid] = "non-conformant"
                try:
                    tool, args, fixture = MATRIX
                    matrix_report = parse_json_output(run_command([sys.executable, tool, *args], tree), "e14-a5-matrix")
                    expected = json.loads((tree / fixture).read_text(encoding="utf-8"))
                    if matrix_report != expected:
                        raise RuntimeError("matrix differs from frozen fixture")
                    component_results["e14-a5-matrix"] = "conformant"
                except Exception as exc:
                    findings.append(Finding("error", "E15A1.HISTORY.MATRIX", "e14-a5-matrix", str(exc)))
                    component_results["e14-a5-matrix"] = "non-conformant"

    if output_dir is not None and reports:
        target = (root / output_dir).resolve() if not output_dir.is_absolute() else output_dir.resolve()
        target.mkdir(parents=True, exist_ok=True)
        for cid, report in reports.items():
            (target / f"{cid}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if "e14-a5" in reports:
            (target / "e14-a5-f1.json").write_text(
                json.dumps(reports["e14-a5"], indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            component_results["e14-a5-f1"] = "conformant"
    if matrix_output is not None and matrix_report is not None:
        target = (root / matrix_output).resolve() if not matrix_output.is_absolute() else matrix_output.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(matrix_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    overall = "non-conformant" if any(f.severity == "error" for f in findings) else "conformant"
    return {
        "tool": "eigiib-historical-e14-replay",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "source_commit": source_commit,
        "materialization": "git-archive-isolated-tree",
        "ancestry_result": "conformant" if ancestor.returncode == 0 else "non-conformant",
        "component_results": component_results,
        "overall_result": overall,
        "findings": [asdict(f) for f in sorted(findings)],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--source-commit", default=SOURCE_COMMIT)
    parser.add_argument("--output-dir")
    parser.add_argument("--matrix-output")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = replay(
        Path(args.root),
        args.source_commit,
        Path(args.output_dir) if args.output_dir else None,
        Path(args.matrix_output) if args.matrix_output else None,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
