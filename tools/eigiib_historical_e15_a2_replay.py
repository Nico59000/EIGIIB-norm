#!/usr/bin/env python3
"""Materialize and replay the exact historical E15-A2 authority."""
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
STANDARD = "EIGIIB-E15-A3-HISTORICAL-E15-A2-REPLAY-1.0"
SOURCE_COMMIT = "25988d80571f0f8d3587d976810a2dd8e0ce2328"


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


def replay(root: Path, source_commit: str = SOURCE_COMMIT) -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []
    historical_e14_result = "non-conformant"
    e15_a1_result = "non-conformant"
    e15_a2_result = "non-conformant"
    e15_a2_tests_result = "non-conformant"

    exact = run_command(["git", "rev-parse", "--verify", f"{source_commit}^{{commit}}"], root)
    if exact.returncode != 0 or exact.stdout.strip() != source_commit:
        findings.append(Finding("error", "E15A3.HISTORY.SOURCE", "", "exact E15-A2 source commit is unavailable"))
    ancestor = run_command(["git", "merge-base", "--is-ancestor", source_commit, "HEAD"], root)
    if ancestor.returncode != 0:
        findings.append(Finding("error", "E15A3.HISTORY.ANCESTRY", "", "E15-A2 source commit is not an ancestor of HEAD"))

    if not findings:
        with tempfile.TemporaryDirectory(prefix="eigiib-e15-a2-history-") as td:
            td_path = Path(td)
            archive = td_path / "e15-a2.tar"
            tree = td_path / "tree"
            tree.mkdir()
            archived = run_command(["git", "archive", "--format=tar", f"--output={archive}", source_commit], root)
            if archived.returncode != 0:
                findings.append(Finding("error", "E15A3.HISTORY.ARCHIVE", "", archived.stderr.strip()))
            else:
                try:
                    safe_extract(archive, tree)
                except Exception as exc:
                    findings.append(Finding("error", "E15A3.HISTORY.EXTRACT", "", str(exc)))

            if not findings:
                try:
                    parent_history_tool = tree / "tools/eigiib_historical_e15_a1_replay.py"
                    parent_report = parse_json_output(
                        run_command([sys.executable, str(parent_history_tool), str(root), "--json"], root),
                        "historical-e15-a1",
                    )
                    if parent_report.get("overall_result") != "conformant":
                        raise RuntimeError("historical E15-A1 replay is non-conformant")
                    historical_e14_result = "conformant" if parent_report.get("historical_e14_result") == "conformant" else "non-conformant"
                    e15_a1_result = "conformant" if parent_report.get("e15_a1_result") == "conformant" else "non-conformant"
                    history_rel = Path(".eigiib-runtime/historical-e15-a1-report.json")
                    history_path = tree / history_rel
                    history_path.parent.mkdir(parents=True, exist_ok=True)
                    history_path.write_text(json.dumps(parent_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                except Exception as exc:
                    findings.append(Finding("error", "E15A3.HISTORY.E15A1", "historical-e15-a1", str(exc)))

                if historical_e14_result == e15_a1_result == "conformant":
                    try:
                        checker = tree / "tools/eigiib_delivery_evidence_check.py"
                        report = parse_json_output(
                            run_command([
                                sys.executable, str(checker), str(tree),
                                "--history-report", history_rel.as_posix(), "--json",
                            ], tree),
                            "e15-a2",
                        )
                        expected = json.loads((tree / "tests/fixtures/e15-a2/expected-report.json").read_text(encoding="utf-8"))
                        if report != expected:
                            raise RuntimeError("E15-A2 report differs from frozen fixture")
                        e15_a2_result = "conformant"
                    except Exception as exc:
                        findings.append(Finding("error", "E15A3.HISTORY.E15A2", "e15-a2", str(exc)))

                try:
                    proc = run_command([sys.executable, "-m", "unittest", "-v", "tests/test_eigiib_delivery_evidence.py"], tree)
                    if proc.returncode != 0:
                        raise RuntimeError(proc.stderr or proc.stdout)
                    e15_a2_tests_result = "conformant"
                except Exception as exc:
                    findings.append(Finding("error", "E15A3.HISTORY.TESTS", "e15-a2-tests", str(exc)))

    overall = "non-conformant" if any(f.severity == "error" for f in findings) else "conformant"
    return {
        "tool": "eigiib-historical-e15-a2-replay",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "source_commit": source_commit,
        "materialization": "git-archive-isolated-tree",
        "ancestry_result": "conformant" if ancestor.returncode == 0 else "non-conformant",
        "historical_e14_result": historical_e14_result,
        "e15_a1_result": e15_a1_result,
        "e15_a2_result": e15_a2_result,
        "e15_a2_tests_result": e15_a2_tests_result,
        "overall_result": overall,
        "findings": [asdict(f) for f in sorted(findings)],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--source-commit", default=SOURCE_COMMIT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = replay(Path(args.root), args.source_commit)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
