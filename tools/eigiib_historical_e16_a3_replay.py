#!/usr/bin/env python3
"""Materialize and replay the exact historical E16-A3 authority."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-E16-A4-HISTORICAL-E16-A3-REPLAY-1.0"
SOURCE_COMMIT = "74cb64ebcb1b51b0a035e755be413dbd2a7e9e3e"


@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


def run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def parsed(proc: subprocess.CompletedProcess[str], label: str) -> dict[str, Any]:
    if proc.returncode:
        raise RuntimeError(f"{label} exited {proc.returncode}: {proc.stderr or proc.stdout}")
    value = json.loads(proc.stdout)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} did not emit an object")
    return value


def replay(root: Path, source_commit: str = SOURCE_COMMIT) -> dict[str, Any]:
    root = root.resolve()
    findings: list[Finding] = []
    results = {
        "e16_a2_history_result": "non-conformant",
        "e16_a3_result": "non-conformant",
        "e16_a3_tests_result": "non-conformant",
    }
    exact = run(["git", "rev-parse", "--verify", f"{source_commit}^{{commit}}"], root)
    ancestor = run(["git", "merge-base", "--is-ancestor", source_commit, "HEAD"], root)
    if exact.returncode or exact.stdout.strip() != source_commit:
        findings.append(Finding("error", "E16A4.HISTORY.SOURCE", "", "exact E16-A3 source commit is unavailable"))
    if ancestor.returncode:
        findings.append(Finding("error", "E16A4.HISTORY.ANCESTRY", "", "E16-A3 source commit is not an ancestor of HEAD"))

    if not findings:
        with tempfile.TemporaryDirectory(prefix="eigiib-e16-a3-history-") as td_raw:
            td = Path(td_raw)
            archive = td / "tree.tar"
            tree = td / "tree"
            tree.mkdir()
            proc = run(["git", "archive", "--format=tar", f"--output={archive}", source_commit], root)
            if proc.returncode:
                findings.append(Finding("error", "E16A4.HISTORY.ARCHIVE", "", proc.stderr.strip()))
            else:
                try:
                    with tarfile.open(archive, "r:") as tf:
                        tf.extractall(tree, filter="data")
                except Exception as exc:
                    findings.append(Finding("error", "E16A4.HISTORY.EXTRACT", "", str(exc)))

            if not findings:
                try:
                    a2_history = parsed(
                        run(
                            [
                                sys.executable,
                                str(tree / "tools/eigiib_historical_e16_a2_replay.py"),
                                str(root),
                                "--json",
                            ],
                            root,
                        ),
                        "historical-e16-a2",
                    )
                    if a2_history.get("overall_result") != "conformant":
                        raise RuntimeError("historical E16-A2 replay is non-conformant")
                    results["e16_a2_history_result"] = "conformant"

                    rel = Path(".eigiib-runtime/e16-a2-history.json")
                    history_path = tree / rel
                    history_path.parent.mkdir(parents=True, exist_ok=True)
                    history_path.write_text(
                        json.dumps(a2_history, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    a3 = parsed(
                        run(
                            [
                                sys.executable,
                                str(tree / "tools/eigiib_retention_readback_restore_check.py"),
                                str(tree),
                                "--history-report",
                                rel.as_posix(),
                                "--json",
                            ],
                            tree,
                        ),
                        "e16-a3",
                    )
                    expected = json.loads(
                        (tree / "tests/fixtures/e16-a3/expected-report.json").read_text(encoding="utf-8")
                    )
                    if a3 != expected:
                        raise RuntimeError("E16-A3 report differs from frozen fixture")
                    results["e16_a3_result"] = "conformant"
                except Exception as exc:
                    findings.append(Finding("error", "E16A4.HISTORY.E16A3", "e16-a3", str(exc)))

                try:
                    proc = run(
                        [
                            sys.executable,
                            "-m",
                            "unittest",
                            "-v",
                            "tests/test_eigiib_retention_readback_restore.py",
                        ],
                        tree,
                    )
                    if proc.returncode:
                        raise RuntimeError(proc.stderr or proc.stdout)
                    results["e16_a3_tests_result"] = "conformant"
                except Exception as exc:
                    findings.append(Finding("error", "E16A4.HISTORY.TESTS", "e16-a3-tests", str(exc)))

    overall = (
        "non-conformant"
        if findings or any(value != "conformant" for value in results.values())
        else "conformant"
    )
    return {
        "tool": "eigiib-historical-e16-a3-replay",
        "tool_version": TOOL_VERSION,
        "standard": STANDARD,
        "source_commit": source_commit,
        "materialization": "git-archive-isolated-tree",
        "ancestry_result": "conformant" if ancestor.returncode == 0 else "non-conformant",
        **results,
        "overall_result": overall,
        "findings": [asdict(item) for item in sorted(findings)],
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
