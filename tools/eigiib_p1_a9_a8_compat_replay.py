#!/usr/bin/env python3
"""Replay the fixed P1-A8 bundle with an append-only A7 runner policy succession."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PLATFORMS = ("ubuntu-24.04", "macos-15", "windows-2025")


def _run_json(command: list[str], cwd: Path, env: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, env=env, check=True, capture_output=True, text=True)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"offline replay did not emit JSON: {command[1]}") from exc
    if not isinstance(value, dict):
        raise ValueError("offline replay result is not an object")
    return value


def _offline_replay(source: Path, platform: str, selected_policy: Path) -> None:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["GOTOOLCHAIN"] = "local"
    python = sys.executable
    commands = [
        [python, "tools/eigiib_negative_vector_generator.py", ".", "--json"],
        [python, "tools/eigiib_negative_route_replay.py", ".", "--go", "go", "--expected", "tests/fixtures/p1-a7/expected-a7.2-route-replay.json", "--json"],
        [python, "tools/eigiib_structural_route_replay.py", ".", "--go", "go", "--expected", "tests/fixtures/p1-a7/expected-a7.3-structural-replay.json", "--json"],
        [python, "tools/eigiib_signature_route_replay.py", ".", "--go", "go", "--openssl", "openssl", "--expected", "tests/fixtures/p1-a7/expected-a7.4-signature-replay.json", "--json"],
        [python, "tools/eigiib_cose_route_replay.py", ".", "--go", "go", "--openssl", "openssl", "--expected", "tests/fixtures/p1-a7/expected-a7.5-cose-replay.json", "--json"],
        [python, "tools/eigiib_receipt_route_replay.py", ".", "--go", "go", "--openssl", "openssl", "--expected", "tests/fixtures/p1-a7/expected-a7.6-receipt-replay.json", "--json"],
    ]
    for command in commands:
        result = _run_json(command, source, env)
        if result.get("overall_result", result.get("structural_result")) != "conformant":
            raise ValueError(f"offline route replay is not conformant: {command[1]}")
    attestation = source.parent / f"a7.7-{platform}-offline-attestation.json"
    authority = _run_json(
        [
            python,
            "tools/eigiib_p1_a7_authority_freeze.py",
            ".",
            "--manifest",
            "tests/fixtures/p1-a7/a7.7-authority-freeze.json",
            "--policy",
            str(selected_policy),
            "--expected",
            "tests/fixtures/p1-a7/expected-a7.7-authority-report.json",
            "--platform",
            platform,
            "--attestation-out",
            str(attestation),
            "--json",
        ],
        source,
        env,
    )
    if authority.get("overall_result") != "conformant":
        raise ValueError("offline A7.7 authority replay is not conformant")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--reference-dir", required=True, type=Path)
    parser.add_argument("--independent-dir", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--expected-release", required=True, type=Path)
    parser.add_argument("--expected-sha256sums", required=True, type=Path)
    parser.add_argument("--expected-report", required=True, type=Path)
    parser.add_argument("--a7-toolchain-policy-succession", required=True, type=Path)
    parser.add_argument("--runner-image-version", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    succession_path = args.a7_toolchain_policy_succession.resolve()
    try:
        base_command = [
            sys.executable,
            "tools/eigiib_p1_a8_publication_replay.py",
            ".",
            "--policy",
            str(args.policy.resolve()),
            "--reference-dir",
            str(args.reference_dir.resolve()),
            "--independent-dir",
            str(args.independent_dir.resolve()),
            "--platform",
            args.platform,
            "--expected-release",
            str(args.expected_release.resolve()),
            "--expected-sha256sums",
            str(args.expected_sha256sums.resolve()),
            "--expected-report",
            str(args.expected_report.resolve()),
            "--skip-offline-replay",
            "--json",
        ]
        base = _run_json(base_command, root, os.environ.copy())
        if base.get("overall_result") != "conformant":
            raise ValueError("base P1-A8 publication replay is not conformant")

        sys.path.insert(0, str(root / "tools"))
        from eigiib_p1_a8_common import strict_object, validate_policy
        from eigiib_p1_a8_publication_replay import _extract, _read_distribution, _validate_archive
        from eigiib_p1_a9_f1_runner_succession import select_policy

        git_version = subprocess.run(
            ["git", "--version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        selected_policy = select_policy(
            root,
            succession_path,
            args.platform,
            args.runner_image_version,
            git_version,
        )

        policy = strict_object(args.policy.resolve(), "P1-A8 release policy")
        validate_policy(policy)
        reference = _read_distribution(args.reference_dir.resolve(), policy)
        manifest_bytes = reference[policy["manifestName"]]
        bundle = reference[policy["bundleName"]]
        _, parsed = _validate_archive(bundle, manifest_bytes, policy)
        with tempfile.TemporaryDirectory(prefix="eigiib-p1-a9-f1-a8-") as temp:
            source = _extract(parsed, Path(temp) / "source", policy)
            _offline_replay(source, args.platform, selected_policy)
        print(json.dumps(base, sort_keys=True, separators=(",", ":")) if args.json else base["bundle_sha256"])
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A9.A8.COMPATIBILITY.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
