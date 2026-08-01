#!/usr/bin/env python3
"""Replay the fixed P1-A8 bundle with a closed descendant A7 toolchain policy set."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

OLD_WINDOWS_PAIR = ("20260714.173.1", "git version 2.55.0.windows.2")
NEW_WINDOWS_PAIR = ("20260728.188.1", "git version 2.55.0.windows.3")
PLATFORMS = ("ubuntu-24.04", "macos-15", "windows-2025")


def _strict_object(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def policy_variant(platform: str, image_version: str, git_version: str) -> str:
    """Select one exact registered policy variant and reject all other Windows pairs."""
    if platform != "windows-2025":
        return "original"
    observed = (image_version, git_version)
    if observed == OLD_WINDOWS_PAIR:
        return "original"
    if observed == NEW_WINDOWS_PAIR:
        return "revision"
    raise ValueError(
        "unregistered Windows distribution for P1-A8 offline replay: "
        f"{image_version}|{git_version}"
    )


def validate_revision(original: dict[str, Any], revision: dict[str, Any]) -> None:
    """Require an additive revision differing only in the registered Windows pair."""
    if set(original) != set(revision):
        raise ValueError("A7 toolchain policy revision fields differ")
    for field in (
        "standard",
        "actions",
        "common",
        "binaryIdentityPolicy",
        "semanticEqualityPolicy",
    ):
        if original.get(field) != revision.get(field):
            raise ValueError(f"A7 toolchain policy revision changes {field}")
    original_platforms = original.get("platforms")
    revision_platforms = revision.get("platforms")
    if not isinstance(original_platforms, dict) or not isinstance(revision_platforms, dict):
        raise ValueError("A7 toolchain policy platforms differ")
    if set(original_platforms) != set(revision_platforms):
        raise ValueError("A7 toolchain policy platform set differs")
    for platform in ("ubuntu-24.04", "macos-15"):
        if original_platforms.get(platform) != revision_platforms.get(platform):
            raise ValueError(f"A7 toolchain policy revision changes {platform}")
    old_windows = original_platforms.get("windows-2025")
    new_windows = revision_platforms.get("windows-2025")
    if not isinstance(old_windows, dict) or not isinstance(new_windows, dict):
        raise ValueError("A7 Windows policy carrier differs")
    changed = {key for key in old_windows if old_windows.get(key) != new_windows.get(key)}
    if set(old_windows) != set(new_windows) or changed != {"imageVersion", "git"}:
        raise ValueError("A7 Windows policy revision is not bounded")
    if (old_windows.get("imageVersion"), old_windows.get("git")) != OLD_WINDOWS_PAIR:
        raise ValueError("original A7 Windows distribution differs")
    if (new_windows.get("imageVersion"), new_windows.get("git")) != NEW_WINDOWS_PAIR:
        raise ValueError("revised A7 Windows distribution differs")


def _run_json(command: list[str], cwd: Path, env: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, env=env, check=True, capture_output=True, text=True)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"offline replay did not emit JSON: {command[1]}") from exc
    if not isinstance(value, dict):
        raise ValueError("offline replay result is not an object")
    return value


def _selected_policy(
    source: Path,
    platform: str,
    revision_path: Path | None,
    env: dict[str, str],
    image_version: str,
) -> Path:
    original_path = source / "tests/fixtures/p1-a7/a7.7-toolchain-policy.json"
    if platform != "windows-2025":
        return original_path
    git_version = subprocess.run(
        ["git", "--version"], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()
    variant = policy_variant(platform, image_version, git_version)
    if variant == "original":
        return original_path
    if revision_path is None or not revision_path.is_file() or revision_path.is_symlink():
        raise ValueError("registered A7 Windows policy revision is unavailable")
    original = _strict_object(original_path, "original A7 toolchain policy")
    revision = _strict_object(revision_path, "revised A7 toolchain policy")
    validate_revision(original, revision)
    return revision_path


def _offline_replay(
    source: Path,
    platform: str,
    revision_path: Path | None,
    image_version: str,
) -> None:
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
    policy_path = _selected_policy(source, platform, revision_path, env, image_version)
    attestation = source.parent / f"a7.7-{platform}-offline-attestation.json"
    authority = _run_json(
        [
            python,
            "tools/eigiib_p1_a7_authority_freeze.py",
            ".",
            "--manifest",
            "tests/fixtures/p1-a7/a7.7-authority-freeze.json",
            "--policy",
            str(policy_path),
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
    parser.add_argument("--a7-toolchain-policy-revision", type=Path)
    parser.add_argument("--runner-image-version", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    revision_path = args.a7_toolchain_policy_revision
    if revision_path is not None:
        revision_path = revision_path.resolve()
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

        policy = strict_object(args.policy.resolve(), "P1-A8 release policy")
        validate_policy(policy)
        reference = _read_distribution(args.reference_dir.resolve(), policy)
        manifest_bytes = reference[policy["manifestName"]]
        bundle = reference[policy["bundleName"]]
        _, parsed = _validate_archive(bundle, manifest_bytes, policy)
        with tempfile.TemporaryDirectory(prefix="eigiib-p1-a9-a8-") as temp:
            source = _extract(parsed, Path(temp) / "source", policy)
            _offline_replay(source, args.platform, revision_path, args.runner_image_version)
        print(json.dumps(base, sort_keys=True, separators=(",", ":")) if args.json else base["bundle_sha256"])
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A9.A8.COMPATIBILITY.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
