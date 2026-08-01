#!/usr/bin/env python3
"""Verify two exact P1-A8 publications and replay P1-A7 outside Git."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from eigiib_p1_a8_common import (
    BUNDLE_STANDARD,
    PROFILE,
    RELEASE_STANDARD,
    REPLAY_PROFILE,
    REPLAY_STANDARD,
    TOOL_VERSION,
    canonical_json_bytes,
    ensure_ascii_path,
    git_blob_sha1,
    sha256_hex,
    source_tree_root,
    strict_object,
    validate_policy,
)
from eigiib_p1_a8_ustar import ParsedEntry, parse as parse_ustar


def _strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member in {label}: {key}")
            out[key] = value
        return out

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _read_distribution(directory: Path, policy: dict[str, Any]) -> dict[str, bytes]:
    names = [policy["bundleName"], policy["manifestName"], policy["releaseName"], policy["checksumName"]]
    result: dict[str, bytes] = {}
    for name in names:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"distribution file unavailable: {path}")
        result[name] = path.read_bytes()
    return result


def _validate_manifest(manifest: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    expected = {
        "standard", "profile", "releaseId", "sourceCommit", "authorityRoot", "archiveRoot",
        "embeddedManifestPath", "sourcePathPrefix", "sourceTreeRoot", "ustarProfile", "entries",
    }
    if set(manifest) != expected:
        raise ValueError("embedded manifest fields differ")
    if manifest["standard"] != BUNDLE_STANDARD or manifest["profile"] != PROFILE:
        raise ValueError("embedded manifest constants differ")
    for field in ("releaseId", "sourceCommit", "authorityRoot", "archiveRoot"):
        if manifest[field] != policy[field]:
            raise ValueError(f"embedded manifest {field} differs")
    expected_manifest_path = f"{policy['archiveRoot']}/META-INF/{policy['manifestName']}"
    expected_source_prefix = f"{policy['archiveRoot']}/source/"
    if manifest["embeddedManifestPath"] != expected_manifest_path or manifest["sourcePathPrefix"] != expected_source_prefix:
        raise ValueError("embedded archive paths differ")
    if manifest["ustarProfile"] != {
        "format": "ustar", "pathEncoding": "ascii", "pathOrder": "bytewise-ascending",
        "uid": 0, "gid": 0, "mtime": 0, "regularMode": "0644", "executableMode": "0755",
        "directoryEntries": False, "paxHeaders": False, "trailerBlocks": 2,
    }:
        raise ValueError("embedded USTAR profile differs")
    entries = manifest["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("embedded manifest entries must be non-empty")
    if entries != sorted(entries, key=lambda item: item.get("path", "") if isinstance(item, dict) else ""):
        raise ValueError("embedded manifest entries are not path-sorted")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "mode", "bytes", "sha256", "gitBlobSha1"}:
            raise ValueError("embedded source entry fields differ")
        path = entry["path"]
        ensure_ascii_path(path, "source path")
        if path in seen:
            raise ValueError(f"duplicate embedded source path: {path}")
        seen.add(path)
        if entry["mode"] not in {"0644", "0755"}:
            raise ValueError(f"embedded source mode differs: {path}")
        if not isinstance(entry["bytes"], int) or entry["bytes"] < 0:
            raise ValueError(f"embedded source byte count differs: {path}")
        for field, width in (("sha256", 64), ("gitBlobSha1", 40)):
            value = entry[field]
            if not isinstance(value, str) or len(value) != width or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"embedded source {field} differs: {path}")
    expected_root = {
        "algorithm": "sha256-over-path-mode-size-sha256-gitblob-v1",
        "digest": source_tree_root(entries),
    }
    if manifest["sourceTreeRoot"] != expected_root:
        raise ValueError("embedded source tree root differs")
    return entries


def _validate_archive(bundle: bytes, detached_manifest: bytes, policy: dict[str, Any]) -> tuple[dict[str, Any], list[ParsedEntry]]:
    parsed = parse_ustar(bundle)
    by_path = {entry.path: entry for entry in parsed}
    if len(by_path) != len(parsed):
        raise ValueError("archive contains duplicate paths")
    manifest_path = f"{policy['archiveRoot']}/META-INF/{policy['manifestName']}"
    manifest_entry = by_path.get(manifest_path)
    if manifest_entry is None or manifest_entry.mode != 0o644:
        raise ValueError("embedded manifest entry is unavailable")
    if manifest_entry.data != detached_manifest:
        raise ValueError("embedded and detached manifest bytes differ")
    manifest = _strict_json_bytes(detached_manifest, "P1-A8 bundle manifest")
    if canonical_json_bytes(manifest) != detached_manifest:
        raise ValueError("bundle manifest is not canonical JSON")
    source_entries = _validate_manifest(manifest, policy)
    expected_paths = {manifest_path}
    for row in source_entries:
        archive_path = f"{policy['archiveRoot']}/source/{row['path']}"
        expected_paths.add(archive_path)
        entry = by_path.get(archive_path)
        if entry is None:
            raise ValueError(f"archive source entry unavailable: {row['path']}")
        if entry.mode != int(row["mode"], 8):
            raise ValueError(f"archive source mode differs: {row['path']}")
        if len(entry.data) != row["bytes"] or sha256_hex(entry.data) != row["sha256"]:
            raise ValueError(f"archive source SHA-256/length differs: {row['path']}")
        if git_blob_sha1(entry.data) != row["gitBlobSha1"]:
            raise ValueError(f"archive source Git blob identity differs: {row['path']}")
    if set(by_path) != expected_paths:
        raise ValueError("archive contains undeclared or missing paths")
    return manifest, parsed


def _release_from_bytes(bundle: bytes, manifest_bytes: bytes, manifest: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "standard": RELEASE_STANDARD,
        "profile": PROFILE,
        "releaseId": policy["releaseId"],
        "sourceCommit": policy["sourceCommit"],
        "authorityRoot": policy["authorityRoot"],
        "bundle": {"name": policy["bundleName"], "bytes": len(bundle), "sha256": sha256_hex(bundle)},
        "embeddedManifest": {
            "name": policy["manifestName"],
            "path": manifest["embeddedManifestPath"],
            "bytes": len(manifest_bytes),
            "sha256": sha256_hex(manifest_bytes),
            "sourceEntryCount": len(manifest["entries"]),
        },
        "sourceTreeRoot": manifest["sourceTreeRoot"],
        "requiredPublishers": policy["requiredPublishers"],
        "requiredPlatforms": policy["requiredPlatforms"],
        "claimBoundary": policy["claimBoundary"],
    }


def _expected_sums(release: dict[str, Any], policy: dict[str, Any]) -> bytes:
    return (
        f"{release['bundle']['sha256']}  {policy['bundleName']}\n"
        f"{release['embeddedManifest']['sha256']}  {policy['manifestName']}\n"
    ).encode("ascii")


def _extract(parsed: list[ParsedEntry], target: Path, policy: dict[str, Any]) -> Path:
    source_prefix = f"{policy['archiveRoot']}/source/"
    for entry in parsed:
        if not entry.path.startswith(source_prefix):
            continue
        rel = entry.path[len(source_prefix):]
        ensure_ascii_path(rel, "extracted source path")
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(entry.data)
        destination.chmod(entry.mode)
    return target


def _run_json(command: list[str], cwd: Path, env: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, env=env, check=True, capture_output=True, text=True)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"offline replay did not emit JSON: {command[1] if len(command) > 1 else command[0]}") from exc
    if not isinstance(value, dict):
        raise ValueError("offline replay result is not an object")
    return value


def _offline_replay(source: Path, platform: str) -> None:
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
        if result.get("overall_result", result.get("structural_result")) not in {"conformant"}:
            raise ValueError(f"offline route replay is not conformant: {command[1]}")
    attestation = source.parent / f"a7.7-{platform}-offline-attestation.json"
    authority = _run_json([
        python, "tools/eigiib_p1_a7_authority_freeze.py", ".",
        "--manifest", "tests/fixtures/p1-a7/a7.7-authority-freeze.json",
        "--policy", "tests/fixtures/p1-a7/a7.7-toolchain-policy.json",
        "--expected", "tests/fixtures/p1-a7/expected-a7.7-authority-report.json",
        "--platform", platform,
        "--attestation-out", str(attestation),
        "--json",
    ], source, env)
    if authority.get("overall_result") != "conformant":
        raise ValueError("offline A7.7 authority replay is not conformant")


def publication_report(release: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "standard": REPLAY_STANDARD,
        "profile": REPLAY_PROFILE,
        "tool": "eigiib-p1-a8-publication-replay",
        "tool_version": TOOL_VERSION,
        "release_id": release["releaseId"],
        "source_commit": release["sourceCommit"],
        "authority_root": release["authorityRoot"],
        "bundle_sha256": release["bundle"]["sha256"],
        "bundle_bytes": release["bundle"]["bytes"],
        "embedded_manifest_sha256": release["embeddedManifest"]["sha256"],
        "source_tree_root": release["sourceTreeRoot"]["digest"],
        "source_entry_count": release["embeddedManifest"]["sourceEntryCount"],
        "publishers": policy["requiredPublishers"],
        "platforms": policy["requiredPlatforms"],
        "publisher_byte_equivalence_result": "conformant",
        "release_digest_result": "conformant",
        "archive_structure_result": "conformant",
        "archive_content_result": "conformant",
        "offline_a7_authority_result": "conformant",
        "offline_a7_route_replay_result": "conformant",
        "independent_publication_replay_result": "conformant",
        "overall_result": "conformant",
        "findings": [],
        "claim_boundary": policy["claimBoundary"]["doesNotImply"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--reference-dir", required=True, type=Path)
    parser.add_argument("--independent-dir", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=["ubuntu-24.04", "macos-15", "windows-2025"])
    parser.add_argument("--expected-release", type=Path)
    parser.add_argument("--expected-sha256sums", type=Path)
    parser.add_argument("--expected-report", type=Path)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--skip-offline-replay", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        policy = strict_object(args.policy, "P1-A8 release policy")
        validate_policy(policy)
        reference = _read_distribution(args.reference_dir.resolve(), policy)
        independent = _read_distribution(args.independent_dir.resolve(), policy)
        if reference != independent:
            differing = sorted(name for name in reference if reference[name] != independent[name])
            raise ValueError(f"publisher outputs differ: {differing}")
        manifest_bytes = reference[policy["manifestName"]]
        bundle = reference[policy["bundleName"]]
        manifest, parsed = _validate_archive(bundle, manifest_bytes, policy)
        release = _release_from_bytes(bundle, manifest_bytes, manifest, policy)
        if canonical_json_bytes(release) != reference[policy["releaseName"]]:
            raise ValueError("generated release descriptor differs from archive")
        sums = _expected_sums(release, policy)
        if sums != reference[policy["checksumName"]]:
            raise ValueError("generated SHA256SUMS differs from archive")
        report = publication_report(release, policy)
        if args.probe:
            print("P1A8_RELEASE_CANDIDATE=" + canonical_json_bytes(release).decode("utf-8").strip())
            print("P1A8_SHA256SUMS_CANDIDATE=" + json.dumps(sums.decode("ascii")))
            print("P1A8_REPORT_CANDIDATE=" + canonical_json_bytes(report).decode("utf-8").strip())
        else:
            if not args.expected_release or not args.expected_sha256sums or not args.expected_report:
                raise ValueError("expected release, SHA256SUMS and report are required outside probe mode")
            expected_release = strict_object(args.expected_release, "expected P1-A8 release")
            expected_report = strict_object(args.expected_report, "expected P1-A8 report")
            if canonical_json_bytes(release) != canonical_json_bytes(expected_release):
                raise ValueError("release descriptor differs from registered release")
            if sums != args.expected_sha256sums.read_bytes():
                raise ValueError("SHA256SUMS differs from registered release")
            if canonical_json_bytes(report) != canonical_json_bytes(expected_report):
                raise ValueError("publication report differs from registered result")
        if not args.skip_offline_replay:
            with tempfile.TemporaryDirectory(prefix="eigiib-p1-a8-") as temp:
                source = _extract(parsed, Path(temp) / "source", policy)
                _offline_replay(source, args.platform)
        print(json.dumps(report, sort_keys=True, separators=(",", ":")) if args.json else report["bundle_sha256"])
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A8.PUBLICATION.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
