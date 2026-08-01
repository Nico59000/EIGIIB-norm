#!/usr/bin/env python3
"""Build the exact P1-A8 source distribution from one Git commit."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a8_common import (
    BUNDLE_STANDARD,
    PROFILE,
    RELEASE_STANDARD,
    TOOL_VERSION,
    canonical_json_bytes,
    sha256_hex,
    source_tree_root,
    strict_object,
    validate_policy,
)
from eigiib_p1_a8_git_snapshot import git_snapshot
from eigiib_p1_a8_ustar import build as build_ustar


def build_distribution(root: Path, policy: dict[str, Any]) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
    validate_policy(policy)
    snapshot = git_snapshot(root, policy["sourceCommit"])
    public_entries = [{key: row[key] for key in ("path", "mode", "bytes", "sha256", "gitBlobSha1")} for row in snapshot]
    tree_root = source_tree_root(public_entries)
    manifest_path = f"{policy['archiveRoot']}/META-INF/{policy['manifestName']}"
    manifest = {
        "standard": BUNDLE_STANDARD,
        "profile": PROFILE,
        "releaseId": policy["releaseId"],
        "sourceCommit": policy["sourceCommit"],
        "authorityRoot": policy["authorityRoot"],
        "archiveRoot": policy["archiveRoot"],
        "embeddedManifestPath": manifest_path,
        "sourcePathPrefix": f"{policy['archiveRoot']}/source/",
        "sourceTreeRoot": {
            "algorithm": "sha256-over-path-mode-size-sha256-gitblob-v1",
            "digest": tree_root,
        },
        "ustarProfile": {
            "format": "ustar",
            "pathEncoding": "ascii",
            "pathOrder": "bytewise-ascending",
            "uid": 0,
            "gid": 0,
            "mtime": 0,
            "regularMode": "0644",
            "executableMode": "0755",
            "directoryEntries": False,
            "paxHeaders": False,
            "trailerBlocks": 2,
        },
        "entries": public_entries,
    }
    manifest_bytes = canonical_json_bytes(manifest)
    archive_entries: list[tuple[str, int, bytes]] = [(manifest_path, 0o644, manifest_bytes)]
    for row in snapshot:
        archive_entries.append((f"{policy['archiveRoot']}/source/{row['path']}", int(row["mode"], 8), row["data"]))
    archive_entries.sort(key=lambda item: item[0])
    bundle = build_ustar(archive_entries)
    release = {
        "standard": RELEASE_STANDARD,
        "profile": PROFILE,
        "releaseId": policy["releaseId"],
        "sourceCommit": policy["sourceCommit"],
        "authorityRoot": policy["authorityRoot"],
        "bundle": {
            "name": policy["bundleName"],
            "bytes": len(bundle),
            "sha256": sha256_hex(bundle),
        },
        "embeddedManifest": {
            "name": policy["manifestName"],
            "path": manifest_path,
            "bytes": len(manifest_bytes),
            "sha256": sha256_hex(manifest_bytes),
            "sourceEntryCount": len(public_entries),
        },
        "sourceTreeRoot": manifest["sourceTreeRoot"],
        "requiredPublishers": policy["requiredPublishers"],
        "requiredPlatforms": policy["requiredPlatforms"],
        "claimBoundary": policy["claimBoundary"],
    }
    sums = (
        f"{release['bundle']['sha256']}  {policy['bundleName']}\n"
        f"{release['embeddedManifest']['sha256']}  {policy['manifestName']}\n"
    ).encode("ascii")
    return manifest, bundle, release, sums


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        policy = strict_object(args.policy, "P1-A8 release policy")
        manifest, bundle, release, sums = build_distribution(root, policy)
        out = args.out_dir.resolve()
        out.mkdir(parents=True, exist_ok=True)
        (out / policy["manifestName"]).write_bytes(canonical_json_bytes(manifest))
        (out / policy["bundleName"]).write_bytes(bundle)
        (out / policy["releaseName"]).write_bytes(canonical_json_bytes(release))
        (out / policy["checksumName"]).write_bytes(sums)
        result = {
            "tool": "eigiib-p1-a8-distribution",
            "tool_version": TOOL_VERSION,
            "publisher": "reference-python-stdlib",
            "release": release,
            "result": "conformant",
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")) if args.json else release["bundle"]["sha256"])
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A8.DISTRIBUTION.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
