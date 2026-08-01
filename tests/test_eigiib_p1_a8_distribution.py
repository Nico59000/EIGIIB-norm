from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from eigiib_p1_a8_common import canonical_json_bytes, git_blob_sha1, source_tree_root, validate_policy
from eigiib_p1_a8_distribution import build_distribution
from eigiib_p1_a8_publication_replay import _validate_archive
from eigiib_p1_a8_ustar import build as build_ustar, parse as parse_ustar


class P1A8DistributionTests(unittest.TestCase):
    def policy(self, commit: str) -> dict:
        return {
            "standard": "EIGIIB-P1-A8-POLICY-1.0",
            "profile": "exact-ustar-source-distribution-v1",
            "releaseId": "eigiib-p1-a7-authority-1.0",
            "sourceCommit": commit,
            "authorityRoot": "e338247156165c48b7b1ce88a69f24123defc0162b1f3f6a58c4ecd510e105be",
            "archiveRoot": "eigiib-p1-a7-authority-1.0",
            "bundleName": "eigiib-p1-a7-authority-1.0.tar",
            "manifestName": "eigiib-p1-a8-bundle-manifest.json",
            "releaseName": "eigiib-p1-a8-release.json",
            "checksumName": "SHA256SUMS",
            "requiredPublishers": ["reference-python-stdlib", "independent-go-stdlib"],
            "requiredPlatforms": ["ubuntu-24.04", "macos-15", "windows-2025"],
            "claimBoundary": {"doesNotImply": ["external-publication"]},
        }

    def make_repo(self) -> tuple[tempfile.TemporaryDirectory, Path, str]:
        holder = tempfile.TemporaryDirectory()
        root = Path(holder.name) / "repo"
        root.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "a@example.test"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "A"], cwd=root, check=True)
        (root / "a.txt").write_bytes(b"committed\n")
        (root / "bin").mkdir()
        executable = root / "bin" / "tool"
        executable.write_bytes(b"#!/bin/sh\n")
        executable.chmod(0o755)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        return holder, root, commit

    def test_policy_is_closed(self) -> None:
        validate_policy(self.policy("a" * 40))
        changed = self.policy("a" * 40)
        changed["extra"] = True
        with self.assertRaises(ValueError):
            validate_policy(changed)

    def test_git_blob_identity(self) -> None:
        self.assertEqual(git_blob_sha1(b"test\n"), "9daeafb9864cf43055ae93beb0afd6c7d144bfa4")

    def test_source_tree_root_is_order_independent(self) -> None:
        rows = [
            {"path": "b", "mode": "0644", "bytes": 1, "sha256": "1" * 64, "gitBlobSha1": "2" * 40},
            {"path": "a", "mode": "0755", "bytes": 2, "sha256": "3" * 64, "gitBlobSha1": "4" * 40},
        ]
        self.assertEqual(source_tree_root(rows), source_tree_root(reversed(rows)))

    def test_closed_ustar_round_trip(self) -> None:
        raw = build_ustar([
            ("release/META-INF/manifest.json", 0o644, b"{}\n"),
            ("release/source/bin/tool", 0o755, b"#!/bin/sh\n"),
        ])
        parsed = parse_ustar(raw)
        self.assertEqual([(x.path, x.mode, x.data) for x in parsed], [
            ("release/META-INF/manifest.json", 0o644, b"{}\n"),
            ("release/source/bin/tool", 0o755, b"#!/bin/sh\n"),
        ])

    def test_ustar_checksum_mutation_is_rejected(self) -> None:
        raw = bytearray(build_ustar([("release/source/a", 0o644, b"a")]))
        raw[10] ^= 1
        with self.assertRaises(ValueError):
            parse_ustar(bytes(raw))

    def test_distribution_reads_commit_not_worktree(self) -> None:
        holder, root, commit = self.make_repo()
        self.addCleanup(holder.cleanup)
        (root / "a.txt").write_bytes(b"working-tree-change\n")
        manifest, bundle, release, sums = build_distribution(root, self.policy(commit))
        parsed = parse_ustar(bundle)
        by_path = {entry.path: entry for entry in parsed}
        self.assertEqual(by_path["eigiib-p1-a7-authority-1.0/source/a.txt"].data, b"committed\n")
        self.assertEqual(release["embeddedManifest"]["sourceEntryCount"], 2)
        self.assertIn(release["bundle"]["sha256"].encode("ascii"), sums)
        self.assertEqual(canonical_json_bytes(manifest), by_path[manifest["embeddedManifestPath"]].data)

    def test_archive_validation_rejects_undeclared_entry(self) -> None:
        holder, root, commit = self.make_repo()
        self.addCleanup(holder.cleanup)
        policy = self.policy(commit)
        manifest, bundle, _, _ = build_distribution(root, policy)
        manifest_bytes = canonical_json_bytes(manifest)
        _validate_archive(bundle, manifest_bytes, policy)
        parsed = parse_ustar(bundle)
        entries = [(entry.path, entry.mode, entry.data) for entry in parsed]
        entries.append(("eigiib-p1-a7-authority-1.0/source/extra", 0o644, b"x"))
        entries.sort(key=lambda item: item[0])
        with self.assertRaises(ValueError):
            _validate_archive(build_ustar(entries), manifest_bytes, policy)


if __name__ == "__main__":
    unittest.main()
