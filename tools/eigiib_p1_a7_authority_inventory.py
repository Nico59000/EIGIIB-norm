"""Repository inventory and canonical report for P1-A7.7."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from eigiib_p1_a7_authority_common import (
    PLATFORMS,
    PROFILE,
    ROUTES,
    STANDARD,
    TOOL,
    TOOL_VERSION,
    authority_root,
    confined_file,
    git_blob_sha1,
    load_json,
    sha256_hex,
)

EXPECTED_COUNTS = {
    "authorityFiles": 13,
    "generatorVectors": 8,
    "negativeVectors": 37,
    "positiveCarriers": 5,
    "routeBoundObservations": 141,
}
REPORT_PATHS = [
    "tests/fixtures/p1-a7/expected-a7.2-route-replay.json",
    "tests/fixtures/p1-a7/expected-a7.3-structural-replay.json",
    "tests/fixtures/p1-a7/expected-a7.4-signature-replay.json",
    "tests/fixtures/p1-a7/expected-a7.5-cose-replay.json",
    "tests/fixtures/p1-a7/expected-a7.6-receipt-replay.json",
]


def _run_text(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)
    return completed.stdout.strip()


def validate_manifest(root: Path, manifest: dict[str, Any], require_git_source: bool) -> list[dict[str, Any]]:
    expected_fields = {
        "standard", "profile", "sourceCommit", "authorityRoot", "entries",
        "requiredRoutes", "requiredPlatforms", "counts", "claimBoundary",
    }
    if set(manifest) != expected_fields:
        raise ValueError("authority manifest fields differ from contract")
    if manifest["standard"] != STANDARD or manifest["profile"] != PROFILE:
        raise ValueError("authority manifest constants differ")
    if manifest["requiredRoutes"] != ROUTES or manifest["requiredPlatforms"] != PLATFORMS:
        raise ValueError("authority routes or platforms differ")
    if manifest["counts"] != EXPECTED_COUNTS:
        raise ValueError("authority counts differ")
    source = manifest["sourceCommit"]
    if not isinstance(source, str) or len(source) != 40 or any(ch not in "0123456789abcdef" for ch in source):
        raise ValueError("source commit is not a lowercase SHA-1 object ID")
    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) != EXPECTED_COUNTS["authorityFiles"]:
        raise ValueError("authority entry count differs")
    if entries != sorted(entries, key=lambda item: item.get("path", "")):
        raise ValueError("authority entries are not path-sorted")
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "gitBlobSha1"}:
            raise ValueError("authority entry fields differ")
        rel = entry["path"]
        blob = entry["gitBlobSha1"]
        if rel in seen:
            raise ValueError(f"duplicate authority path: {rel}")
        seen.add(rel)
        if not isinstance(blob, str) or len(blob) != 40 or any(ch not in "0123456789abcdef" for ch in blob):
            raise ValueError(f"invalid Git blob identity for {rel}")
        raw = confined_file(root, rel).read_bytes()
        actual_blob = git_blob_sha1(raw)
        if actual_blob != blob:
            raise ValueError(f"working-tree Git blob identity differs for {rel}")
        rows.append({"path": rel, "bytes": len(raw), "sha256": sha256_hex(raw), "git_blob_sha1": actual_blob})
    root_decl = manifest["authorityRoot"]
    if root_decl != {
        "algorithm": "sha256-over-sorted-git-blob-identities-v1",
        "digest": authority_root(entries),
    }:
        raise ValueError("declared authority root differs")
    if require_git_source:
        subprocess.run(["git", "cat-file", "-e", f"{source}^{{commit}}"], cwd=root, check=True)
        subprocess.run(["git", "merge-base", "--is-ancestor", source, "HEAD"], cwd=root, check=True)
        for entry in entries:
            source_blob = _run_text(["git", "rev-parse", f"{source}:{entry['path']}"], root)
            if source_blob != entry["gitBlobSha1"]:
                raise ValueError(f"source commit blob differs for {entry['path']}")
    return rows


def validate_prior_reports(root: Path, manifest: dict[str, Any]) -> None:
    observations = 0
    negative_ids: set[str] = set()
    positive_ids: set[str] = set()
    for rel in REPORT_PATHS:
        report = load_json(confined_file(root, rel), rel)
        if not isinstance(report, dict) or report.get("overall_result") != "conformant":
            raise ValueError(f"prior report is not conformant: {rel}")
        rows = report.get("observations")
        vector_ids = report.get("vector_ids")
        if not isinstance(rows, list) or not isinstance(vector_ids, list):
            raise ValueError(f"prior report carrier differs: {rel}")
        observations += len(rows)
        negative_ids.update(vector_ids)
        positive_ids.update(
            row.get("vector_id") for row in rows
            if isinstance(row, dict) and row.get("accepted") is True
        )
    generator = load_json(confined_file(root, "tests/fixtures/p1-a7/corpus.json"), "A7.1 corpus")
    if not isinstance(generator, dict) or len(generator.get("vectors", [])) != EXPECTED_COUNTS["generatorVectors"]:
        raise ValueError("A7.1 generator vector count differs")
    actual = {
        "authorityFiles": len(manifest["entries"]),
        "generatorVectors": len(generator["vectors"]),
        "negativeVectors": len(negative_ids),
        "positiveCarriers": len(positive_ids),
        "routeBoundObservations": observations,
    }
    if actual != EXPECTED_COUNTS:
        raise ValueError(f"frozen corpus counts differ: {actual!r}")


def build_report(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "standard": STANDARD,
        "profile": PROFILE,
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "source_commit": manifest["sourceCommit"],
        "authority_root": manifest["authorityRoot"]["digest"],
        "authority_file_count": EXPECTED_COUNTS["authorityFiles"],
        "generator_vector_count": EXPECTED_COUNTS["generatorVectors"],
        "negative_vector_count": EXPECTED_COUNTS["negativeVectors"],
        "positive_carrier_count": EXPECTED_COUNTS["positiveCarriers"],
        "route_bound_observation_count": EXPECTED_COUNTS["routeBoundObservations"],
        "routes": ROUTES,
        "platforms": PLATFORMS,
        "authority_inventory_result": "conformant",
        "canonical_replay_identity_result": "conformant",
        "cross_platform_reproducibility_result": "conformant",
        "toolchain_policy_result": "conformant",
        "authority_registration_result": "conformant",
        "full_p1_a7_freeze_result": "conformant",
        "overall_result": "conformant",
        "findings": [],
        "claim_boundary": manifest["claimBoundary"]["doesNotImply"],
    }
