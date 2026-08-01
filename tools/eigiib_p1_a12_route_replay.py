#!/usr/bin/env python3
"""Replay P1-A12 through Python/OpenSSL, independent Go and external go-cose routes."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a12_common import PROFILE, canonical_json, strict_json

ROUTE_KEYS = [
    "release_id",
    "source_time_report_sha256",
    "transparency_trust_root_spki_sha256",
    "registered_service_id",
    "registered_service_epoch",
    "registered_service_spki_sha256",
    "recovered_service_id",
    "recovered_service_epoch",
    "recovered_service_spki_sha256",
    "witness_threshold",
    "baseline_checkpoint_root",
    "canonical_checkpoint_root",
    "conflicting_checkpoint_root",
    "recovered_checkpoint_root",
    "baseline_quorum_ids",
    "canonical_quorum_ids",
    "conflicting_quorum_ids",
    "recovered_quorum_ids",
    "equivocating_witness_ids",
    "equivocation_result",
    "predecessor_service_result",
    "trusted_transparency_service_result",
    "append_only_consistency_result",
    "global_append_only_consistency_result",
    "accepted_checkpoint_ids",
    "rejected_checkpoint_ids",
    "boundary",
]


def run_json(command: list[str], cwd: Path) -> dict[str, Any]:
    result = subprocess.run(command, cwd=cwd, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    value = strict_json(result.stdout)
    if not isinstance(value, dict):
        raise ValueError("route result")
    return value


def reference(root: Path, capsule: Path, openssl: str) -> dict[str, Any]:
    report = run_json([
        sys.executable,
        str(root / "tools/eigiib_p1_a12_transparency_check.py"),
        str(root), "--capsule", str(capsule), "--openssl", openssl, "--json",
    ], root)
    route = {"standard": "EIGIIB-P1-A12-ROUTE-1.0", "route": "reference-python-openssl"}
    route.update({key: report[key] for key in ROUTE_KEYS})
    route["accepted"] = True
    return route


def go_route(root: Path, module: str, route_name: str, go: str) -> dict[str, Any]:
    value = run_json([
        go, "run", "./cmd/eigiib-p1-transparency-adapter",
        "--root", "..", "--capsule", "../tests/fixtures/p1-a12/capsule.json",
    ], root / module)
    if value.get("route") != route_name:
        raise ValueError("route identity")
    return value


def replay(root: Path, capsule: Path, go: str, openssl: str) -> dict[str, Any]:
    observations = [
        reference(root, capsule, openssl),
        go_route(root, "independent", "independent-go-stdlib", go),
        go_route(root, "external", "external-go-cose", go),
    ]
    baseline = {key: observations[0][key] for key in ROUTE_KEYS + ["accepted"]}
    for row in observations[1:]:
        if {key: row[key] for key in ROUTE_KEYS + ["accepted"]} != baseline:
            raise ValueError("route semantic divergence")
    return {
        "standard": "EIGIIB-P1-A12-REPLAY-1.0",
        "profile": PROFILE,
        "route_count": 3,
        "observations": observations,
        "equivocation_result": baseline["equivocation_result"],
        "trusted_transparency_service_result": baseline["trusted_transparency_service_result"],
        "append_only_consistency_result": baseline["append_only_consistency_result"],
        "global_append_only_consistency_result": baseline["global_append_only_consistency_result"],
        "boundary": baseline["boundary"],
        "overall_result": "conformant",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = replay(args.root.resolve(), args.capsule.resolve(), args.go, args.openssl)
        if args.expected and result != strict_json(args.expected.read_bytes()):
            raise ValueError("expected replay mismatch")
    except Exception as exc:
        print(f"P1-A12 route replay failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        sys.stdout.buffer.write(canonical_json(result))
    else:
        print("P1-A12 three-route replay: conformant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
