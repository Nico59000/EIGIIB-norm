#!/usr/bin/env python3
"""Replay P1-A14 through Python, independent Go and external go-cose routes."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a14_common import ROUTES, strict_json
from eigiib_p1_a14_remediation_check import evaluate

PROJECTION = [
    "revoked_release_id",
    "revoked_release_descriptor_sha256",
    "revoked_archive_sha256",
    "source_revocation_report_sha256",
    "source_revocation_capsule_sha256",
    "trusted_effective_time_unix",
    "policy_envelope_sha256",
    "advisory_id",
    "advisory_envelope_sha256",
    "vulnerability_ids",
    "remediation_id",
    "remediation_envelope_sha256",
    "fixed_release_id",
    "fixed_release_descriptor_sha256",
    "fixed_release_archive_sha256",
    "fixed_release_envelope_sha256",
    "fixed_release_floor_sequence",
    "accepted_history",
    "replay_results",
    "advisory_binding_result",
    "remediation_lineage_result",
    "fixed_release_replay_result",
    "vulnerability_remediation_result",
    "real_world_vulnerability_resolution_result",
    "production_release_authorization_result",
    "live_release_publication_result",
    "boundary",
    "overall_result",
]


def _go(root: Path, module: str, go: str, capsule: Path) -> dict[str, Any]:
    command = [go, "run", "./cmd/eigiib-p1-remediation-adapter", "--root", str(root), "--capsule", str(capsule)]
    completed = subprocess.run(command, cwd=root / module, check=True, capture_output=True)
    value = strict_json(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError(f"{module} result")
    return value


def replay(root: Path, capsule: Path, go: str = "go", openssl: str = "openssl") -> dict[str, Any]:
    results = {
        "reference-python-openssl": evaluate(root, capsule, openssl),
        "independent-go-stdlib": _go(root, "independent", go, capsule),
        "external-go-cose": _go(root, "external", go, capsule),
    }
    baseline = results[ROUTES[0]]
    for route in ROUTES[1:]:
        if results[route] != baseline:
            raise ValueError(f"route mismatch: {route}")
    projection = {key: baseline[key] for key in PROJECTION}
    return {
        "overall_result": "conformant",
        "portable_projection": projection,
        "routes": [{"route": route, "result": results[route]} for route in ROUTES],
        "standard": "EIGIIB-P1-A14-REPLAY-1.0",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, default=Path("tests/fixtures/p1-a14/capsule.json"))
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        capsule = args.capsule if args.capsule.is_absolute() else root / args.capsule
        result = replay(root, capsule, args.go, args.openssl)
        if args.expected:
            expected = args.expected if args.expected.is_absolute() else root / args.expected
            if result != strict_json(expected.read_bytes()):
                raise ValueError("expected replay mismatch")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")) if args.json else result["overall_result"])
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        message = {"error": str(exc), "overall_result": "non-conformant"}
        print(json.dumps(message, sort_keys=True, separators=(",", ":")) if args.json else f"non-conformant: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
