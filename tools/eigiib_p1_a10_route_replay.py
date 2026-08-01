#!/usr/bin/env python3
"""Run the three P1-A10 authorization routes and compare portable results."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a10_authorization_check import validate
from eigiib_p1_a10_common import ROUTES, canonical_json, strict_json

ROUTE_STANDARD = "EIGIIB-P1-A10-ROUTE-1.0"
REPLAY_STANDARD = "EIGIIB-P1-A10-REPLAY-1.0"
BOUNDARY = "recovered-threshold-authorization"


def portable(report: dict[str, Any], route: str) -> dict[str, Any]:
    return {
        "standard": ROUTE_STANDARD,
        "route": route,
        "release_id": report["release_id"],
        "release_descriptor_sha256": report["release_descriptor_sha256"],
        "release_signer_spki_sha256": report["release_signer_spki_sha256"],
        "trust_root_spki_sha256": report["trust_root_spki_sha256"],
        "policy_envelope_sha256": report["policy_envelope_sha256"],
        "threshold": report["threshold"],
        "delegate_count": report["delegate_count"],
        "initial_approval_ids": report["initial_approval_ids"],
        "revoked_delegate_id": report["revoked_delegate_id"],
        "revocation_sequence": report["revocation_sequence"],
        "recovered_approval_ids": report["recovered_approval_ids"],
        "trusted_release_signer_result": report["trusted_release_signer_result"],
        "authorized_release_signer_result": report[
            "authorized_release_signer_result"
        ],
        "accepted": True,
        "boundary": BOUNDARY,
    }


def go_route(root: Path, module: str, go: str) -> dict[str, Any]:
    capsule = root / "tests/fixtures/p1-a10/capsule.json"
    completed = subprocess.run(
        [
            go,
            "run",
            "./cmd/eigiib-p1-authorization-adapter",
            "--root",
            str(root),
            "--capsule",
            str(capsule),
        ],
        cwd=root / module,
        check=True,
        capture_output=True,
        text=True,
    )
    value = strict_json(completed.stdout.encode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{module} route result")
    return value


def replay(root: Path, capsule: Path, go: str, openssl: str) -> dict[str, Any]:
    reference_report = validate(root, capsule, openssl)
    observations = [
        portable(reference_report, ROUTES[0]),
        go_route(root, "independent", go),
        go_route(root, "external", go),
    ]
    if [row.get("route") for row in observations] != ROUTES:
        raise ValueError("route order")
    baseline = {key: value for key, value in observations[0].items() if key != "route"}
    for observation in observations:
        if {key: value for key, value in observation.items() if key != "route"} != baseline:
            raise ValueError("portable route divergence")
    return {
        "standard": REPLAY_STANDARD,
        "profile": "delegated-threshold-authorization-revocation-v1",
        "route_count": len(observations),
        "observations": observations,
        "trusted_release_signer_result": "conformant-for-supplied-root-policy-scope",
        "authorized_release_signer_result": "conformant-for-exact-release-descriptor-scope",
        "threshold_approval_result": "conformant",
        "revocation_replay_result": "conformant",
        "stale_approval_result": "rejected-as-required",
        "recovered_approval_result": "conformant",
        "boundary": BOUNDARY,
        "overall_result": "conformant",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = replay(args.root.resolve(), args.capsule.resolve(), args.go, args.openssl)
        if args.expected and canonical_json(result) != args.expected.read_bytes():
            raise ValueError("canonical replay differs")
        print(
            json.dumps(
                result if args.json else {"overall_result": result["overall_result"]},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A10.REPLAY.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
