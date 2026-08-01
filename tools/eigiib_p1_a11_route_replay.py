#!/usr/bin/env python3
"""Run the three P1-A11 trusted-time routes and compare portable results."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a11_common import ROUTES, canonical_json, strict_json
from eigiib_p1_a11_time_check import BOUNDARY, validate

ROUTE_STANDARD = "EIGIIB-P1-A11-ROUTE-1.0"
REPLAY_STANDARD = "EIGIIB-P1-A11-REPLAY-1.0"


def portable(report: dict[str, Any], route: str) -> dict[str, Any]:
    return {
        "standard": ROUTE_STANDARD,
        "route": route,
        "release_id": report["release_id"],
        "authorization_report_sha256": report["authorization_report_sha256"],
        "recovered_authorization_sha256": report["recovered_authorization_sha256"],
        "time_trust_root_spki_sha256": report["time_trust_root_spki_sha256"],
        "timestamp_authority_id": report["timestamp_authority_id"],
        "timestamp_authority_spki_sha256": report["timestamp_authority_spki_sha256"],
        "time_policy_envelope_sha256": report["time_policy_envelope_sha256"],
        "not_before_unix": report["not_before_unix"],
        "not_after_unix": report["not_after_unix"],
        "accepted_observation_ids": report["accepted_observation_ids"],
        "last_accepted_timestamp_unix": report["last_accepted_timestamp_unix"],
        "not_yet_valid_result": report["not_yet_valid_result"],
        "valid_window_result": report["valid_window_result"],
        "clock_rollback_result": report["clock_rollback_result"],
        "expiry_result": report["expiry_result"],
        "trusted_timestamp_authority_result": report["trusted_timestamp_authority_result"],
        "trusted_effective_time_result": report["trusted_effective_time_result"],
        "accepted": True,
        "boundary": BOUNDARY,
    }


def go_route(root: Path, module: str, go: str) -> dict[str, Any]:
    capsule = root / "tests/fixtures/p1-a11/capsule.json"
    completed = subprocess.run(
        [go, "run", "./cmd/eigiib-p1-time-adapter", "--root", str(root), "--capsule", str(capsule)],
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
        "profile": "trusted-timestamp-window-rollback-expiry-v1",
        "route_count": 3,
        "observations": observations,
        "trusted_timestamp_authority_result": "conformant-for-supplied-time-root-delegation-scope",
        "trusted_effective_time_result": "conformant-for-signed-observation-and-closed-window-scope",
        "not_yet_valid_result": "rejected-as-required",
        "valid_window_result": "conformant",
        "clock_rollback_result": "rejected-as-required",
        "expiry_result": "rejected-as-required",
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
        print(json.dumps(result if args.json else {"overall_result": result["overall_result"]}, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A11.REPLAY.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
