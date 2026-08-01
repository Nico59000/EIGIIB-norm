#!/usr/bin/env python3
"""Verify trusted timestamp delegation, validity windows, rollback and expiry for P1-A11."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eigiib_p1_a11_common import (
    OBSERVATION_TYPE,
    POLICY_TYPE,
    PROFILE,
    STANDARD,
    canonical_json,
    confined,
    decode_b64,
    exact_keys,
    identity,
    strict_json,
)
from eigiib_p1_a11_crypto import public_der, verify_cose_sign1

POLICY_ID = "eigiib-p1-a11-time-policy-1"
AUTHORITY_ID = "eigiib-p1-a11-tsa-1"
NOT_BEFORE = ("2026-08-01T16:00:00Z", 1785600000)
NOT_AFTER = ("2026-08-02T16:00:00Z", 1785686400)
OBSERVATIONS = [
    ("before-window", 100, "2026-08-01T15:59:59Z", 1785599999, "rejected-not-yet-valid"),
    ("valid-window", 101, "2026-08-01T17:00:00Z", 1785603600, "conformant"),
    ("clock-rollback", 102, "2026-08-01T16:30:00Z", 1785601800, "rejected-clock-rollback"),
    ("expired-window", 103, "2026-08-02T16:00:01Z", 1785686401, "rejected-expired"),
]
BOUNDARY = "trusted-time-window-rollback-expiry-closure"


def _carrier_bytes(carrier: Any, label: str) -> bytes:
    if not exact_keys(carrier, {"data", "identity"}):
        raise ValueError(f"{label} carrier")
    raw = decode_b64(carrier["data"])
    if carrier["identity"] != identity(raw):
        raise ValueError(f"{label} identity")
    return raw


def _key(root: Path, carrier: Any, label: str, openssl: str) -> tuple[Path, dict[str, Any]]:
    expected = {"path", "spki"}
    if label == "timestamp authority":
        expected.add("id")
    if not exact_keys(carrier, expected):
        raise ValueError(f"{label} key carrier")
    path = confined(root, carrier["path"])
    der = public_der(path, openssl)
    if carrier["spki"] != identity(der):
        raise ValueError(f"{label} SPKI identity")
    if label == "timestamp authority" and carrier["id"] != AUTHORITY_ID:
        raise ValueError("timestamp authority id")
    return path, identity(der)


def _rfc3339_epoch(text: str) -> int:
    if not isinstance(text, str) or len(text) != 20 or not text.endswith("Z"):
        raise ValueError("RFC3339 timestamp")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("RFC3339 timestamp") from exc
    return int(parsed.timestamp())


def _source(root: Path) -> tuple[bytes, bytes, bytes, dict[str, Any]]:
    report_path = confined(root, "tests/fixtures/p1-a10/expected-report.json")
    capsule_path = confined(root, "tests/fixtures/p1-a10/capsule.json")
    report_raw = report_path.read_bytes()
    capsule_raw = capsule_path.read_bytes()
    report = strict_json(report_raw)
    capsule = strict_json(capsule_raw)
    if not isinstance(report, dict) or report.get("overall_result") != "conformant":
        raise ValueError("A10 report")
    if not isinstance(capsule, dict):
        raise ValueError("A10 capsule")
    recovered = capsule.get("recoveredAuthorization")
    if not isinstance(recovered, dict):
        raise ValueError("A10 recovered authorization")
    payload = _carrier_bytes(recovered.get("payload"), "A10 recovered authorization payload")
    if identity(payload)["digest"] != report.get("recovered_authorization_sha256"):
        raise ValueError("A10 recovered authorization report binding")
    return report_raw, capsule_raw, payload, report


def validate(root: Path, capsule_path: Path, openssl: str = "openssl") -> dict[str, Any]:
    capsule = strict_json(capsule_path.read_bytes())
    if not exact_keys(
        capsule,
        {
            "claimBoundary",
            "observations",
            "policy",
            "profile",
            "sourceAuthorization",
            "standard",
            "timestampAuthority",
            "timeTrustRoot",
        },
    ):
        raise ValueError("capsule fields")
    if capsule["standard"] != STANDARD or capsule["profile"] != PROFILE:
        raise ValueError("capsule constants")

    report_raw, a10_capsule_raw, recovered_payload, report = _source(root)
    source = capsule["sourceAuthorization"]
    expected_source = {
        "authorizationCapsule": {
            "path": "tests/fixtures/p1-a10/capsule.json",
            "identity": identity(a10_capsule_raw),
        },
        "authorizationReport": {
            "path": "tests/fixtures/p1-a10/expected-report.json",
            "identity": identity(report_raw),
        },
        "recoveredAuthorizationPayload": identity(recovered_payload),
        "releaseDescriptor": {
            "algorithm": "sha256",
            "bytes": 1278,
            "digest": report["release_descriptor_sha256"],
        },
        "releaseId": report["release_id"],
    }
    if source != expected_source:
        raise ValueError("source authorization binding")

    root_key, root_spki = _key(root, capsule["timeTrustRoot"], "time trust root", openssl)
    tsa_key, tsa_spki = _key(root, capsule["timestampAuthority"], "timestamp authority", openssl)

    expected_policy = {
        "action": "delegate-trusted-timestamp-authority",
        "authority": {"id": AUTHORITY_ID, "spki": tsa_spki},
        "claimBoundary": {
            "doesNotImply": [
                "supplied-time-root-does-not-prove-real-world-identity",
                "signed-time-does-not-prove-secure-clock-hardware",
                "fixture-window-does-not-establish-legal-effective-time",
                "trusted-time-does-not-imply-content-revocation",
            ]
        },
        "clockPolicy": {
            "observationSequenceStrictlyIncreasing": True,
            "rejectTimestampRegression": True,
            "rejectedObservationDoesNotAdvanceAcceptedClock": True,
        },
        "policyId": POLICY_ID,
        "policySequence": 1,
        "sourceAuthorization": expected_source,
        "standard": "EIGIIB-P1-A11-TIME-POLICY-1.0",
        "validityWindow": {
            "boundaryPolicy": "inclusive",
            "notAfterRfc3339": NOT_AFTER[0],
            "notAfterUnix": NOT_AFTER[1],
            "notBeforeRfc3339": NOT_BEFORE[0],
            "notBeforeUnix": NOT_BEFORE[1],
        },
    }
    policy = capsule["policy"]
    if not exact_keys(policy, {"envelope", "payload"}):
        raise ValueError("policy carrier")
    policy_payload = _carrier_bytes(policy["payload"], "time policy payload")
    if strict_json(policy_payload) != expected_policy:
        raise ValueError("time policy semantics")
    policy_envelope = _carrier_bytes(policy["envelope"], "time policy envelope")
    verify_cose_sign1(policy_envelope, policy_payload, POLICY_TYPE, root_key, openssl)

    observations = capsule["observations"]
    if not isinstance(observations, list) or len(observations) != len(OBSERVATIONS):
        raise ValueError("observation set")
    subject = {
        "authorizationReport": identity(report_raw),
        "recoveredAuthorizationPayload": identity(recovered_payload),
        "releaseDescriptor": expected_source["releaseDescriptor"],
        "releaseId": report["release_id"],
    }
    decisions: list[dict[str, Any]] = []
    accepted_ids: list[str] = []
    last_sequence: int | None = None
    last_accepted_time: int | None = None
    for row, (obs_id, sequence, rfc3339, epoch, expected_decision) in zip(observations, OBSERVATIONS):
        if not exact_keys(row, {"envelope", "expectedDecision", "id", "payload"}):
            raise ValueError("observation carrier")
        if row["id"] != obs_id or row["expectedDecision"] != expected_decision:
            raise ValueError("observation identity or expected decision")
        payload = _carrier_bytes(row["payload"], f"observation {obs_id} payload")
        expected_payload = {
            "authorityId": AUTHORITY_ID,
            "observationId": obs_id,
            "observationSequence": sequence,
            "policyId": POLICY_ID,
            "policySequence": 1,
            "purpose": "evaluate-release-authorization-validity",
            "standard": "EIGIIB-P1-A11-TIME-OBSERVATION-1.0",
            "subject": subject,
            "timestampRfc3339": rfc3339,
            "timestampUnix": epoch,
        }
        if strict_json(payload) != expected_payload:
            raise ValueError(f"observation {obs_id} semantics")
        if _rfc3339_epoch(rfc3339) != epoch:
            raise ValueError(f"observation {obs_id} timestamp representation")
        envelope = _carrier_bytes(row["envelope"], f"observation {obs_id} envelope")
        verify_cose_sign1(envelope, payload, OBSERVATION_TYPE, tsa_key, openssl)
        if last_sequence is not None and sequence <= last_sequence:
            raise ValueError("observation sequence rollback")
        last_sequence = sequence
        if epoch < NOT_BEFORE[1]:
            decision = "rejected-not-yet-valid"
        elif epoch > NOT_AFTER[1]:
            decision = "rejected-expired"
        elif last_accepted_time is not None and epoch < last_accepted_time:
            decision = "rejected-clock-rollback"
        else:
            decision = "conformant"
            last_accepted_time = epoch
            accepted_ids.append(obs_id)
        if decision != expected_decision:
            raise ValueError(f"observation {obs_id} decision")
        decisions.append(
            {
                "decision": decision,
                "id": obs_id,
                "observation_sequence": sequence,
                "timestamp_rfc3339": rfc3339,
                "timestamp_unix": epoch,
            }
        )

    boundary = capsule["claimBoundary"]
    if not exact_keys(boundary, {"doesNotImply"}) or boundary["doesNotImply"] != [
        "time-root-fixture-does-not-prove-real-world-operator-identity",
        "timestamp-signature-does-not-prove-clock-hardware-integrity",
        "validity-window-does-not-imply-legal-or-business-effective-time",
        "time-validation-does-not-imply-transparency-log-trust",
        "time-validation-does-not-imply-global-append-only-consistency",
        "time-validation-does-not-imply-content-revocation-or-withdrawal",
        "p1-a11-does-not-imply-production-release-governance",
    ]:
        raise ValueError("claim boundary")

    return {
        "standard": STANDARD,
        "tool": "eigiib-p1-a11-time-check",
        "tool_version": "0.1.0",
        "profile": PROFILE,
        "release_id": report["release_id"],
        "authorization_report_sha256": identity(report_raw)["digest"],
        "recovered_authorization_sha256": identity(recovered_payload)["digest"],
        "time_trust_root_spki_sha256": root_spki["digest"],
        "timestamp_authority_id": AUTHORITY_ID,
        "timestamp_authority_spki_sha256": tsa_spki["digest"],
        "time_policy_payload_sha256": identity(policy_payload)["digest"],
        "time_policy_envelope_sha256": identity(policy_envelope)["digest"],
        "not_before_rfc3339": NOT_BEFORE[0],
        "not_before_unix": NOT_BEFORE[1],
        "not_after_rfc3339": NOT_AFTER[0],
        "not_after_unix": NOT_AFTER[1],
        "observation_count": len(decisions),
        "observations": decisions,
        "accepted_observation_ids": accepted_ids,
        "last_accepted_timestamp_rfc3339": "2026-08-01T17:00:00Z",
        "last_accepted_timestamp_unix": 1785603600,
        "not_yet_valid_result": "rejected-as-required",
        "valid_window_result": "conformant",
        "clock_rollback_result": "rejected-as-required",
        "expiry_result": "rejected-as-required",
        "trusted_timestamp_authority_result": "conformant-for-supplied-time-root-delegation-scope",
        "trusted_effective_time_result": "conformant-for-signed-observation-and-closed-window-scope",
        "boundary": BOUNDARY,
        "claim_boundary": boundary["doesNotImply"],
        "overall_result": "conformant",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = validate(args.root.resolve(), args.capsule.resolve(), args.openssl)
        if args.expected and canonical_json(result) != args.expected.read_bytes():
            raise ValueError("canonical report differs")
        print(json.dumps(result if args.json else {"overall_result": result["overall_result"]}, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A11.TIME.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
