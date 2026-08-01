#!/usr/bin/env python3
"""Verify content revocation, registered-channel withdrawal and anti-rollback for P1-A13."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a13_common import (
    OBSERVATION_TYPE,
    POLICY_TYPE,
    PROFILE,
    REVOCATION_TYPE,
    STANDARD,
    WITHDRAWAL_TYPE,
    canonical_json,
    confined,
    decode_b64,
    exact_keys,
    identity,
    strict_json,
)
from eigiib_p1_a13_crypto import public_der, verify_cose_sign1

SOURCE_COMMIT = "286c17db08911ae22202aa30c90cac10dc3c61b8"
A12_REPORT_SHA256 = "7613429f8d3b771812433f5b57d64accb8148550ed9f8b71a38a97b23a45343c"
A12_CAPSULE_SHA256 = "12b3ca6c0ca260b3357993d65a8b4595f6cc23d4b8b26ca67dcee94e06148046"
RELEASE_ID = "eigiib-p1-a7-authority-1.0"
RELEASE_DESCRIPTOR_SHA256 = "1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec"
ARCHIVE_SHA256 = "0e3ce06e9ef4f9299ad5ade9182d3924704248230d924bec656562d58287960e"
RECOVERED_AUTHORIZATION_SHA256 = "d185060877ac9f63cfb1ae93f1b56aea16307ce090977bbc3e997036ae4a5d01"
TRUSTED_EFFECTIVE_TIME = 1785603600
ACCEPTED_CHECKPOINT_ROOT = "cbaa2980c0c57054a161f77c34a1300d86f4cd4c04a06fbcdde35ef5d4628641"
POLICY_ID = "eigiib-p1-a13-content-control-policy-1"
REVOCATION_ID = "eigiib-p1-a13-revocation-1"
REVOCATION_SEQUENCE = 31
BOUNDARY = "registered-content-revocation-distribution-withdrawal-anti-rollback-closure"

CONTENT = {
    "archiveSha256": ARCHIVE_SHA256,
    "releaseDescriptorSha256": RELEASE_DESCRIPTOR_SHA256,
    "releaseId": RELEASE_ID,
}
CHANNELS = [
    ("fixture-primary", "fixture-primary-operator", 32),
    ("fixture-mirror", "fixture-mirror-operator", 33),
]
REPLAY_DECISIONS = [
    ("pre-revocation-sequence", 30, "fixture-primary", "rejected-below-revocation-floor"),
    ("at-revocation-floor", 31, "fixture-mirror", "rejected-revoked-content"),
    ("newer-sequence-same-content", 34, "fixture-primary", "rejected-revoked-content"),
]
CLAIM_BOUNDARY = [
    "content-revocation-does-not-erase-published-bytes",
    "registered-channel-withdrawal-does-not-prove-global-unavailability",
    "anti-rollback-does-not-prove-absence-from-unregistered-mirrors",
    "revocation-does-not-establish-vulnerability-remediation",
    "withdrawal-does-not-establish-durable-purge",
    "fixture-control-root-does-not-prove-real-world-operator-identity",
    "p1-a13-does-not-imply-live-github-or-registry-publication",
]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source(root: Path) -> dict[str, Any]:
    a12_report_path = confined(root, "tests/fixtures/p1-a12/expected-report.json")
    a12_report_raw = a12_report_path.read_bytes()
    if _sha256(a12_report_raw) != A12_REPORT_SHA256:
        raise ValueError("A12 report identity")
    a12 = strict_json(a12_report_raw)
    if not isinstance(a12, dict) or a12.get("overall_result") != "conformant":
        raise ValueError("A12 report")
    if a12.get("release_id") != RELEASE_ID or a12.get("trusted_effective_time_unix") != TRUSTED_EFFECTIVE_TIME:
        raise ValueError("A12 release/time binding")
    if a12.get("recovered_checkpoint_root") != ACCEPTED_CHECKPOINT_ROOT:
        raise ValueError("A12 accepted checkpoint")
    if a12.get("trusted_transparency_service_result") != "conformant-for-root-registered-successor-and-quarantined-predecessor-scope":
        raise ValueError("A12 transparency result")
    if a12.get("append_only_consistency_result") != "conformant-for-accepted-2-to-4-to-8-history-scope":
        raise ValueError("A12 consistency result")

    a12_state = strict_json(confined(root, "conformance/p1-a12-transparency.json").read_bytes())
    if not isinstance(a12_state, dict) or a12_state.get("source_commit") != "356949456e8d4084ce317f45f5912522150ecd97":
        raise ValueError("A12 state source")
    if a12_state.get("capsule_sha256") != A12_CAPSULE_SHA256:
        raise ValueError("A12 capsule authority")

    a10 = strict_json(confined(root, "tests/fixtures/p1-a10/expected-report.json").read_bytes())
    a11 = strict_json(confined(root, "tests/fixtures/p1-a11/expected-report.json").read_bytes())
    if not isinstance(a10, dict) or not isinstance(a11, dict):
        raise ValueError("source reports")
    if a10.get("release_descriptor_sha256") != RELEASE_DESCRIPTOR_SHA256 or a10.get("recovered_authorization_sha256") != RECOVERED_AUTHORIZATION_SHA256:
        raise ValueError("A10 source authority")
    if a11.get("recovered_authorization_sha256") != RECOVERED_AUTHORIZATION_SHA256 or a11.get("last_accepted_timestamp_unix") != TRUSTED_EFFECTIVE_TIME:
        raise ValueError("A11 source authority")

    return {
        "acceptedTransparencyCheckpointRoot": ACCEPTED_CHECKPOINT_ROOT,
        "releaseDescriptorSha256": RELEASE_DESCRIPTOR_SHA256,
        "releaseId": RELEASE_ID,
        "recoveredAuthorizationSha256": RECOVERED_AUTHORIZATION_SHA256,
        "sourceCommit": SOURCE_COMMIT,
        "transparencyCapsuleSha256": A12_CAPSULE_SHA256,
        "transparencyReportSha256": A12_REPORT_SHA256,
        "trustedEffectiveTimeUnix": TRUSTED_EFFECTIVE_TIME,
    }


def _carrier_bytes(carrier: Any, label: str) -> bytes:
    if not exact_keys(carrier, {"data", "identity"}):
        raise ValueError(f"{label} carrier")
    raw = decode_b64(carrier["data"])
    if carrier["identity"] != identity(raw):
        raise ValueError(f"{label} identity")
    return raw


def _key(root: Path, carrier: Any, label: str, openssl: str, *, with_id: bool = False, channel: bool = False) -> tuple[Path, dict[str, Any]]:
    keys = {"path", "spki"}
    if with_id:
        keys.add("id")
    if channel:
        keys |= {"channelId", "operatorId"}
    if not exact_keys(carrier, keys):
        raise ValueError(f"{label} key carrier")
    path = confined(root, carrier["path"])
    der = public_der(path, openssl)
    ident = identity(der)
    if carrier["spki"] != ident:
        raise ValueError(f"{label} SPKI identity")
    return path, ident


def _signed(carrier: Any, expected: dict[str, Any], content_type: str, key: Path, openssl: str, label: str) -> tuple[bytes, bytes]:
    if not exact_keys(carrier, {"payload", "envelope"}):
        raise ValueError(f"{label} signed carrier")
    payload = _carrier_bytes(carrier["payload"], f"{label} payload")
    expected_raw = canonical_json(expected)
    if payload != expected_raw:
        raise ValueError(f"{label} semantics")
    envelope = _carrier_bytes(carrier["envelope"], f"{label} envelope")
    verify_cose_sign1(envelope, payload, content_type, key, openssl)
    return payload, envelope


def _policy_expected(source: dict[str, Any], root_spki: dict[str, Any], revoker: dict[str, Any], channels: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "action": "register-content-control-policy",
        "antiRollbackPolicy": {
            "floorMode": "revocation-sequence-inclusive",
            "rejectedObservationDoesNotAdvanceHistory": True,
            "revokedDigestRemainsRejectedAboveFloor": True,
        },
        "channels": channels,
        "claimBoundary": {"doesNotImply": CLAIM_BOUNDARY},
        "contentControlRootSpki": root_spki,
        "policyId": POLICY_ID,
        "policySequence": 30,
        "revocationAuthority": revoker,
        "sourceAuthority": source,
        "standard": "EIGIIB-P1-A13-POLICY-1.0",
    }


def evaluate(root: Path, capsule_path: Path, openssl: str = "openssl") -> dict[str, Any]:
    capsule = strict_json(capsule_path.read_bytes())
    required = {"standard", "profile", "sourceAuthority", "contentControlRoot", "revocationAuthority", "channels", "policy", "revocation", "withdrawals", "replays", "claimBoundary"}
    if not isinstance(capsule, dict) or set(capsule) != required or capsule.get("standard") != STANDARD or capsule.get("profile") != PROFILE:
        raise ValueError("capsule structure")

    source = _source(root)
    if capsule["sourceAuthority"] != source:
        raise ValueError("source authority binding")
    if capsule["claimBoundary"] != CLAIM_BOUNDARY:
        raise ValueError("claim boundary")

    root_key, root_spki = _key(root, capsule["contentControlRoot"], "content-control root", openssl)
    revoker_key, revoker_spki = _key(root, capsule["revocationAuthority"], "revocation authority", openssl, with_id=True)
    if capsule["revocationAuthority"]["id"] != "eigiib-p1-a13-revoker-1":
        raise ValueError("revocation authority id")
    revoker = {"id": capsule["revocationAuthority"]["id"], "spki": revoker_spki}

    channel_rows = capsule["channels"]
    if not isinstance(channel_rows, list) or len(channel_rows) != 2:
        raise ValueError("channel count")
    channel_keys: dict[str, Path] = {}
    channel_specs: list[dict[str, Any]] = []
    for row, expected in zip(channel_rows, CHANNELS, strict=True):
        key, spki = _key(root, row, f"channel {expected[0]}", openssl, channel=True)
        if row["channelId"] != expected[0] or row["operatorId"] != expected[1]:
            raise ValueError("channel identity")
        channel_keys[expected[0]] = key
        channel_specs.append({"channelId": expected[0], "operatorId": expected[1], "spki": spki})

    policy_expected = _policy_expected(source, root_spki, revoker, channel_specs)
    _, policy_envelope = _signed(capsule["policy"], policy_expected, POLICY_TYPE, root_key, openssl, "policy")
    policy_identity = identity(policy_envelope)

    revocation_expected = {
        "action": "revoke-content",
        "content": CONTENT,
        "effectiveTimeUnix": 1785607200,
        "policyEnvelope": policy_identity,
        "reasonCode": "security-withdrawal",
        "replacement": None,
        "revocationId": REVOCATION_ID,
        "revocationSequence": REVOCATION_SEQUENCE,
        "sourceAuthority": source,
        "standard": "EIGIIB-P1-A13-REVOCATION-1.0",
    }
    _, revocation_envelope = _signed(capsule["revocation"], revocation_expected, REVOCATION_TYPE, revoker_key, openssl, "revocation")
    revocation_identity = identity(revocation_envelope)

    withdrawals = capsule["withdrawals"]
    if not isinstance(withdrawals, list) or len(withdrawals) != 2:
        raise ValueError("withdrawal count")
    withdrawn_channels: list[str] = []
    accepted_history = ["policy-sequence-30", "revocation-sequence-31"]
    for index, (row, spec) in enumerate(zip(withdrawals, CHANNELS, strict=True)):
        channel_id, operator_id, sequence = spec
        expected = {
            "action": "withdraw-distribution",
            "availabilityState": "withdrawn-from-registered-channel",
            "channel": {"channelId": channel_id, "operatorId": operator_id},
            "content": CONTENT,
            "observedAtUnix": 1785609000 + index * 60,
            "policyEnvelope": policy_identity,
            "revocationEnvelope": revocation_identity,
            "standard": "EIGIIB-P1-A13-WITHDRAWAL-1.0",
            "withdrawalId": f"eigiib-p1-a13-withdrawal-{channel_id}",
            "withdrawalSequence": sequence,
        }
        _signed(row, expected, WITHDRAWAL_TYPE, channel_keys[channel_id], openssl, f"withdrawal {channel_id}")
        withdrawn_channels.append(channel_id)
        accepted_history.append(f"{channel_id}-withdrawal-sequence-{sequence}")

    replays = capsule["replays"]
    if not isinstance(replays, list) or len(replays) != len(REPLAY_DECISIONS):
        raise ValueError("replay count")
    replay_results: list[dict[str, Any]] = []
    for index, (row, spec) in enumerate(zip(replays, REPLAY_DECISIONS, strict=True)):
        replay_id, sequence, channel_id, expected_decision = spec
        if not isinstance(row, dict) or set(row) != {"id", "observation", "expectedDecision"}:
            raise ValueError("replay carrier")
        if row["id"] != replay_id or row["expectedDecision"] != expected_decision:
            raise ValueError("replay expectation")
        operator_id = next(item[1] for item in CHANNELS if item[0] == channel_id)
        expected = {
            "action": "observe-distribution",
            "channel": {"channelId": channel_id, "operatorId": operator_id},
            "content": CONTENT,
            "distributionSequence": sequence,
            "observedAtUnix": 1785609600 + index * 60,
            "policyEnvelope": policy_identity,
            "standard": "EIGIIB-P1-A13-OBSERVATION-1.0",
        }
        _signed(row["observation"], expected, OBSERVATION_TYPE, channel_keys[channel_id], openssl, f"replay {replay_id}")
        decision = "rejected-below-revocation-floor" if sequence < REVOCATION_SEQUENCE else "rejected-revoked-content"
        if decision != expected_decision:
            raise ValueError("anti-rollback decision")
        replay_results.append({"decision": decision, "id": replay_id, "sequence": sequence})

    return {
        "accepted_history": accepted_history,
        "anti_rollback_floor_sequence": REVOCATION_SEQUENCE,
        "anti_rollback_result": "conformant-for-revocation-floor-and-registered-channel-history-scope",
        "boundary": BOUNDARY,
        "claim_boundary": CLAIM_BOUNDARY,
        "content_archive_sha256": ARCHIVE_SHA256,
        "content_revocation_result": "conformant-for-exact-release-content-scope",
        "distribution_withdrawal_result": "conformant-for-two-registered-fixture-channels-scope",
        "global_content_unavailability_result": "not-claimed",
        "overall_result": "conformant",
        "policy_envelope_sha256": _sha256(policy_envelope),
        "profile": PROFILE,
        "registered_channel_ids": [item[0] for item in CHANNELS],
        "release_descriptor_sha256": RELEASE_DESCRIPTOR_SHA256,
        "release_id": RELEASE_ID,
        "replay_results": replay_results,
        "revocation_envelope_sha256": _sha256(revocation_envelope),
        "revocation_id": REVOCATION_ID,
        "revocation_sequence": REVOCATION_SEQUENCE,
        "source_transparency_capsule_sha256": A12_CAPSULE_SHA256,
        "source_transparency_report_sha256": A12_REPORT_SHA256,
        "standard": STANDARD,
        "tool": "eigiib-p1-a13-revocation-check",
        "tool_version": "0.1.0",
        "trusted_effective_time_unix": TRUSTED_EFFECTIVE_TIME,
        "vulnerability_remediation_result": "not-claimed",
        "withdrawn_channel_ids": withdrawn_channels,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, default=Path("tests/fixtures/p1-a13/capsule.json"))
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        capsule = args.capsule if args.capsule.is_absolute() else root / args.capsule
        result = evaluate(root, capsule, args.openssl)
        if args.expected:
            expected_path = args.expected if args.expected.is_absolute() else root / args.expected
            expected = strict_json(expected_path.read_bytes())
            if result != expected:
                raise ValueError("expected report mismatch")
        if args.json:
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        else:
            print(result["overall_result"])
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"overall_result": "non-conformant", "error": str(exc)}, sort_keys=True, separators=(",", ":")))
        else:
            print(f"non-conformant: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
