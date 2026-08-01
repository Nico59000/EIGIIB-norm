#!/usr/bin/env python3
"""Verify delegated threshold authorization and delegate revocation for P1-A10."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a10_common import (
    APPROVAL_TYPE,
    POLICY_TYPE,
    PROFILE,
    REVOCATION_TYPE,
    STANDARD,
    canonical_json,
    confined,
    decode_b64,
    exact_keys,
    identity,
    strict_json,
)
from eigiib_p1_a10_crypto import public_der, verify_cose_sign1

POLICY_ID = "eigiib-p1-a10-release-policy-1"
ROLE = "release-approver"
THRESHOLD = 2
INITIAL_SEQUENCE = 10
REVOCATION_SEQUENCE = 11
RECOVERED_SEQUENCE = 12
REVOKED_DELEGATE = "delegate-b"


def _carrier_bytes(carrier: Any, label: str) -> bytes:
    if not exact_keys(carrier, {"data", "identity"}):
        raise ValueError(f"{label} carrier")
    raw = decode_b64(carrier["data"])
    if carrier["identity"] != identity(raw):
        raise ValueError(f"{label} identity")
    return raw


def _key(root: Path, carrier: Any, label: str, openssl: str) -> tuple[Path, dict[str, Any]]:
    expected = {"path", "spki"}
    if label.startswith("delegate"):
        expected.add("id")
    if not exact_keys(carrier, expected):
        raise ValueError(f"{label} key carrier")
    path = confined(root, carrier["path"])
    der = public_der(path, openssl)
    if carrier["spki"] != identity(der):
        raise ValueError(f"{label} SPKI identity")
    return path, carrier["spki"]


def _approval_set(
    root: Path,
    approvals: Any,
    payload: bytes,
    delegates: dict[str, tuple[Path, dict[str, Any]]],
    evaluation_sequence: int,
    revoked_delegate: str,
    revocation_sequence: int,
    openssl: str,
) -> tuple[list[str], list[str]]:
    if not isinstance(approvals, list) or len(approvals) != THRESHOLD:
        raise ValueError("approval count")
    signer_ids: list[str] = []
    active_ids: list[str] = []
    for row in approvals:
        if not exact_keys(row, {"delegateId", "envelope"}):
            raise ValueError("approval carrier")
        delegate_id = row["delegateId"]
        if not isinstance(delegate_id, str) or delegate_id not in delegates:
            raise ValueError("unknown delegate")
        if delegate_id in signer_ids:
            raise ValueError("duplicate delegate approval")
        envelope = _carrier_bytes(row["envelope"], f"approval {delegate_id}")
        verify_cose_sign1(
            envelope,
            payload,
            APPROVAL_TYPE,
            delegates[delegate_id][0],
            openssl,
        )
        signer_ids.append(delegate_id)
        if not (
            delegate_id == revoked_delegate
            and evaluation_sequence >= revocation_sequence
        ):
            active_ids.append(delegate_id)
    return signer_ids, active_ids


def validate(
    root: Path,
    capsule_path: Path,
    openssl: str = "openssl",
) -> dict[str, Any]:
    capsule = strict_json(capsule_path.read_bytes())
    if not exact_keys(
        capsule,
        {
            "claimBoundary",
            "delegates",
            "initialAuthorization",
            "policy",
            "profile",
            "recoveredAuthorization",
            "revocation",
            "sourceRelease",
            "sourceReleaseSigner",
            "staleReplay",
            "standard",
            "trustRoot",
        },
    ):
        raise ValueError("capsule fields")
    if capsule["standard"] != STANDARD or capsule["profile"] != PROFILE:
        raise ValueError("capsule constants")

    source = capsule["sourceRelease"]
    if not exact_keys(source, {"identity", "path", "releaseId"}):
        raise ValueError("source release carrier")
    release_path = confined(root, source["path"])
    release_raw = release_path.read_bytes()
    release_doc = strict_json(release_raw)
    if source != {
        "identity": identity(release_raw),
        "path": source["path"],
        "releaseId": release_doc["releaseId"],
    }:
        raise ValueError("source release identity")

    release_key, release_spki = _key(
        root, capsule["sourceReleaseSigner"], "release signer", openssl
    )
    del release_key
    root_key, root_spki = _key(root, capsule["trustRoot"], "trust root", openssl)

    delegates_value = capsule["delegates"]
    if not isinstance(delegates_value, list) or len(delegates_value) != 3:
        raise ValueError("delegate set")
    delegates: dict[str, tuple[Path, dict[str, Any]]] = {}
    for row in delegates_value:
        path, spki = _key(root, row, f"delegate {row.get('id')}", openssl)
        delegate_id = row["id"]
        if delegate_id in delegates:
            raise ValueError("duplicate delegate")
        delegates[delegate_id] = (path, spki)
    if list(delegates) != ["delegate-a", "delegate-b", "delegate-c"]:
        raise ValueError("delegate order or identifiers")

    expected_policy = {
        "action": "delegate-release-authorization",
        "claimBoundary": {
            "doesNotImply": [
                "supplied-root-does-not-prove-real-world-identity",
                "sequence-does-not-imply-trusted-time",
                "delegate-revocation-does-not-imply-content-revocation",
                "fixture-authorization-does-not-imply-production-governance",
            ]
        },
        "delegates": [
            {"id": delegate_id, "spki": delegates[delegate_id][1]}
            for delegate_id in delegates
        ],
        "policyId": POLICY_ID,
        "policySequence": 1,
        "releaseScope": {
            "releaseDescriptor": identity(release_raw),
            "releaseId": release_doc["releaseId"],
            "releaseSignerSpki": release_spki,
        },
        "revocationAuthoritySpki": root_spki,
        "role": ROLE,
        "standard": "EIGIIB-P1-A10-POLICY-1.0",
        "threshold": THRESHOLD,
    }
    policy = capsule["policy"]
    if not exact_keys(policy, {"envelope", "payload"}):
        raise ValueError("policy carrier")
    policy_payload = _carrier_bytes(policy["payload"], "policy payload")
    if strict_json(policy_payload) != expected_policy:
        raise ValueError("policy semantics")
    policy_envelope = _carrier_bytes(policy["envelope"], "policy envelope")
    verify_cose_sign1(policy_envelope, policy_payload, POLICY_TYPE, root_key, openssl)

    expected_initial = {
        "action": "authorize-release",
        "authorizationSequence": INITIAL_SEQUENCE,
        "policyId": POLICY_ID,
        "policySequence": 1,
        "releaseDescriptor": identity(release_raw),
        "releaseId": release_doc["releaseId"],
        "releaseSignerSpki": release_spki,
        "standard": "EIGIIB-P1-A10-AUTHORIZATION-1.0",
    }
    initial = capsule["initialAuthorization"]
    if not exact_keys(initial, {"approvals", "evaluationSequence", "payload"}):
        raise ValueError("initial authorization carrier")
    if initial["evaluationSequence"] != INITIAL_SEQUENCE:
        raise ValueError("initial evaluation sequence")
    initial_payload = _carrier_bytes(initial["payload"], "initial authorization payload")
    if strict_json(initial_payload) != expected_initial:
        raise ValueError("initial authorization semantics")

    revocation = capsule["revocation"]
    if not exact_keys(revocation, {"envelope", "payload"}):
        raise ValueError("revocation carrier")
    revocation_payload = _carrier_bytes(revocation["payload"], "revocation payload")
    expected_revocation = {
        "action": "revoke-delegate-authorization",
        "claimBoundary": {
            "doesNotImply": [
                "content-revocation",
                "distribution-withdrawal",
                "trusted-effective-time",
            ]
        },
        "policyId": POLICY_ID,
        "policySequence": 1,
        "revocationSequence": REVOCATION_SEQUENCE,
        "scope": "evaluations-at-or-after-revocation-sequence",
        "standard": "EIGIIB-P1-A10-REVOCATION-1.0",
        "subjectDelegateId": REVOKED_DELEGATE,
        "subjectSpki": delegates[REVOKED_DELEGATE][1],
    }
    if strict_json(revocation_payload) != expected_revocation:
        raise ValueError("revocation semantics")
    revocation_envelope = _carrier_bytes(revocation["envelope"], "revocation envelope")
    verify_cose_sign1(
        revocation_envelope, revocation_payload, REVOCATION_TYPE, root_key, openssl
    )

    initial_signers, initial_active = _approval_set(
        root,
        initial["approvals"],
        initial_payload,
        delegates,
        INITIAL_SEQUENCE,
        REVOKED_DELEGATE,
        REVOCATION_SEQUENCE,
        openssl,
    )
    if len(initial_active) < THRESHOLD:
        raise ValueError("initial threshold")

    stale = capsule["staleReplay"]
    if stale != {
        "evaluationSequence": RECOVERED_SEQUENCE,
        "expected": "rejected-revoked-threshold",
        "usesAuthorizationSequence": INITIAL_SEQUENCE,
    }:
        raise ValueError("stale replay carrier")
    _, stale_active = _approval_set(
        root,
        initial["approvals"],
        initial_payload,
        delegates,
        stale["evaluationSequence"],
        REVOKED_DELEGATE,
        REVOCATION_SEQUENCE,
        openssl,
    )
    if len(stale_active) >= THRESHOLD:
        raise ValueError("stale replay unexpectedly authorized")

    expected_recovered = {
        "action": "authorize-release",
        "authorizationSequence": RECOVERED_SEQUENCE,
        "policyId": POLICY_ID,
        "policySequence": 1,
        "releaseDescriptor": identity(release_raw),
        "releaseId": release_doc["releaseId"],
        "releaseSignerSpki": release_spki,
        "standard": "EIGIIB-P1-A10-AUTHORIZATION-1.0",
    }
    recovered = capsule["recoveredAuthorization"]
    if not exact_keys(recovered, {"approvals", "evaluationSequence", "payload"}):
        raise ValueError("recovered authorization carrier")
    if recovered["evaluationSequence"] != RECOVERED_SEQUENCE:
        raise ValueError("recovered evaluation sequence")
    recovered_payload = _carrier_bytes(
        recovered["payload"], "recovered authorization payload"
    )
    if strict_json(recovered_payload) != expected_recovered:
        raise ValueError("recovered authorization semantics")
    recovered_signers, recovered_active = _approval_set(
        root,
        recovered["approvals"],
        recovered_payload,
        delegates,
        RECOVERED_SEQUENCE,
        REVOKED_DELEGATE,
        REVOCATION_SEQUENCE,
        openssl,
    )
    if recovered_signers != ["delegate-a", "delegate-c"] or len(recovered_active) < THRESHOLD:
        raise ValueError("recovered threshold")

    boundary = capsule["claimBoundary"]
    if not exact_keys(boundary, {"doesNotImply"}) or not isinstance(
        boundary["doesNotImply"], list
    ) or len(boundary["doesNotImply"]) < 8:
        raise ValueError("claim boundary")

    return {
        "standard": STANDARD,
        "profile": PROFILE,
        "tool": "eigiib-p1-a10-authorization-check",
        "tool_version": "0.1.0",
        "release_id": release_doc["releaseId"],
        "release_descriptor_sha256": identity(release_raw)["digest"],
        "release_signer_spki_sha256": release_spki["digest"],
        "trust_root_spki_sha256": root_spki["digest"],
        "policy_payload_sha256": identity(policy_payload)["digest"],
        "policy_envelope_sha256": identity(policy_envelope)["digest"],
        "initial_authorization_sha256": identity(initial_payload)["digest"],
        "revocation_sha256": identity(revocation_payload)["digest"],
        "recovered_authorization_sha256": identity(recovered_payload)["digest"],
        "delegate_count": len(delegates),
        "threshold": THRESHOLD,
        "initial_approval_ids": initial_signers,
        "revoked_delegate_id": REVOKED_DELEGATE,
        "revocation_sequence": REVOCATION_SEQUENCE,
        "recovered_approval_ids": recovered_signers,
        "trusted_release_signer_result": "conformant-for-supplied-root-policy-scope",
        "authorized_release_signer_result": "conformant-for-exact-release-descriptor-scope",
        "initial_threshold_result": "conformant",
        "delegate_revocation_result": "conformant",
        "stale_approval_replay_result": "rejected-as-required",
        "recovered_threshold_result": "conformant",
        "overall_result": "conformant",
        "findings": [],
        "claim_boundary": boundary["doesNotImply"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = validate(args.root.resolve(), args.capsule, args.openssl)
        if args.expected and canonical_json(report) != args.expected.read_bytes():
            raise ValueError("canonical report differs")
        print(
            json.dumps(
                report
                if args.json
                else {
                    "overall_result": report["overall_result"],
                    "policy_envelope_sha256": report["policy_envelope_sha256"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"P1A10.AUTHORIZATION.FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
