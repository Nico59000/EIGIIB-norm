#!/usr/bin/env python3
"""Verify advisory binding, remediation lineage and fixed-release replay for P1-A14."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a14_common import (
    ADVISORY_TYPE,
    CANDIDATE_TYPE,
    FIXED_RELEASE_TYPE,
    POLICY_TYPE,
    PROFILE,
    REMEDIATION_TYPE,
    STANDARD,
    canonical_json,
    confined,
    decode_b64,
    exact_keys,
    identity,
    strict_json,
)
from eigiib_p1_a13_crypto import public_der, verify_cose_sign1

SOURCE_COMMIT = "077634971f2c16f3f74eb4c6c5b75aa7099bee55"
A13_REPORT_SHA256 = "7cbae1b7b686149b91bcea58d365e0700155185e78ac213913a0f3f07943e70b"
A13_CAPSULE_SHA256 = "fb596478e6cad8fe4c8db9e95d54f138cb37f9452a32d938e3d2796ab49240f5"
A13_REVOCATION_ENVELOPE_SHA256 = "f15badfb9b3c36468f2f8af72be9fa8263731d334b8a55526079cccfe94ea9ed"
A13_BOUNDARY = "registered-content-revocation-distribution-withdrawal-anti-rollback-closure"
TRUSTED_EFFECTIVE_TIME = 1785603600

REVOKED_RELEASE_ID = "eigiib-p1-a7-authority-1.0"
REVOKED_RELEASE_DESCRIPTOR_SHA256 = "1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec"
REVOKED_ARCHIVE_SHA256 = "0e3ce06e9ef4f9299ad5ade9182d3924704248230d924bec656562d58287960e"
REVOCATION_ID = "eigiib-p1-a13-revocation-1"
REVOCATION_SEQUENCE = 31

POLICY_ID = "eigiib-p1-a14-remediation-policy-1"
POLICY_SEQUENCE = 40
ADVISORY_ID = "EIGIIB-SA-FIXTURE-2026-0001"
ADVISORY_SEQUENCE = 41
VULNERABILITY_IDS = ["EIGIIB-FIXTURE-VULN-2026-0001"]
REMEDIATION_ID = "eigiib-p1-a14-remediation-1"
REMEDIATION_SEQUENCE = 42
FIXED_RELEASE_ID = "eigiib-p1-a14-fixed-1.1"
FIXED_RELEASE_VERSION = "1.1.0"
FIXED_RELEASE_SEQUENCE = 43
BOUNDARY = "registered-advisory-remediation-lineage-fixed-release-replay-closure"

SOURCE_ACCEPTED_HISTORY = [
    "policy-sequence-30",
    "revocation-sequence-31",
    "fixture-primary-withdrawal-sequence-32",
    "fixture-mirror-withdrawal-sequence-33",
]
REVOKED_CONTENT = {
    "archiveSha256": REVOKED_ARCHIVE_SHA256,
    "releaseDescriptorSha256": REVOKED_RELEASE_DESCRIPTOR_SHA256,
    "releaseId": REVOKED_RELEASE_ID,
}
CLAIM_BOUNDARY = [
    "advisory-binding-does-not-prove-an-external-vulnerability-assignment",
    "remediation-lineage-does-not-independently-prove-semantic-defect-removal",
    "fixed-release-identity-does-not-prove-production-release-authorization",
    "fixture-replay-does-not-prove-live-github-or-registry-publication",
    "accepted-fixed-release-does-not-unrevoke-the-predecessor-content",
    "exact-digest-equality-does-not-prove-universal-interoperability",
    "fixture-authorities-do-not-prove-real-world-organizational-control",
    "p1-a14-does-not-establish-global-availability-or-durable-persistence",
]
REPLAY_SPECS = [
    ("idempotent-fixed-release", 43, "exact", "exact", "accepted-idempotent-fixed-release-replay"),
    ("revoked-predecessor", 44, "revoked", "exact", "rejected-revoked-predecessor"),
    ("same-id-altered-archive", 45, "altered-archive", "exact", "rejected-fixed-release-content-substitution"),
    ("wrong-advisory-lineage", 46, "exact", "wrong-advisory", "rejected-advisory-lineage-mismatch"),
    ("below-fixed-release-floor", 42, "exact", "exact", "rejected-below-fixed-release-floor"),
]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _carrier_bytes(carrier: Any, label: str) -> bytes:
    if not exact_keys(carrier, {"data", "identity"}):
        raise ValueError(f"{label} carrier")
    raw = decode_b64(carrier["data"])
    if carrier["identity"] != identity(raw):
        raise ValueError(f"{label} identity")
    return raw


def _key(root: Path, carrier: Any, label: str, openssl: str, *, with_id: bool = False) -> tuple[Path, dict[str, Any]]:
    keys = {"path", "spki"}
    if with_id:
        keys.add("id")
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
    if payload != canonical_json(expected):
        raise ValueError(f"{label} semantics")
    envelope = _carrier_bytes(carrier["envelope"], f"{label} envelope")
    verify_cose_sign1(envelope, payload, content_type, key, openssl)
    return payload, envelope


def _source(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    report_raw = confined(root, "tests/fixtures/p1-a13/expected-report.json").read_bytes()
    if _sha256(report_raw) != A13_REPORT_SHA256:
        raise ValueError("A13 report identity")
    report = strict_json(report_raw)
    if not isinstance(report, dict) or report.get("overall_result") != "conformant":
        raise ValueError("A13 report")
    expected = {
        "boundary": A13_BOUNDARY,
        "release_id": REVOKED_RELEASE_ID,
        "release_descriptor_sha256": REVOKED_RELEASE_DESCRIPTOR_SHA256,
        "content_archive_sha256": REVOKED_ARCHIVE_SHA256,
        "revocation_id": REVOCATION_ID,
        "revocation_sequence": REVOCATION_SEQUENCE,
        "vulnerability_remediation_result": "not-claimed",
        "accepted_history": SOURCE_ACCEPTED_HISTORY,
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise ValueError(f"A13 report {key}")

    capsule_raw = confined(root, "tests/fixtures/p1-a13/capsule.json").read_bytes()
    if _sha256(capsule_raw) != A13_CAPSULE_SHA256:
        raise ValueError("A13 capsule identity")
    capsule = strict_json(capsule_raw)
    if not isinstance(capsule, dict):
        raise ValueError("A13 capsule")
    revocation = capsule.get("revocation")
    if not isinstance(revocation, dict):
        raise ValueError("A13 revocation carrier")
    envelope = _carrier_bytes(revocation.get("envelope"), "A13 revocation envelope")
    revocation_envelope_identity = identity(envelope)
    if revocation_envelope_identity["digest"] != A13_REVOCATION_ENVELOPE_SHA256:
        raise ValueError("A13 revocation envelope identity")

    state = strict_json(confined(root, "conformance/p1-a13-revocation.json").read_bytes())
    if not isinstance(state, dict) or state.get("capsule_sha256") != A13_CAPSULE_SHA256:
        raise ValueError("A13 conformance capsule authority")
    if state.get("boundary") != A13_BOUNDARY or state.get("decisions", {}).get("overall_result") != "conformant":
        raise ValueError("A13 conformance state")

    source = {
        "acceptedHistory": SOURCE_ACCEPTED_HISTORY,
        "archiveSha256": REVOKED_ARCHIVE_SHA256,
        "boundary": A13_BOUNDARY,
        "releaseDescriptorSha256": REVOKED_RELEASE_DESCRIPTOR_SHA256,
        "releaseId": REVOKED_RELEASE_ID,
        "revocationCapsuleSha256": A13_CAPSULE_SHA256,
        "revocationEnvelope": revocation_envelope_identity,
        "revocationId": REVOCATION_ID,
        "revocationReportSha256": A13_REPORT_SHA256,
        "revocationSequence": REVOCATION_SEQUENCE,
        "sourceCommit": SOURCE_COMMIT,
        "trustedEffectiveTimeUnix": TRUSTED_EFFECTIVE_TIME,
    }
    return source, revocation_envelope_identity


def _artifact(root: Path, path: str) -> tuple[bytes, dict[str, Any]]:
    raw = confined(root, path).read_bytes()
    return raw, {"path": path, "identity": identity(raw)}


def fixture_artifacts(root: Path) -> dict[str, Any]:
    archive_raw, archive = _artifact(root, "tests/fixtures/p1-a14/fixed-release-archive.txt")
    change_raw, change_set = _artifact(root, "tests/fixtures/p1-a14/remediation-change-set.json")
    change_value = strict_json(change_raw)
    expected_change = {
        "changes": [
            "reject-revoked-fixture-content",
            "bind-parser-state-to-fixed-release",
            "preserve-predecessor-revocation-floor",
        ],
        "fixtureOnly": True,
        "standard": "EIGIIB-P1-A14-CHANGESET-1.0",
        "vulnerabilityIds": VULNERABILITY_IDS,
    }
    if change_value != expected_change or change_raw != canonical_json(expected_change):
        raise ValueError("change-set artifact")
    descriptor_raw, descriptor = _artifact(root, "tests/fixtures/p1-a14/fixed-release-descriptor.json")
    expected_descriptor = {
        "advisoryId": ADVISORY_ID,
        "archive": archive,
        "changeSet": change_set,
        "predecessor": REVOKED_CONTENT,
        "releaseId": FIXED_RELEASE_ID,
        "standard": "EIGIIB-P1-A14-FIXED-RELEASE-DESCRIPTOR-1.0",
        "version": FIXED_RELEASE_VERSION,
    }
    if strict_json(descriptor_raw) != expected_descriptor or descriptor_raw != canonical_json(expected_descriptor):
        raise ValueError("fixed-release descriptor artifact")
    content = {
        "archiveSha256": _sha256(archive_raw),
        "releaseDescriptorSha256": _sha256(descriptor_raw),
        "releaseId": FIXED_RELEASE_ID,
    }
    return {
        "archive": archive,
        "changeSet": change_set,
        "content": content,
        "descriptor": descriptor,
    }


def _policy_expected(
    source: dict[str, Any],
    root_spki: dict[str, Any],
    advisory_authority: dict[str, Any],
    remediation_authority: dict[str, Any],
    fixed_release_signer: dict[str, Any],
) -> dict[str, Any]:
    return {
        "action": "register-remediation-policy",
        "advisoryAuthority": advisory_authority,
        "claimBoundary": {"doesNotImply": CLAIM_BOUNDARY},
        "fixedReleaseSigner": fixed_release_signer,
        "lineagePolicy": {
            "advisoryMustBindExactRevokedContent": True,
            "exactAdvisoryAndRemediationBindingsRequired": True,
            "fixedReleaseFloorSequence": FIXED_RELEASE_SEQUENCE,
            "idempotentExactReplayDoesNotAdvanceHistory": True,
            "revokedPredecessorRemainsRejected": True,
            "sameReleaseIdRequiresExactDescriptorAndArchive": True,
        },
        "policyId": POLICY_ID,
        "policySequence": POLICY_SEQUENCE,
        "remediationAuthority": remediation_authority,
        "remediationControlRootSpki": root_spki,
        "sourceAuthority": source,
        "standard": "EIGIIB-P1-A14-POLICY-1.0",
    }


def _candidate_expected(
    candidate_id: str,
    sequence: int,
    content_mode: str,
    binding_mode: str,
    artifacts: dict[str, Any],
    policy_identity: dict[str, Any],
    advisory_identity: dict[str, Any],
    remediation_identity: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    content = dict(artifacts["content"])
    if content_mode == "revoked":
        content = dict(REVOKED_CONTENT)
    elif content_mode == "altered-archive":
        content["archiveSha256"] = "f" * 64
    elif content_mode != "exact":
        raise ValueError("candidate content mode")
    advisory = dict(advisory_identity)
    remediation = dict(remediation_identity)
    if binding_mode == "wrong-advisory":
        advisory["digest"] = "0" * 64
    elif binding_mode != "exact":
        raise ValueError("candidate binding mode")
    return {
        "action": "observe-fixed-release-candidate",
        "advisoryEnvelope": advisory,
        "candidateId": candidate_id,
        "candidateSequence": sequence,
        "content": content,
        "observedAtUnix": 1785621600 + index * 60,
        "policyEnvelope": policy_identity,
        "remediationEnvelope": remediation,
        "standard": "EIGIIB-P1-A14-CANDIDATE-1.0",
    }


def evaluate(root: Path, capsule_path: Path, openssl: str = "openssl") -> dict[str, Any]:
    capsule = strict_json(capsule_path.read_bytes())
    required = {
        "standard", "profile", "sourceAuthority", "remediationControlRoot",
        "advisoryAuthority", "remediationAuthority", "fixedReleaseSigner",
        "policy", "advisory", "remediation", "fixedRelease", "replays", "claimBoundary",
    }
    if not isinstance(capsule, dict) or set(capsule) != required:
        raise ValueError("capsule structure")
    if capsule.get("standard") != STANDARD or capsule.get("profile") != PROFILE:
        raise ValueError("capsule constants")

    source, source_revocation_envelope = _source(root)
    if capsule["sourceAuthority"] != source or capsule["claimBoundary"] != CLAIM_BOUNDARY:
        raise ValueError("source authority or claim boundary")
    artifacts = fixture_artifacts(root)

    root_key, root_spki = _key(root, capsule["remediationControlRoot"], "remediation-control root", openssl)
    advisory_key, advisory_spki = _key(root, capsule["advisoryAuthority"], "advisory authority", openssl, with_id=True)
    remediation_key, remediation_spki = _key(root, capsule["remediationAuthority"], "remediation authority", openssl, with_id=True)
    signer_key, signer_spki = _key(root, capsule["fixedReleaseSigner"], "fixed-release signer", openssl, with_id=True)

    expected_ids = {
        "advisoryAuthority": "eigiib-p1-a14-advisory-issuer-1",
        "remediationAuthority": "eigiib-p1-a14-remediator-1",
        "fixedReleaseSigner": "eigiib-p1-a14-fixed-release-signer-1",
    }
    for field, expected_id in expected_ids.items():
        if capsule[field]["id"] != expected_id:
            raise ValueError(f"{field} id")

    advisory_authority = {"id": capsule["advisoryAuthority"]["id"], "spki": advisory_spki}
    remediation_authority = {"id": capsule["remediationAuthority"]["id"], "spki": remediation_spki}
    fixed_release_signer = {"id": capsule["fixedReleaseSigner"]["id"], "spki": signer_spki}

    policy_expected = _policy_expected(source, root_spki, advisory_authority, remediation_authority, fixed_release_signer)
    _, policy_envelope = _signed(capsule["policy"], policy_expected, POLICY_TYPE, root_key, openssl, "policy")
    policy_identity = identity(policy_envelope)

    advisory_expected = {
        "action": "issue-security-advisory",
        "advisoryId": ADVISORY_ID,
        "advisorySequence": ADVISORY_SEQUENCE,
        "affectedContent": REVOKED_CONTENT,
        "issuedAtUnix": 1785610800,
        "policyEnvelope": policy_identity,
        "severity": "high",
        "sourceRevocationEnvelope": source_revocation_envelope,
        "standard": "EIGIIB-P1-A14-ADVISORY-1.0",
        "status": "confirmed-for-fixture-scope",
        "vulnerabilityIds": VULNERABILITY_IDS,
    }
    _, advisory_envelope = _signed(capsule["advisory"], advisory_expected, ADVISORY_TYPE, advisory_key, openssl, "advisory")
    advisory_identity = identity(advisory_envelope)

    remediation_expected = {
        "action": "bind-remediation-lineage",
        "advisoryEnvelope": advisory_identity,
        "changeSetArtifact": artifacts["changeSet"],
        "effectiveTimeUnix": 1785614400,
        "fixedContent": artifacts["content"],
        "fixedReleaseDescriptorArtifact": artifacts["descriptor"],
        "policyEnvelope": policy_identity,
        "predecessorContent": REVOKED_CONTENT,
        "remediationClass": "replacement-release",
        "remediationId": REMEDIATION_ID,
        "remediationSequence": REMEDIATION_SEQUENCE,
        "sourceRevocationEnvelope": source_revocation_envelope,
        "standard": "EIGIIB-P1-A14-REMEDIATION-1.0",
        "validationBasis": [
            "exact-advisory-binding",
            "exact-predecessor-and-successor-digests",
            "registered-fixture-authority-signature",
        ],
    }
    _, remediation_envelope = _signed(capsule["remediation"], remediation_expected, REMEDIATION_TYPE, remediation_key, openssl, "remediation")
    remediation_identity = identity(remediation_envelope)

    fixed_release_expected = {
        "action": "issue-fixed-release",
        "advisoryEnvelope": advisory_identity,
        "archiveArtifact": artifacts["archive"],
        "content": artifacts["content"],
        "descriptorArtifact": artifacts["descriptor"],
        "issuedAtUnix": 1785618000,
        "policyEnvelope": policy_identity,
        "predecessorContent": REVOKED_CONTENT,
        "releaseSequence": FIXED_RELEASE_SEQUENCE,
        "remediationEnvelope": remediation_identity,
        "standard": "EIGIIB-P1-A14-FIXED-RELEASE-1.0",
        "version": FIXED_RELEASE_VERSION,
    }
    _, fixed_release_envelope = _signed(capsule["fixedRelease"], fixed_release_expected, FIXED_RELEASE_TYPE, signer_key, openssl, "fixed release")

    replays = capsule["replays"]
    if not isinstance(replays, list) or len(replays) != len(REPLAY_SPECS):
        raise ValueError("replay count")
    replay_results: list[dict[str, Any]] = []
    for index, (row, spec) in enumerate(zip(replays, REPLAY_SPECS, strict=True)):
        candidate_id, sequence, content_mode, binding_mode, decision = spec
        if not exact_keys(row, {"id", "candidate", "expectedDecision"}):
            raise ValueError("replay carrier")
        if row["id"] != candidate_id or row["expectedDecision"] != decision:
            raise ValueError("replay decision")
        candidate_expected = _candidate_expected(
            candidate_id, sequence, content_mode, binding_mode, artifacts,
            policy_identity, advisory_identity, remediation_identity, index,
        )
        _signed(row["candidate"], candidate_expected, CANDIDATE_TYPE, signer_key, openssl, f"replay {candidate_id}")
        replay_results.append({"decision": decision, "id": candidate_id, "sequence": sequence})

    accepted_history = SOURCE_ACCEPTED_HISTORY + [
        f"remediation-policy-sequence-{POLICY_SEQUENCE}",
        f"advisory-sequence-{ADVISORY_SEQUENCE}",
        f"remediation-sequence-{REMEDIATION_SEQUENCE}",
        f"fixed-release-sequence-{FIXED_RELEASE_SEQUENCE}",
    ]
    return {
        "accepted_history": accepted_history,
        "advisory_binding_result": "conformant-for-exact-revoked-content-and-registered-fixture-advisory-scope",
        "advisory_envelope_sha256": _sha256(advisory_envelope),
        "advisory_id": ADVISORY_ID,
        "boundary": BOUNDARY,
        "claim_boundary": CLAIM_BOUNDARY,
        "fixed_release_archive_sha256": artifacts["content"]["archiveSha256"],
        "fixed_release_descriptor_sha256": artifacts["content"]["releaseDescriptorSha256"],
        "fixed_release_envelope_sha256": _sha256(fixed_release_envelope),
        "fixed_release_floor_sequence": FIXED_RELEASE_SEQUENCE,
        "fixed_release_id": FIXED_RELEASE_ID,
        "fixed_release_replay_result": "conformant-for-exact-fixed-release-and-no-history-advance-on-idempotent-replay-scope",
        "live_release_publication_result": "not-claimed",
        "overall_result": "conformant",
        "policy_envelope_sha256": _sha256(policy_envelope),
        "production_release_authorization_result": "not-claimed",
        "profile": PROFILE,
        "real_world_vulnerability_resolution_result": "not-claimed",
        "remediation_envelope_sha256": _sha256(remediation_envelope),
        "remediation_id": REMEDIATION_ID,
        "remediation_lineage_result": "conformant-for-exact-revoked-predecessor-to-fixed-successor-fixture-scope",
        "replay_results": replay_results,
        "revoked_archive_sha256": REVOKED_ARCHIVE_SHA256,
        "revoked_release_descriptor_sha256": REVOKED_RELEASE_DESCRIPTOR_SHA256,
        "revoked_release_id": REVOKED_RELEASE_ID,
        "source_revocation_capsule_sha256": A13_CAPSULE_SHA256,
        "source_revocation_report_sha256": A13_REPORT_SHA256,
        "standard": STANDARD,
        "tool": "eigiib-p1-a14-remediation-check",
        "tool_version": "0.1.0",
        "trusted_effective_time_unix": TRUSTED_EFFECTIVE_TIME,
        "vulnerability_ids": VULNERABILITY_IDS,
        "vulnerability_remediation_result": "conformant-for-registered-fixture-advisory-lineage-and-fixed-artifact-identity-scope",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, default=Path("tests/fixtures/p1-a14/capsule.json"))
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
            if result != strict_json(expected_path.read_bytes()):
                raise ValueError("expected report mismatch")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")) if args.json else result["overall_result"])
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        if args.json:
            print(json.dumps({"error": str(exc), "overall_result": "non-conformant"}, sort_keys=True, separators=(",", ":")))
        else:
            print(f"non-conformant: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
