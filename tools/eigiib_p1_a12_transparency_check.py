#!/usr/bin/env python3
"""Verify transparency registration, quorum, consistency, equivocation and recovery for P1-A12."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from eigiib_p1_a12_common import (
    CHECKPOINT_TYPE,
    PROFILE,
    REGISTRATION_TYPE,
    STANDARD,
    SUCCESSION_TYPE,
    WITNESS_TYPE,
    canonical_json,
    confined,
    decode_b64,
    exact_keys,
    identity,
    strict_json,
)
from eigiib_p1_a12_crypto import public_der, verify_cose_sign1

REGISTRATION_ID = "eigiib-p1-a12-registration-1"
SUCCESSION_ID = "eigiib-p1-a12-succession-1"
LOG1 = ("eigiib-p1-a12-log-1", 1)
LOG2 = ("eigiib-p1-a12-log-2", 2)
WITNESS_SET_1 = ("eigiib-p1-a12-witness-set-1", ["witness-a", "witness-b", "witness-c"], 2)
WITNESS_SET_2 = ("eigiib-p1-a12-witness-set-2", ["witness-a", "witness-c", "witness-d"], 2)
BOUNDARY = "registered-transparency-quorum-consistency-equivocation-recovery-closure"


def _carrier_bytes(carrier: Any, label: str) -> bytes:
    if not exact_keys(carrier, {"data", "identity"}):
        raise ValueError(f"{label} carrier")
    raw = decode_b64(carrier["data"])
    if carrier["identity"] != identity(raw):
        raise ValueError(f"{label} identity")
    return raw


def _key(root: Path, carrier: Any, label: str, openssl: str, *, service: bool = False, witness: bool = False) -> tuple[Path, dict[str, Any]]:
    keys = {"path", "spki"}
    if service:
        keys |= {"id", "epoch"}
    if witness:
        keys |= {"id"}
    if not exact_keys(carrier, keys):
        raise ValueError(f"{label} key carrier")
    path = confined(root, carrier["path"])
    der = public_der(path, openssl)
    if carrier["spki"] != identity(der):
        raise ValueError(f"{label} SPKI identity")
    return path, identity(der)


def _source(root: Path) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    report_path = confined(root, "tests/fixtures/p1-a11/expected-report.json")
    capsule_path = confined(root, "tests/fixtures/p1-a11/capsule.json")
    report_raw = report_path.read_bytes()
    capsule_raw = capsule_path.read_bytes()
    report = strict_json(report_raw)
    if not isinstance(report, dict) or report.get("overall_result") != "conformant":
        raise ValueError("A11 report")
    expected = {
        "timeCapsule": {"path": "tests/fixtures/p1-a11/capsule.json", "identity": identity(capsule_raw)},
        "timeReport": {"path": "tests/fixtures/p1-a11/expected-report.json", "identity": identity(report_raw)},
        "releaseId": report["release_id"],
        "lastAcceptedTimestampUnix": report["last_accepted_timestamp_unix"],
        "timePolicyEnvelopeSha256": report["time_policy_envelope_sha256"],
        "timestampAuthoritySpkiSha256": report["timestamp_authority_spki_sha256"],
        "trustedEffectiveTimeResult": report["trusted_effective_time_result"],
    }
    return expected, report, report_raw, capsule_raw


def _leaf_hash(raw: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + raw).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _balanced_root(raws: list[bytes]) -> bytes:
    if not raws or len(raws) & (len(raws) - 1):
        raise ValueError("power-of-two leaves required")
    level = [_leaf_hash(raw) for raw in raws]
    while len(level) > 1:
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _leaf_payload(leaf_id: str, kind: str, subject: dict[str, Any]) -> bytes:
    return canonical_json({"kind": kind, "leafId": leaf_id, "standard": "EIGIIB-P1-A12-LEAF-1.0", "subject": subject})


def _checkpoint_payload(*, checkpoint_id: str, sequence: int, service_id: str, epoch: int, tree_size: int, root_hash: bytes, registration_identity: dict[str, Any], predecessor: dict[str, Any] | None, proof: list[bytes], source: dict[str, Any]) -> dict[str, Any]:
    return {
        "checkpointId": checkpoint_id,
        "checkpointSequence": sequence,
        "consistencyProof": [row.hex() for row in proof],
        "predecessor": predecessor,
        "registrationEnvelope": registration_identity,
        "rootHash": root_hash.hex(),
        "serviceEpoch": epoch,
        "serviceId": service_id,
        "sourceTime": source,
        "standard": "EIGIIB-P1-A12-CHECKPOINT-1.0",
        "treeHashAlgorithm": "sha256-rfc6962-domain-separated-v1",
        "treeSize": tree_size,
    }


def _verify_consistency(old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    return len(proof) == 1 and _node_hash(old_root, proof[0]) == new_root


def _signed(carrier: Any, expected: dict[str, Any], content_type: str, key: Path, openssl: str, label: str) -> tuple[bytes, bytes]:
    if not exact_keys(carrier, {"payload", "envelope"}):
        raise ValueError(f"{label} signed carrier")
    payload = _carrier_bytes(carrier["payload"], f"{label} payload")
    if payload != canonical_json(expected):
        raise ValueError(f"{label} semantics")
    envelope = _carrier_bytes(carrier["envelope"], f"{label} envelope")
    verify_cose_sign1(envelope, payload, content_type, key, openssl)
    return payload, envelope


def _verify_witnesses(root: Path, row: dict[str, Any], checkpoint_expected: dict[str, Any], checkpoint_envelope: bytes, witness_set_id: str, allowed: list[str], threshold: int, witness_keys: dict[str, Path], openssl: str) -> list[str]:
    statements = row.get("witnessStatements")
    if not isinstance(statements, list):
        raise ValueError("witness statements")
    accepted: list[str] = []
    seen: set[str] = set()
    for statement in statements:
        if not isinstance(statement, dict) or set(statement) != {"id", "payload", "envelope"}:
            raise ValueError("witness statement carrier")
        witness_id = statement["id"]
        if witness_id not in allowed or witness_id in seen or witness_id not in witness_keys:
            raise ValueError("witness membership")
        expected = {
            "checkpointEnvelope": identity(checkpoint_envelope),
            "checkpointId": checkpoint_expected["checkpointId"],
            "checkpointRootHash": checkpoint_expected["rootHash"],
            "checkpointSequence": checkpoint_expected["checkpointSequence"],
            "serviceEpoch": checkpoint_expected["serviceEpoch"],
            "serviceId": checkpoint_expected["serviceId"],
            "standard": "EIGIIB-P1-A12-WITNESS-STATEMENT-1.0",
            "treeSize": checkpoint_expected["treeSize"],
            "witnessId": witness_id,
            "witnessSetId": witness_set_id,
        }
        _signed({"payload": statement["payload"], "envelope": statement["envelope"]}, expected, WITNESS_TYPE, witness_keys[witness_id], openssl, f"witness {witness_id}")
        seen.add(witness_id)
        accepted.append(witness_id)
    if len(accepted) < threshold:
        raise ValueError("witness quorum")
    return accepted


def evaluate(root: Path, capsule_path: Path, openssl: str = "openssl") -> dict[str, Any]:
    capsule_raw = capsule_path.read_bytes()
    capsule = strict_json(capsule_raw)
    if not isinstance(capsule, dict) or capsule.get("standard") != STANDARD or capsule.get("profile") != PROFILE:
        raise ValueError("capsule constants")
    required = {"standard", "profile", "sourceTime", "transparencyTrustRoot", "services", "witnesses", "registration", "leaves", "checkpoints", "succession", "claimBoundary"}
    if set(capsule) != required:
        raise ValueError("capsule members")

    source, a11, report_raw, _ = _source(root)
    if capsule["sourceTime"] != source:
        raise ValueError("source time binding")

    trust_key, trust_spki = _key(root, capsule["transparencyTrustRoot"], "transparency root", openssl)
    services = capsule["services"]
    if not isinstance(services, list) or len(services) != 2:
        raise ValueError("service count")
    service_keys: dict[tuple[str, int], Path] = {}
    service_spki: dict[tuple[str, int], dict[str, Any]] = {}
    for index, spec in enumerate((LOG1, LOG2)):
        path, spki = _key(root, services[index], f"service {spec[0]}", openssl, service=True)
        if services[index]["id"] != spec[0] or services[index]["epoch"] != spec[1]:
            raise ValueError("service identity")
        service_keys[spec] = path
        service_spki[spec] = spki

    witness_rows = capsule["witnesses"]
    if not isinstance(witness_rows, list) or len(witness_rows) != 4:
        raise ValueError("witness count")
    witness_keys: dict[str, Path] = {}
    witness_carriers: dict[str, dict[str, Any]] = {}
    for expected_id, row in zip(["witness-a", "witness-b", "witness-c", "witness-d"], witness_rows, strict=True):
        path, _ = _key(root, row, f"witness {expected_id}", openssl, witness=True)
        if row["id"] != expected_id:
            raise ValueError("witness identity")
        witness_keys[expected_id] = path
        witness_carriers[expected_id] = row

    registration_expected = {
        "action": "register-transparency-service",
        "claimBoundary": {"doesNotImply": [
            "registered-service-does-not-prove-real-world-operator-identity",
            "witness-quorum-does-not-prevent-colluding-equivocation",
            "registered-log-consistency-does-not-prove-global-append-only-consistency",
            "transparency-registration-does-not-imply-content-revocation",
        ]},
        "consistencyPolicy": {
            "acceptedHistoryMustBeAppendOnly": True,
            "equivocationAtEqualTreeSizeQuarantinesServiceEpoch": True,
            "proofProfile": "power-of-two-prefix-rfc6962-v1",
        },
        "registrationId": REGISTRATION_ID,
        "registrationSequence": 1,
        "service": services[0],
        "sourceTime": source,
        "standard": "EIGIIB-P1-A12-REGISTRATION-1.0",
        "witnessSet": {"id": WITNESS_SET_1[0], "members": [witness_carriers[x] for x in WITNESS_SET_1[1]], "threshold": WITNESS_SET_1[2]},
    }
    _, registration_envelope = _signed(capsule["registration"], registration_expected, REGISTRATION_TYPE, trust_key, openssl, "registration")

    leaves = capsule["leaves"]
    if not isinstance(leaves, dict) or set(leaves) != {"canonical", "fork", "recovery"}:
        raise ValueError("leaves carrier")
    expected_canonical = [
        _leaf_payload("a11-report", "source-authority", source["timeReport"]),
        _leaf_payload("a11-capsule", "source-authority", source["timeCapsule"]),
        _leaf_payload("a11-time-policy", "time-policy", {
            "timePolicyEnvelopeSha256": a11["time_policy_envelope_sha256"],
            "timestampAuthoritySpkiSha256": a11["timestamp_authority_spki_sha256"],
            "lastAcceptedTimestampUnix": a11["last_accepted_timestamp_unix"],
        }),
        _leaf_payload("release-authorization", "release-authorization", {
            "authorizationReportSha256": a11["authorization_report_sha256"],
            "recoveredAuthorizationSha256": a11["recovered_authorization_sha256"],
            "releaseId": a11["release_id"],
        }),
    ]
    canonical_carriers = leaves["canonical"]
    if not isinstance(canonical_carriers, list) or len(canonical_carriers) != 4:
        raise ValueError("canonical leaves")
    canonical_raws = [_carrier_bytes(carrier, f"canonical leaf {i}") for i, carrier in enumerate(canonical_carriers)]
    if canonical_raws != expected_canonical:
        raise ValueError("canonical leaf semantics")
    fork_expected = _leaf_payload("fork-release-authorization", "fork-marker", {
        "releaseId": a11["release_id"],
        "unauthorizedRoot": hashlib.sha256(b"EIGIIB-P1-A12-FORK").hexdigest(),
    })
    fork_raw = _carrier_bytes(leaves["fork"], "fork leaf")
    if fork_raw != fork_expected:
        raise ValueError("fork leaf semantics")

    root2 = _balanced_root(canonical_raws[:2])
    right2 = _balanced_root(canonical_raws[2:4])
    root4 = _node_hash(root2, right2)
    fork_right2 = _balanced_root([canonical_raws[2], fork_raw])
    fork_root4 = _node_hash(root2, fork_right2)
    reg_identity = identity(registration_envelope)

    checkpoints = capsule["checkpoints"]
    if not isinstance(checkpoints, list) or len(checkpoints) != 4:
        raise ValueError("checkpoint count")

    cp2_expected = _checkpoint_payload(checkpoint_id="epoch1-size2", sequence=10, service_id=LOG1[0], epoch=1, tree_size=2, root_hash=root2, registration_identity=reg_identity, predecessor=None, proof=[], source=source)
    cp2_payload, cp2_envelope = _signed({"payload": checkpoints[0]["payload"], "envelope": checkpoints[0]["envelope"]}, cp2_expected, CHECKPOINT_TYPE, service_keys[LOG1], openssl, "checkpoint size2")
    if checkpoints[0].get("expectedDecision") != "conformant":
        raise ValueError("checkpoint size2 decision")
    q2 = _verify_witnesses(root, checkpoints[0], cp2_expected, cp2_envelope, WITNESS_SET_1[0], WITNESS_SET_1[1], 2, witness_keys, openssl)
    cp2_pred = {"checkpointEnvelope": identity(cp2_envelope), "checkpointId": "epoch1-size2", "rootHash": root2.hex(), "treeSize": 2}

    cp4_expected = _checkpoint_payload(checkpoint_id="epoch1-size4-main", sequence=11, service_id=LOG1[0], epoch=1, tree_size=4, root_hash=root4, registration_identity=reg_identity, predecessor=cp2_pred, proof=[right2], source=source)
    cp4_payload, cp4_envelope = _signed({"payload": checkpoints[1]["payload"], "envelope": checkpoints[1]["envelope"]}, cp4_expected, CHECKPOINT_TYPE, service_keys[LOG1], openssl, "checkpoint size4 main")
    if checkpoints[1].get("expectedDecision") != "conformant" or not _verify_consistency(root2, root4, [right2]):
        raise ValueError("checkpoint size4 main")
    q4 = _verify_witnesses(root, checkpoints[1], cp4_expected, cp4_envelope, WITNESS_SET_1[0], WITNESS_SET_1[1], 2, witness_keys, openssl)

    fork_expected_cp = _checkpoint_payload(checkpoint_id="epoch1-size4-fork", sequence=11, service_id=LOG1[0], epoch=1, tree_size=4, root_hash=fork_root4, registration_identity=reg_identity, predecessor=cp2_pred, proof=[fork_right2], source=source)
    _, fork_envelope = _signed({"payload": checkpoints[2]["payload"], "envelope": checkpoints[2]["envelope"]}, fork_expected_cp, CHECKPOINT_TYPE, service_keys[LOG1], openssl, "checkpoint size4 fork")
    if checkpoints[2].get("expectedDecision") != "rejected-equivocation-and-quarantined" or not _verify_consistency(root2, fork_root4, [fork_right2]):
        raise ValueError("fork checkpoint")
    qfork = _verify_witnesses(root, checkpoints[2], fork_expected_cp, fork_envelope, WITNESS_SET_1[0], WITNESS_SET_1[1], 2, witness_keys, openssl)
    if root4 == fork_root4 or cp4_expected["treeSize"] != fork_expected_cp["treeSize"] or cp4_expected["checkpointSequence"] != fork_expected_cp["checkpointSequence"]:
        raise ValueError("equivocation evidence")
    overlapping = sorted(set(q4) & set(qfork))
    if overlapping != ["witness-b"]:
        raise ValueError("equivocating witness overlap")

    succession_expected = {
        "action": "recover-transparency-service-after-equivocation",
        "acceptedPredecessor": {"checkpointEnvelope": identity(cp4_envelope), "rootHash": root4.hex(), "treeSize": 4},
        "claimBoundary": {"doesNotImply": [
            "successor-registration-does-not-prove-real-world-operator-identity",
            "local-recovery-does-not-prove-global-log-consistency",
            "quorum-recovery-does-not-imply-production-governance",
        ]},
        "equivocationEvidence": {
            "canonicalCheckpointEnvelope": identity(cp4_envelope),
            "conflictingCheckpointEnvelope": identity(fork_envelope),
            "sameEpoch": 1,
            "sameSequence": 11,
            "sameTreeSize": 4,
        },
        "quarantine": {"serviceEpoch": {"epoch": 1, "id": LOG1[0]}, "witnessIds": ["witness-b"]},
        "sourceTime": source,
        "standard": "EIGIIB-P1-A12-SUCCESSION-1.0",
        "successorService": services[1],
        "successionId": SUCCESSION_ID,
        "successionSequence": 2,
        "witnessSet": {"id": WITNESS_SET_2[0], "members": [witness_carriers[x] for x in WITNESS_SET_2[1]], "threshold": WITNESS_SET_2[2]},
    }
    _, succession_envelope = _signed(capsule["succession"], succession_expected, SUCCESSION_TYPE, trust_key, openssl, "succession")

    expected_recovery = [
        _leaf_payload("equivocation-evidence", "equivocation-evidence", succession_expected["equivocationEvidence"]),
        _leaf_payload("quarantine-decision", "quarantine", succession_expected["quarantine"]),
        _leaf_payload("succession-policy", "succession-policy", {"payload": capsule["succession"]["payload"]["identity"], "envelope": capsule["succession"]["envelope"]["identity"]}),
        _leaf_payload("a12-closure", "closure-marker", {"boundary": BOUNDARY, "releaseId": a11["release_id"]}),
    ]
    recovery_carriers = leaves["recovery"]
    if not isinstance(recovery_carriers, list) or len(recovery_carriers) != 4:
        raise ValueError("recovery leaves")
    recovery_raws = [_carrier_bytes(carrier, f"recovery leaf {i}") for i, carrier in enumerate(recovery_carriers)]
    if recovery_raws != expected_recovery:
        raise ValueError("recovery leaf semantics")
    recovery_right = _balanced_root(recovery_raws)
    root8 = _node_hash(root4, recovery_right)
    cp8_pred = {"checkpointEnvelope": identity(cp4_envelope), "checkpointId": "epoch1-size4-main", "rootHash": root4.hex(), "treeSize": 4}
    cp8_expected = _checkpoint_payload(checkpoint_id="epoch2-size8-recovery", sequence=20, service_id=LOG2[0], epoch=2, tree_size=8, root_hash=root8, registration_identity=identity(succession_envelope), predecessor=cp8_pred, proof=[recovery_right], source=source)
    _, cp8_envelope = _signed({"payload": checkpoints[3]["payload"], "envelope": checkpoints[3]["envelope"]}, cp8_expected, CHECKPOINT_TYPE, service_keys[LOG2], openssl, "checkpoint size8 recovery")
    if checkpoints[3].get("expectedDecision") != "conformant" or not _verify_consistency(root4, root8, [recovery_right]):
        raise ValueError("checkpoint size8 recovery")
    q8 = _verify_witnesses(root, checkpoints[3], cp8_expected, cp8_envelope, WITNESS_SET_2[0], WITNESS_SET_2[1], 2, witness_keys, openssl)
    if "witness-b" in q8:
        raise ValueError("quarantined witness reused")

    claim = [
        "fixture-trust-root-does-not-prove-real-world-operator-identity",
        "witness-quorum-does-not-prevent-colluding-witnesses",
        "accepted-local-history-does-not-prove-global-append-only-consistency",
        "equivocation-recovery-does-not-imply-content-revocation-or-withdrawal",
        "transparency-recovery-does-not-imply-production-release-governance",
        "p1-a12-does-not-imply-universal-interoperability",
    ]
    if capsule["claimBoundary"] != {"doesNotImply": claim}:
        raise ValueError("claim boundary")

    report = {
        "tool": "eigiib-p1-a12-transparency-check",
        "tool_version": "0.1.0",
        "standard": STANDARD,
        "profile": PROFILE,
        "release_id": a11["release_id"],
        "source_time_report_sha256": identity(report_raw)["digest"],
        "source_time_capsule_sha256": source["timeCapsule"]["identity"]["digest"],
        "trusted_effective_time_unix": source["lastAcceptedTimestampUnix"],
        "transparency_trust_root_spki_sha256": trust_spki["digest"],
        "registered_service_id": LOG1[0],
        "registered_service_epoch": 1,
        "registered_service_spki_sha256": service_spki[LOG1]["digest"],
        "registration_envelope_sha256": identity(registration_envelope)["digest"],
        "initial_witness_set_id": WITNESS_SET_1[0],
        "initial_witness_count": 3,
        "witness_threshold": 2,
        "baseline_checkpoint_root": root2.hex(),
        "canonical_checkpoint_root": root4.hex(),
        "conflicting_checkpoint_root": fork_root4.hex(),
        "recovered_checkpoint_root": root8.hex(),
        "baseline_quorum_ids": q2,
        "canonical_quorum_ids": q4,
        "conflicting_quorum_ids": qfork,
        "equivocating_witness_ids": overlapping,
        "equivocation_result": "detected-and-quarantined",
        "predecessor_service_result": "quarantined-as-required",
        "succession_envelope_sha256": identity(succession_envelope)["digest"],
        "recovered_service_id": LOG2[0],
        "recovered_service_epoch": 2,
        "recovered_service_spki_sha256": service_spki[LOG2]["digest"],
        "recovered_witness_set_id": WITNESS_SET_2[0],
        "recovered_quorum_ids": q8,
        "baseline_quorum_result": "conformant",
        "canonical_consistency_result": "conformant",
        "conflicting_checkpoint_signature_result": "conformant",
        "conflicting_checkpoint_quorum_result": "conformant",
        "recovered_quorum_result": "conformant",
        "recovered_consistency_result": "conformant",
        "trusted_transparency_service_result": "conformant-for-root-registered-successor-and-quarantined-predecessor-scope",
        "append_only_consistency_result": "conformant-for-accepted-2-to-4-to-8-history-scope",
        "global_append_only_consistency_result": "not-claimed",
        "accepted_checkpoint_ids": ["epoch1-size2", "epoch1-size4-main", "epoch2-size8-recovery"],
        "rejected_checkpoint_ids": ["epoch1-size4-fork"],
        "claim_boundary": claim,
        "boundary": BOUNDARY,
        "overall_result": "conformant",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = evaluate(args.root.resolve(), args.capsule.resolve(), args.openssl)
        if args.expected:
            expected = strict_json(args.expected.read_bytes())
            if report != expected:
                raise ValueError("expected report mismatch")
    except Exception as exc:
        print(f"P1-A12 verification failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        sys.stdout.buffer.write(canonical_json(report))
    else:
        print("P1-A12 transparency replay: conformant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
