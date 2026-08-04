#!/usr/bin/env python3
"""Typed constants and deterministic derivations for M0-A15-F1."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from eigiib_m0_a15_f1_canonical import digest_hex

A15_HEAD = "a39a3865dfe27fe394345e6fb7e9030c37f25203"
A15_TREE = "1c74a2d5b417b96e2058d6270a907e2c8150d52a"
REGISTRY_IDS = (
    "maintenance-registry-alpha",
    "maintenance-registry-beta",
    "maintenance-registry-gamma",
)
REGISTRY_DIMENSIONS = (
    "providerOperator", "tenantAccount", "identityRoot",
    "privilegedAdministrator", "storageDomain", "auditCustody",
)
OBSERVER_DIMENSIONS = (
    "controlDomainId", "identityRoot", "providerOperator", "networkPath", "implementation",
)
MIN_CHECKPOINTS = 6
MIN_SPAN_SECONDS = 7_776_000
WITNESS_QUORUM = 4

REGISTRY_PROFILE_KEYS = {"registryId", *REGISTRY_DIMENSIONS, "keyId", "algorithm", "publicKey"}
WITNESS_PROFILE_KEYS = {"witnessId", "controlDomainId", "identityRoot", "keyId", "algorithm", "publicKey"}
OBSERVER_PROFILE_KEYS = {"observerId", *OBSERVER_DIMENSIONS, "keyId", "algorithm", "publicKey"}
RECEIPT_KEYS = {
    "registryId", "sequence", "observedAt", "previousAcceptedCheckpointDigest",
    "cycleTipDigest", "governanceSnapshotDigest", "previousReceiptDigest", "status",
}
ENDORSEMENT_KEYS = {"witnessId", "controlDomainId", "recordType", "recordDigest", "signedAt"}
READBACK_KEYS = {
    "observerId", "controlDomainId", "subjectType", "subjectDigest", "contentDigest",
    "scope", "registryId", "observedAt", "locator",
}
PROOF_KEYS = {"sequence", "receiptDigests", "candidateViewDigests", "divergentRegistryIds", "proofDigest"}
RECONCILIATION_PAYLOAD_KEYS = {
    "sequence", "commonAncestorCheckpointDigest", "derivedSplitBrainProofDigest",
    "candidateViewDigests", "authoritativeViewDigest", "supportingRegistryIds",
    "quarantinedRegistryIds", "appendOnly", "staleViewsRejected",
}
GOVERNANCE_PAYLOAD_KEYS = {
    "fromSnapshotDigest", "toSnapshotDigest", "effectiveAt", "approvalRecordDigests",
    "independentReviewDigest", "nonWeakeningAssessmentDigest",
}
CHECKPOINT_KEYS = {
    "sequence", "observedAt", "previousAcceptedCheckpointDigest", "registryReceipts",
    "derivedSplitBrainProof", "reconciliationRecord", "governanceReconciliation",
    "witnessEndorsements",
}
CERTIFICATE_PAYLOAD_KEYS = {
    "sourceA15Head", "sourceA15Tree", "a14ReplayDigest", "firstCheckpointDigest",
    "lastCheckpointDigest", "checkpointCount", "observedSpanSeconds", "registryReceiptCount",
    "splitBrainProofCount", "reconciliationRecordCount", "governanceReconciliationCount",
    "finalAuthoritativeViewDigest", "decision",
}


def shape(value: Any, keys: set[str], prefix: str, errors: list[str]) -> bool:
    if not isinstance(value, dict) or set(value) != keys:
        errors.append(f"{prefix}-shape-invalid")
        return False
    return True


def candidate_view_payload(receipt_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence": receipt_payload.get("sequence"),
        "previousAcceptedCheckpointDigest": receipt_payload.get("previousAcceptedCheckpointDigest"),
        "cycleTipDigest": receipt_payload.get("cycleTipDigest"),
        "governanceSnapshotDigest": receipt_payload.get("governanceSnapshotDigest"),
    }


def candidate_view_digest(receipt_payload: dict[str, Any]) -> str:
    return digest_hex(candidate_view_payload(receipt_payload))


def split_brain_proof_base(
    sequence: int,
    receipt_digests: Iterable[str],
    candidate_views: dict[str, str],
) -> dict[str, Any]:
    groups: dict[str, list[str]] = defaultdict(list)
    for registry_id, view_digest in candidate_views.items():
        groups[view_digest].append(registry_id)
    maximum = max((len(ids) for ids in groups.values()), default=0)
    divergent = sorted(
        registry_id
        for view_digest, registry_ids in groups.items()
        if len(registry_ids) < maximum
        for registry_id in registry_ids
    )
    if maximum <= 1 and len(groups) > 1:
        divergent = sorted(candidate_views)
    return {
        "sequence": sequence,
        "receiptDigests": sorted(receipt_digests),
        "candidateViewDigests": sorted(groups),
        "divergentRegistryIds": divergent,
    }


def checkpoint_digest(
    sequence: int,
    observed_at: str,
    previous_checkpoint_digest: str | None,
    accepted_view_digest: str,
    receipt_digests: Iterable[str],
    split_brain_proof_digest: str | None,
    reconciliation_digest: str | None,
    governance_reconciliation_digest: str | None,
) -> str:
    return digest_hex({
        "sequence": sequence,
        "observedAt": observed_at,
        "previousAcceptedCheckpointDigest": previous_checkpoint_digest,
        "acceptedViewDigest": accepted_view_digest,
        "registryReceiptDigests": sorted(receipt_digests),
        "derivedSplitBrainProofDigest": split_brain_proof_digest,
        "reconciliationDigest": reconciliation_digest,
        "governanceReconciliationDigest": governance_reconciliation_digest,
    })
