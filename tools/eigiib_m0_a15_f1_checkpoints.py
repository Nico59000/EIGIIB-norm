#!/usr/bin/env python3
"""Authenticated checkpoint, split-brain and reconciliation replay for M0-A15-F1."""
from __future__ import annotations

from collections import Counter
from typing import Any

from eigiib_m0_a15_f1_canonical import digest_hex, is_hex, parse_time
from eigiib_m0_a15_f1_crypto import verify_envelope
from eigiib_m0_a15_f1_model import (
    CHECKPOINT_KEYS, GOVERNANCE_PAYLOAD_KEYS, MIN_CHECKPOINTS, MIN_SPAN_SECONDS,
    PROOF_KEYS, RECEIPT_KEYS, RECONCILIATION_PAYLOAD_KEYS, REGISTRY_IDS,
    candidate_view_digest, candidate_view_payload, checkpoint_digest,
    shape, split_brain_proof_base,
)
from eigiib_m0_a15_f1_principals import verify_readbacks, verify_witness_quorum


def verify_checkpoints(
    checkpoints: Any,
    registry_map: dict[str, Any],
    witness_map: dict[str, Any],
    observer_map: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    if not isinstance(checkpoints, list):
        errors.append("checkpoint-inventory-invalid"); checkpoints = []
    if len(checkpoints) < MIN_CHECKPOINTS: errors.append("minimum-checkpoint-count-not-met")

    previous_checkpoint_digest: str | None = None
    previous_receipt_digests: dict[str, str | None] = {registry_id: None for registry_id in REGISTRY_IDS}
    previous_time = None; first_time = None; last_time = None
    previous_governance_digest: str | None = None
    accepted_checkpoint_digests: list[str] = []
    accepted_view_digests: list[str] = []
    split_brain_count = reconciliation_count = governance_count = total_receipts = 0

    for index, checkpoint in enumerate(checkpoints, 1):
        prefix = f"checkpoint-{index}"
        if not shape(checkpoint, CHECKPOINT_KEYS, prefix, errors): continue
        sequence = checkpoint.get("sequence"); observed_text = checkpoint.get("observedAt")
        observed = parse_time(observed_text)
        if sequence != index: errors.append("checkpoint-sequence-gap")
        if observed is None: errors.append(f"{prefix}-time-invalid")
        else:
            if previous_time is not None and observed <= previous_time: errors.append("checkpoint-time-not-monotonic")
            previous_time = observed; first_time = first_time or observed; last_time = observed
        if checkpoint.get("previousAcceptedCheckpointDigest") != previous_checkpoint_digest: errors.append("checkpoint-chain-broken")

        receipts = checkpoint.get("registryReceipts")
        if not isinstance(receipts, list) or len(receipts) != 3:
            errors.append(f"{prefix}-registry-receipts-incomplete"); receipts = []
        receipt_digests: list[str] = []
        candidate_views: dict[str, str] = {}
        view_payloads: dict[str, dict[str, Any]] = {}
        registry_receipt_by_id: dict[str, dict[str, Any]] = {}
        for receipt_index, envelope in enumerate(receipts):
            receipt_prefix = f"{prefix}-receipt-{receipt_index + 1}"
            payload = envelope.get("payload") if isinstance(envelope, dict) else None
            if not shape(payload, RECEIPT_KEYS, receipt_prefix, errors): continue
            registry_id = payload.get("registryId"); profile = registry_map.get(registry_id)
            if profile is None:
                errors.append(f"{receipt_prefix}-unknown-registry"); continue
            receipt_digest, envelope_errors = verify_envelope(envelope, profile, receipt_prefix); errors.extend(envelope_errors)
            if registry_id in registry_receipt_by_id: errors.append(f"{prefix}-duplicate-registry-receipt")
            registry_receipt_by_id[registry_id] = payload
            if payload.get("sequence") != sequence or payload.get("observedAt") != observed_text: errors.append(f"{receipt_prefix}-checkpoint-binding-mismatch")
            if payload.get("previousAcceptedCheckpointDigest") != previous_checkpoint_digest: errors.append(f"{receipt_prefix}-accepted-checkpoint-binding-mismatch")
            if payload.get("previousReceiptDigest") != previous_receipt_digests.get(registry_id): errors.append(f"{receipt_prefix}-receipt-chain-broken")
            if payload.get("status") != "authoritative": errors.append(f"{receipt_prefix}-status-invalid")
            if not is_hex(payload.get("cycleTipDigest")) or not is_hex(payload.get("governanceSnapshotDigest")): errors.append(f"{receipt_prefix}-state-digest-invalid")
            if receipt_digest is not None:
                receipt_digests.append(receipt_digest); previous_receipt_digests[registry_id] = receipt_digest
                view_digest = candidate_view_digest(payload); candidate_views[registry_id] = view_digest
                view_payloads[view_digest] = candidate_view_payload(payload); total_receipts += 1
        if set(registry_receipt_by_id) != set(REGISTRY_IDS): errors.append(f"{prefix}-registry-receipts-incomplete")

        groups = Counter(candidate_views.values())
        proof = checkpoint.get("derivedSplitBrainProof"); reconciliation = checkpoint.get("reconciliationRecord")
        proof_digest: str | None = None; reconciliation_digest: str | None = None; accepted_view: str | None = None
        if len(groups) <= 1 and groups:
            accepted_view = next(iter(groups))
            if proof is not None: errors.append(f"{prefix}-spurious-split-brain-proof")
            if reconciliation is not None: errors.append(f"{prefix}-spurious-reconciliation-record")
        elif len(groups) > 1:
            split_brain_count += 1
            expected_base = split_brain_proof_base(sequence, receipt_digests, candidate_views)
            expected_digest = digest_hex(expected_base); expected_proof = {**expected_base, "proofDigest": expected_digest}
            if not shape(proof, PROOF_KEYS, f"{prefix}-split-brain-proof", errors): errors.append(f"{prefix}-split-brain-proof-missing")
            elif proof != expected_proof: errors.append(f"{prefix}-split-brain-proof-not-derived")
            else: proof_digest = expected_digest
            if not isinstance(reconciliation, dict) or set(reconciliation) != {"payload", "witnessEndorsements", "readbacks"}:
                errors.append(f"{prefix}-reconciliation-record-missing")
            else:
                payload = reconciliation.get("payload")
                if shape(payload, RECONCILIATION_PAYLOAD_KEYS, f"{prefix}-reconciliation", errors):
                    authoritative_view = payload.get("authoritativeViewDigest")
                    support = sorted(registry_id for registry_id, view in candidate_views.items() if view == authoritative_view)
                    quarantine = sorted(set(candidate_views) - set(support))
                    if len(support) < 2: errors.append(f"{prefix}-reconciliation-registry-support-insufficient")
                    if payload.get("sequence") != sequence: errors.append(f"{prefix}-reconciliation-sequence-mismatch")
                    if payload.get("commonAncestorCheckpointDigest") != previous_checkpoint_digest: errors.append(f"{prefix}-reconciliation-common-ancestor-mismatch")
                    if payload.get("derivedSplitBrainProofDigest") != proof_digest: errors.append(f"{prefix}-reconciliation-proof-binding-mismatch")
                    if payload.get("candidateViewDigests") != sorted(groups): errors.append(f"{prefix}-reconciliation-candidate-inventory-mismatch")
                    if payload.get("supportingRegistryIds") != support: errors.append(f"{prefix}-reconciliation-support-not-derived")
                    if payload.get("quarantinedRegistryIds") != quarantine or not quarantine: errors.append(f"{prefix}-reconciliation-quarantine-not-derived")
                    if payload.get("appendOnly") is not True or payload.get("staleViewsRejected") is not True: errors.append(f"{prefix}-reconciliation-anti-rollback-invalid")
                    if authoritative_view not in groups: errors.append(f"{prefix}-reconciliation-authoritative-view-invalid")
                    else: accepted_view = authoritative_view
                    reconciliation_digest = digest_hex(payload)
                    verify_witness_quorum(reconciliation.get("witnessEndorsements"), witness_map, "reconciliation", reconciliation_digest, f"{prefix}-reconciliation", errors, observed_text)
                    readbacks = verify_readbacks(reconciliation.get("readbacks"), observer_map, f"{prefix}-reconciliation", errors)
                    valid_observers: set[str] = set(); authoritative_readback = False; quarantined_readbacks: set[str] = set()
                    for readback in readbacks:
                        if readback.get("subjectType") != "reconciliation" or readback.get("subjectDigest") != reconciliation_digest:
                            errors.append(f"{prefix}-reconciliation-readback-subject-mismatch"); continue
                        valid_observers.add(readback.get("observerId"))
                        if readback.get("scope") == "authoritative-published-state" and readback.get("registryId") is None and readback.get("contentDigest") == authoritative_view:
                            authoritative_readback = True
                        if readback.get("scope") == "quarantined-registry-state" and readback.get("registryId") in quarantine and readback.get("contentDigest") == candidate_views.get(readback.get("registryId")):
                            quarantined_readbacks.add(readback.get("registryId"))
                    if not authoritative_readback: errors.append(f"{prefix}-authoritative-published-readback-missing")
                    if quarantined_readbacks != set(quarantine): errors.append(f"{prefix}-quarantined-registry-readback-missing")
                    if len(valid_observers) < 2: errors.append(f"{prefix}-reconciliation-readback-observer-independence-insufficient")
                    reconciliation_count += 1
        else:
            errors.append(f"{prefix}-authenticated-receipt-view-missing")

        governance_digest: str | None = None
        governance_record = checkpoint.get("governanceReconciliation")
        accepted_governance = view_payloads.get(accepted_view or "", {}).get("governanceSnapshotDigest")
        if previous_governance_digest is not None and accepted_governance != previous_governance_digest:
            if not isinstance(governance_record, dict) or set(governance_record) != {"payload", "witnessEndorsements"}:
                errors.append(f"{prefix}-governance-reconciliation-missing")
            else:
                payload = governance_record.get("payload")
                if shape(payload, GOVERNANCE_PAYLOAD_KEYS, f"{prefix}-governance", errors):
                    if payload.get("fromSnapshotDigest") != previous_governance_digest or payload.get("toSnapshotDigest") != accepted_governance: errors.append(f"{prefix}-governance-chain-mismatch")
                    effective = parse_time(payload.get("effectiveAt"))
                    if effective is None or (observed is not None and effective > observed): errors.append(f"{prefix}-governance-effective-time-invalid")
                    approvals = payload.get("approvalRecordDigests")
                    if not isinstance(approvals, list) or len(approvals) != 3 or len(set(approvals)) != 3 or not all(is_hex(item) for item in approvals): errors.append(f"{prefix}-governance-approval-records-invalid")
                    if not is_hex(payload.get("independentReviewDigest")) or not is_hex(payload.get("nonWeakeningAssessmentDigest")): errors.append(f"{prefix}-governance-review-evidence-invalid")
                    governance_digest = digest_hex(payload)
                    verify_witness_quorum(governance_record.get("witnessEndorsements"), witness_map, "governance-reconciliation", governance_digest, f"{prefix}-governance", errors, payload.get("effectiveAt"))
                    governance_count += 1
        elif governance_record is not None: errors.append(f"{prefix}-spurious-governance-reconciliation")
        previous_governance_digest = accepted_governance

        if accepted_view is None: accepted_view = "0" * 64
        current_checkpoint_digest = checkpoint_digest(sequence, observed_text, previous_checkpoint_digest, accepted_view, receipt_digests, proof_digest, reconciliation_digest, governance_digest)
        verify_witness_quorum(checkpoint.get("witnessEndorsements"), witness_map, "checkpoint", current_checkpoint_digest, prefix, errors, observed_text)
        previous_checkpoint_digest = current_checkpoint_digest
        accepted_checkpoint_digests.append(current_checkpoint_digest); accepted_view_digests.append(accepted_view)

    observed_span = 0
    if first_time is not None and last_time is not None:
        observed_span = int((last_time - first_time).total_seconds())
        if observed_span < MIN_SPAN_SECONDS: errors.append("minimum-observed-span-not-met")
    if split_brain_count < 1: errors.append("derived-split-brain-exercise-missing")
    if reconciliation_count < 1: errors.append("authenticated-reconciliation-record-missing")
    return {
        "checkpoints": checkpoints,
        "checkpointDigests": accepted_checkpoint_digests,
        "viewDigests": accepted_view_digests,
        "checkpointCount": len(checkpoints),
        "registryReceiptCount": total_receipts,
        "splitBrainProofCount": split_brain_count,
        "reconciliationRecordCount": reconciliation_count,
        "governanceReconciliationCount": governance_count,
        "observedSpanSeconds": observed_span,
    }
