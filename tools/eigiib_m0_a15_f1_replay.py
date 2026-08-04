#!/usr/bin/env python3
"""Authenticated multi-registry replay and exact A14 continuity gate for M0-A15-F1."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from eigiib_m0_a15_f1_canonical import digest_hex, is_hex
from eigiib_m0_a15_f1_checkpoints import verify_checkpoints
from eigiib_m0_a15_f1_historical_a14 import verify_a14_replay
from eigiib_m0_a15_f1_model import (
    A15_HEAD, A15_TREE, CERTIFICATE_PAYLOAD_KEYS, REGISTRY_IDS,
    candidate_view_digest, checkpoint_digest, shape, split_brain_proof_base,
)
from eigiib_m0_a15_f1_principals import profile_maps, verify_readbacks, verify_witness_quorum


def verify_case(case: Any, root: Path) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(case, dict) or set(case) != {
        "a14Replay", "registries", "witnesses", "readbackObservers", "checkpoints", "longTermCertificate"
    }:
        return {"verified": False, "errors": ["evidence-shape-invalid"], "summary": {}}

    registry_map, witness_map, observer_map = profile_maps(case, errors)
    a14_section = case.get("a14Replay")
    if not isinstance(a14_section, dict) or set(a14_section) != {"case", "witnessEndorsements"}:
        errors.append("a14-replay-section-shape-invalid")
        a14_result: dict[str, Any] = {"verified": False, "replayDigest": None, "errors": ["a14-replay-section-invalid"]}
    else:
        a14_result = verify_a14_replay(root, a14_section.get("case")); errors.extend(a14_result.get("errors", []))
        replay_digest = a14_result.get("replayDigest")
        if not a14_result.get("verified") or not is_hex(replay_digest):
            errors.append("a14-exact-continuity-replay-not-verified")
        else:
            verify_witness_quorum(a14_section.get("witnessEndorsements"), witness_map, "a14-continuity-replay", replay_digest, "a14-replay", errors)

    state = verify_checkpoints(case.get("checkpoints"), registry_map, witness_map, observer_map, errors)
    certificate = case.get("longTermCertificate"); certificate_digest: str | None = None
    checkpoints = state["checkpoints"]
    checkpoint_digests = state["checkpointDigests"]
    view_digests = state["viewDigests"]
    expected_payload = {
        "sourceA15Head": A15_HEAD,
        "sourceA15Tree": A15_TREE,
        "a14ReplayDigest": a14_result.get("replayDigest"),
        "firstCheckpointDigest": checkpoint_digests[0] if checkpoint_digests else None,
        "lastCheckpointDigest": checkpoint_digests[-1] if checkpoint_digests else None,
        "checkpointCount": state["checkpointCount"],
        "observedSpanSeconds": state["observedSpanSeconds"],
        "registryReceiptCount": state["registryReceiptCount"],
        "splitBrainProofCount": state["splitBrainProofCount"],
        "reconciliationRecordCount": state["reconciliationRecordCount"],
        "governanceReconciliationCount": state["governanceReconciliationCount"],
        "finalAuthoritativeViewDigest": view_digests[-1] if view_digests else None,
        "decision": "authenticated-multi-registry-evidence-derived-split-brain-and-exact-a14-continuity-verified",
    }
    if not isinstance(certificate, dict) or set(certificate) != {"payload", "witnessEndorsements", "readbacks"}:
        errors.append("long-term-certificate-shape-invalid")
    else:
        payload = certificate.get("payload")
        if shape(payload, CERTIFICATE_PAYLOAD_KEYS, "long-term-certificate", errors):
            if payload != expected_payload:
                errors.append("long-term-certificate-not-derived")
            else:
                certificate_digest = digest_hex(payload)
                verify_witness_quorum(certificate.get("witnessEndorsements"), witness_map, "long-term-certificate", certificate_digest, "long-term-certificate", errors, checkpoints[-1].get("observedAt") if checkpoints else None)
                readbacks = verify_readbacks(certificate.get("readbacks"), observer_map, "long-term-certificate", errors)
                valid_observers: set[str] = set()
                for readback in readbacks:
                    if readback.get("subjectType") == "long-term-certificate" and readback.get("subjectDigest") == certificate_digest and readback.get("contentDigest") == expected_payload.get("lastCheckpointDigest") and readback.get("scope") == "long-term-certificate" and readback.get("registryId") is None:
                        valid_observers.add(readback.get("observerId"))
                    else:
                        errors.append("long-term-certificate-readback-binding-mismatch")
                if len(valid_observers) < 2: errors.append("long-term-certificate-independent-readback-missing")

    return {
        "verified": not errors,
        "errors": sorted(set(errors)),
        "summary": {
            "a14ReplayDigest": a14_result.get("replayDigest"),
            "checkpointCount": state["checkpointCount"],
            "registryReceiptCount": state["registryReceiptCount"],
            "splitBrainProofCount": state["splitBrainProofCount"],
            "reconciliationRecordCount": state["reconciliationRecordCount"],
            "governanceReconciliationCount": state["governanceReconciliationCount"],
            "observedSpanSeconds": state["observedSpanSeconds"],
            "latestCheckpointDigest": checkpoint_digests[-1] if checkpoint_digests else None,
            "longTermCertificateDigest": certificate_digest,
        },
    }
