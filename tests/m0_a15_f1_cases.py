import base64
import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_m0_a15_f1_canonical import CanonicalValueError, canonical_bytes, digest_hex
from eigiib_m0_a15_f1_check import evaluate, validate_evidence_schema
from eigiib_m0_a15_f1_crypto import verify_envelope
from eigiib_m0_a15_f1_replay import (
    A15_HEAD,
    A15_TREE,
    REGISTRY_IDS,
    candidate_view_digest,
    checkpoint_digest,
    split_brain_proof_base,
    verify_case,
)


def h(number):
    return f"{number:064x}"[-64:]


def key(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public_b64(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def sign(private_key, key_id, payload):
    signature = private_key.sign(canonical_bytes(payload))
    return {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "keyId": key_id,
            "value": base64.b64encode(signature).decode(),
        },
    }


class CaseBuilder:
    def __init__(self):
        self.private = {}
        self.registries = []
        for index, registry_id in enumerate(REGISTRY_IDS, 1):
            private = key(index)
            key_id = f"registry-key-{index}"
            self.private[key_id] = private
            self.registries.append({
                "registryId": registry_id,
                "providerOperator": f"registry-provider-{index}",
                "tenantAccount": f"registry-tenant-{index}",
                "identityRoot": f"registry-root-{index}",
                "privilegedAdministrator": f"registry-admin-{index}",
                "storageDomain": f"registry-storage-{index}",
                "auditCustody": f"registry-audit-{index}",
                "keyId": key_id,
                "algorithm": "ed25519",
                "publicKey": public_b64(private),
            })
        self.witnesses = []
        for index in range(1, 6):
            private = key(3 + index)
            key_id = f"witness-key-{index}"
            self.private[key_id] = private
            self.witnesses.append({
                "witnessId": f"witness-{index}",
                "controlDomainId": f"witness-domain-{index}",
                "identityRoot": f"witness-root-{index}",
                "keyId": key_id,
                "algorithm": "ed25519",
                "publicKey": public_b64(private),
            })
        self.observers = []
        for index in range(1, 4):
            private = key(8 + index)
            key_id = f"observer-key-{index}"
            self.private[key_id] = private
            self.observers.append({
                "observerId": f"observer-{index}",
                "controlDomainId": f"observer-domain-{index}",
                "identityRoot": f"observer-root-{index}",
                "providerOperator": f"observer-provider-{index}",
                "networkPath": f"observer-network-{index}",
                "implementation": f"observer-implementation-{index}",
                "keyId": key_id,
                "algorithm": "ed25519",
                "publicKey": public_b64(private),
            })
        self.registry_map = {p["registryId"]: p for p in self.registries}
        self.witness_map = {p["witnessId"]: p for p in self.witnesses}
        self.observer_map = {p["observerId"]: p for p in self.observers}

    def endorse(self, record_type, record_digest, at):
        envelopes = []
        for profile in self.witnesses[:4]:
            payload = {
                "witnessId": profile["witnessId"],
                "controlDomainId": profile["controlDomainId"],
                "recordType": record_type,
                "recordDigest": record_digest,
                "signedAt": at,
            }
            envelopes.append(sign(self.private[profile["keyId"]], profile["keyId"], payload))
        return envelopes

    def readback(self, observer_id, subject_type, subject_digest, content_digest, scope, registry_id, at):
        profile = self.observer_map[observer_id]
        payload = {
            "observerId": observer_id,
            "controlDomainId": profile["controlDomainId"],
            "subjectType": subject_type,
            "subjectDigest": subject_digest,
            "contentDigest": content_digest,
            "scope": scope,
            "registryId": registry_id,
            "observedAt": at,
            "locator": f"https://example.invalid/{observer_id}/{subject_digest}",
        }
        return sign(self.private[profile["keyId"]], profile["keyId"], payload)

    def build(self):
        a14_digest = h(9000)
        a14_at = "2025-12-31T12:00:00Z"
        a14 = {
            "case": {"syntheticExactA14ReplayCase": "covered-by-historical-verifier"},
            "witnessEndorsements": self.endorse("a14-continuity-replay", a14_digest, a14_at),
        }
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        previous_checkpoint = None
        previous_receipts = {registry_id: None for registry_id in REGISTRY_IDS}
        checkpoints = []
        checkpoint_digests = []
        accepted_views = []
        split_count = 0
        reconciliation_count = 0
        total_receipts = 0

        for sequence in range(1, 7):
            observed = start + timedelta(days=(sequence - 1) * 18)
            observed_text = observed.isoformat().replace("+00:00", "Z")
            receipt_envelopes = []
            candidate_views = {}
            receipt_digests = []
            for registry_id in REGISTRY_IDS:
                profile = self.registry_map[registry_id]
                tip = h(200 + sequence)
                if sequence == 3 and registry_id == REGISTRY_IDS[2]:
                    tip = h(999)
                payload = {
                    "registryId": registry_id,
                    "sequence": sequence,
                    "observedAt": observed_text,
                    "previousAcceptedCheckpointDigest": previous_checkpoint,
                    "cycleTipDigest": tip,
                    "governanceSnapshotDigest": h(300),
                    "previousReceiptDigest": previous_receipts[registry_id],
                    "status": "authoritative",
                }
                envelope = sign(self.private[profile["keyId"]], profile["keyId"], payload)
                receipt_envelopes.append(envelope)
                receipt_digest = digest_hex(payload)
                previous_receipts[registry_id] = receipt_digest
                receipt_digests.append(receipt_digest)
                candidate_views[registry_id] = candidate_view_digest(payload)
                total_receipts += 1

            proof = None
            reconciliation = None
            proof_digest = None
            reconciliation_digest = None
            view_counts = {}
            for view in candidate_views.values():
                view_counts[view] = view_counts.get(view, 0) + 1
            if len(view_counts) == 1:
                accepted_view = next(iter(view_counts))
            else:
                split_count += 1
                proof_base = split_brain_proof_base(sequence, receipt_digests, candidate_views)
                proof_digest = digest_hex(proof_base)
                proof = {**proof_base, "proofDigest": proof_digest}
                accepted_view = max(sorted(view_counts), key=lambda item: view_counts[item])
                support = sorted(k for k, value in candidate_views.items() if value == accepted_view)
                quarantine = sorted(set(candidate_views) - set(support))
                reconciliation_payload = {
                    "sequence": sequence,
                    "commonAncestorCheckpointDigest": previous_checkpoint,
                    "derivedSplitBrainProofDigest": proof_digest,
                    "candidateViewDigests": sorted(view_counts),
                    "authoritativeViewDigest": accepted_view,
                    "supportingRegistryIds": support,
                    "quarantinedRegistryIds": quarantine,
                    "appendOnly": True,
                    "staleViewsRejected": True,
                }
                reconciliation_digest = digest_hex(reconciliation_payload)
                endorsement_time = (observed + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
                readback_time = (observed + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
                reconciliation = {
                    "payload": reconciliation_payload,
                    "witnessEndorsements": self.endorse("reconciliation", reconciliation_digest, endorsement_time),
                    "readbacks": [
                        self.readback("observer-1", "reconciliation", reconciliation_digest, accepted_view, "authoritative-published-state", None, readback_time),
                        self.readback("observer-2", "reconciliation", reconciliation_digest, candidate_views[quarantine[0]], "quarantined-registry-state", quarantine[0], readback_time),
                    ],
                }
                reconciliation_count += 1

            current_checkpoint_digest = checkpoint_digest(
                sequence,
                observed_text,
                previous_checkpoint,
                accepted_view,
                receipt_digests,
                proof_digest,
                reconciliation_digest,
                None,
            )
            endorsement_time = (observed + timedelta(hours=3)).isoformat().replace("+00:00", "Z")
            checkpoints.append({
                "sequence": sequence,
                "observedAt": observed_text,
                "previousAcceptedCheckpointDigest": previous_checkpoint,
                "registryReceipts": receipt_envelopes,
                "derivedSplitBrainProof": proof,
                "reconciliationRecord": reconciliation,
                "governanceReconciliation": None,
                "witnessEndorsements": self.endorse("checkpoint", current_checkpoint_digest, endorsement_time),
            })
            previous_checkpoint = current_checkpoint_digest
            checkpoint_digests.append(current_checkpoint_digest)
            accepted_views.append(accepted_view)

        observed_span = int((start + timedelta(days=90) - start).total_seconds())
        certificate_payload = {
            "sourceA15Head": A15_HEAD,
            "sourceA15Tree": A15_TREE,
            "a14ReplayDigest": a14_digest,
            "firstCheckpointDigest": checkpoint_digests[0],
            "lastCheckpointDigest": checkpoint_digests[-1],
            "checkpointCount": 6,
            "observedSpanSeconds": observed_span,
            "registryReceiptCount": total_receipts,
            "splitBrainProofCount": split_count,
            "reconciliationRecordCount": reconciliation_count,
            "governanceReconciliationCount": 0,
            "finalAuthoritativeViewDigest": accepted_views[-1],
            "decision": "authenticated-multi-registry-evidence-derived-split-brain-and-exact-a14-continuity-verified",
        }
        certificate_digest = digest_hex(certificate_payload)
        certificate_time = (start + timedelta(days=90, hours=4)).isoformat().replace("+00:00", "Z")
        certificate = {
            "payload": certificate_payload,
            "witnessEndorsements": self.endorse("long-term-certificate", certificate_digest, certificate_time),
            "readbacks": [
                self.readback("observer-1", "long-term-certificate", certificate_digest, checkpoint_digests[-1], "long-term-certificate", None, certificate_time),
                self.readback("observer-2", "long-term-certificate", certificate_digest, checkpoint_digests[-1], "long-term-certificate", None, certificate_time),
            ],
        }
        return {
            "a14Replay": a14,
            "registries": deepcopy(self.registries),
            "witnesses": deepcopy(self.witnesses),
            "readbackObservers": deepcopy(self.observers),
            "checkpoints": checkpoints,
            "longTermCertificate": certificate,
        }


