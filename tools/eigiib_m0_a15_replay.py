#!/usr/bin/env python3
from datetime import datetime, timezone

A14_HEAD = "5936ed072187cd7fe72db2c33119c8db92d06570"
REGISTRIES = ("maintenance-registry-alpha","maintenance-registry-beta","maintenance-registry-gamma")
DIMENSIONS = ("providerOperator","tenantAccount","identityRoot","privilegedAdministrator","storageDomain","auditCustody")
MIN_CHECKPOINTS = 6
MIN_SPAN = 7776000
WITNESS_QUORUM = 4

def _dt(value):
    try:
        x=datetime.fromisoformat(value.replace("Z","+00:00"))
        return x if x.tzinfo else x.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def _hex(value, n=64):
    return isinstance(value,str) and len(value)==n and all(c in "0123456789abcdef" for c in value)

def _registry_independence(registries):
    errors=[]
    if {r.get("registryId") for r in registries} != set(REGISTRIES):
        errors.append("registry-inventory-invalid")
    for dim in DIMENSIONS:
        values=[r.get(dim) for r in registries]
        if any(not v for v in values) or len(set(values)) != len(REGISTRIES):
            errors.append(f"registry-independence-{dim}-invalid")
    return errors

def _witness_independence(witnesses, registries):
    errors=[]
    if len(witnesses) != 5 or len({w.get("witnessId") for w in witnesses}) != 5:
        errors.append("witness-inventory-invalid")
    if len({w.get("controlDomainId") for w in witnesses}) != 5:
        errors.append("witness-control-domains-not-independent")
    registry_roots={r.get("identityRoot") for r in registries}
    if any(w.get("identityRoot") in registry_roots or not w.get("identityRoot") for w in witnesses):
        errors.append("witness-registry-identity-overlap")
    return errors

def _witness_quorum(endorsements, digest, prefix, witness_ids):
    errors=[]
    valid=[e for e in endorsements if e.get("witnessId") in witness_ids]
    if len({e.get("witnessId") for e in valid}) < WITNESS_QUORUM:
        errors.append(f"{prefix}-witness-quorum-not-met")
    if len({e.get("controlDomainId") for e in valid}) < WITNESS_QUORUM:
        errors.append(f"{prefix}-witness-domains-not-independent")
    if any(e.get("recordDigest") != digest for e in valid):
        errors.append(f"{prefix}-witness-record-digest-mismatch")
    return errors

def verify_case(case):
    errors=[]
    if case.get("a14Decision") != "verified" or case.get("a14Head") != A14_HEAD or not case.get("a14ContinuityCertificateValid"):
        errors.append("m0-a14-not-verified")
    registries=case.get("registries",[])
    witnesses=case.get("witnesses",[])
    errors.extend(_registry_independence(registries))
    errors.extend(_witness_independence(witnesses,registries))
    witness_ids={w.get("witnessId") for w in witnesses}
    checkpoints=case.get("checkpoints",[])
    if len(checkpoints)<MIN_CHECKPOINTS:
        errors.append("minimum-checkpoint-count-not-met")
    previous_receipts={r:None for r in REGISTRIES}
    receipt_digests=set()
    checkpoint_digests=set()
    split_count=0
    reconciliation_count=0
    governance_count=0
    first_time=None
    last_time=None
    previous_time=None
    previous_governance=None
    previous_tip=None
    for index,cp in enumerate(checkpoints,1):
        prefix=f"checkpoint-{index}"
        if cp.get("sequence") != index:
            errors.append("checkpoint-sequence-gap")
        observed=_dt(cp.get("observedAt",""))
        if not observed:
            errors.append(f"{prefix}-time-invalid")
        else:
            if previous_time is not None and observed <= previous_time:
                errors.append("checkpoint-time-not-monotonic")
            previous_time=observed
            first_time=first_time or observed
            last_time=observed
        checkpoint_digest=cp.get("checkpointDigest")
        tip=cp.get("cycleTipDigest")
        governance=cp.get("governanceSnapshotDigest")
        if not _hex(checkpoint_digest) or checkpoint_digest in checkpoint_digests:
            errors.append("checkpoint-digest-invalid-or-reused")
        checkpoint_digests.add(checkpoint_digest)
        if not _hex(tip):
            errors.append(f"{prefix}-cycle-tip-invalid")
        if not _hex(governance):
            errors.append(f"{prefix}-governance-digest-invalid")
        if index>1 and cp.get("previousCheckpointDigest") != checkpoints[index-2].get("checkpointDigest"):
            errors.append("checkpoint-chain-broken")
        receipts=cp.get("registryReceipts",[])
        if {r.get("registryId") for r in receipts} != set(REGISTRIES) or len(receipts)!=3:
            errors.append(f"{prefix}-registry-receipts-incomplete")
        for receipt in receipts:
            rid=receipt.get("registryId")
            if receipt.get("sequence") != index or receipt.get("checkpointDigest") != checkpoint_digest:
                errors.append(f"{prefix}-registry-receipt-binding-mismatch")
            if receipt.get("cycleTipDigest") != tip or receipt.get("governanceSnapshotDigest") != governance:
                errors.append(f"{prefix}-cross-registry-state-divergence")
            if receipt.get("previousReceiptDigest") != previous_receipts.get(rid):
                errors.append(f"{prefix}-registry-receipt-chain-broken")
            rd=receipt.get("receiptDigest")
            if not _hex(rd) or rd in receipt_digests:
                errors.append(f"{prefix}-receipt-digest-invalid-or-reused")
            receipt_digests.add(rd)
            if rid in previous_receipts:
                previous_receipts[rid]=rd
            if receipt.get("status") != "authoritative":
                errors.append(f"{prefix}-nonauthoritative-registry-receipt")
        errors.extend(_witness_quorum(cp.get("witnessEndorsements",[]),checkpoint_digest,prefix,witness_ids))
        governance_rec=cp.get("governanceReconciliation")
        if previous_governance is not None and governance != previous_governance:
            if not isinstance(governance_rec,dict):
                errors.append("governance-change-unreconciled")
            else:
                governance_count+=1
                if governance_rec.get("fromSnapshotDigest") != previous_governance or governance_rec.get("toSnapshotDigest") != governance:
                    errors.append("governance-reconciliation-chain-mismatch")
                if not governance_rec.get("nonWeakening"):
                    errors.append("governance-reconciliation-weakening")
                if not governance_rec.get("threeCollegeIdenticalApproval") or not governance_rec.get("independentReviewValid"):
                    errors.append("governance-reconciliation-approval-invalid")
                effective=_dt(governance_rec.get("effectiveAt",""))
                if not effective or (observed and effective>observed):
                    errors.append("governance-reconciliation-late-or-invalid")
        elif governance_rec is not None:
            errors.append("spurious-governance-reconciliation")
        previous_governance=governance
        events=cp.get("splitBrainEvents",[])
        split_count+=len(events)
        record=cp.get("reconciliationRecord")
        if events:
            if not isinstance(record,dict):
                errors.append("split-brain-unresolved")
            else:
                reconciliation_count+=1
                event_ids={e.get("eventId") for e in events}
                if record.get("eventIds") is None or set(record.get("eventIds",[])) != event_ids:
                    errors.append("reconciliation-event-binding-mismatch")
                if not _hex(record.get("commonAncestorDigest")):
                    errors.append("reconciliation-common-ancestor-invalid")
                candidates=record.get("candidateHeads",[])
                if len(set(candidates))<2 or not all(_hex(x) for x in candidates):
                    errors.append("reconciliation-candidates-invalid")
                if record.get("authoritativeHead") != tip or tip not in candidates:
                    errors.append("reconciliation-authoritative-head-mismatch")
                support=set(record.get("supportingRegistryIds",[]))
                if len(support)<2 or not support.issubset(set(REGISTRIES)):
                    errors.append("reconciliation-registry-support-insufficient")
                quarantine=set(record.get("quarantinedRegistryIds",[]))
                if not quarantine or not quarantine.issubset(set(REGISTRIES)) or support & quarantine:
                    errors.append("reconciliation-quarantine-invalid")
                digest=record.get("recordDigest")
                if not _hex(digest):
                    errors.append("reconciliation-record-digest-invalid")
                errors.extend(_witness_quorum(record.get("witnessEndorsements",[]),digest,"reconciliation",witness_ids))
                if not record.get("appendOnly") or not record.get("staleHeadsRejected"):
                    errors.append("reconciliation-anti-rollback-invalid")
                if not record.get("quarantinedRegistryReadbackValid") or not record.get("independentPublishedReadbackValid"):
                    errors.append("reconciliation-readback-missing")
                if not record.get("governanceReconciliationValid"):
                    errors.append("reconciliation-governance-invalid")
        elif record is not None:
            errors.append("spurious-reconciliation-record")
        for event in events:
            if event.get("sequence") != index or event.get("checkpointDigest") != checkpoint_digest:
                errors.append("split-brain-event-binding-mismatch")
            if event.get("detectionDecision") != "freeze-and-quarantine":
                errors.append("split-brain-detection-decision-invalid")
            heads=event.get("conflictingHeads",[])
            if len(set(heads))<2 or not all(_hex(x) for x in heads):
                errors.append("split-brain-conflicting-heads-invalid")
        if previous_tip is not None and cp.get("previousCycleTipDigest") != previous_tip:
            errors.append("cycle-tip-history-chain-broken")
        previous_tip=tip
    if first_time and last_time and (last_time-first_time).total_seconds()<MIN_SPAN:
        errors.append("minimum-observed-span-not-met")
    if split_count<1:
        errors.append("split-brain-exercise-missing")
    if reconciliation_count<1:
        errors.append("reconciliation-record-missing")
    if not case.get("longTermReconciliationCertificateValid"):
        errors.append("long-term-reconciliation-certificate-invalid")
    if not case.get("independentManualReadbackValid"):
        errors.append("independent-manual-readback-missing")
    return {"verified":not errors,"errors":sorted(set(errors)),"summary":{
        "checkpointCount":len(checkpoints),"registryReceiptCount":sum(len(c.get("registryReceipts",[])) for c in checkpoints),
        "splitBrainEventCount":split_count,"reconciliationRecordCount":reconciliation_count,
        "governanceReconciliationCount":governance_count,
        "latestCheckpointDigest":checkpoints[-1].get("checkpointDigest") if checkpoints else None
    }}
