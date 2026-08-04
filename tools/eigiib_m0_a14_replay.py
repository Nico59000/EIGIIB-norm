#!/usr/bin/env python3
from datetime import datetime, timezone

A13_HEAD = "d096b9fbf68cead15a3a9eb7bf4cff1493a0aa45"
COLLEGES = ("normative-authority-college","operational-governance-college","independent-verification-college")
ALLOWED_CLASSES = ("normative-correction","security-emergency","deprecation-or-withdrawal")
MIN_CYCLES = 3
MIN_SPAN = 2592000

def _dt(value):
    try:
        x=datetime.fromisoformat(value.replace("Z","+00:00"))
        return x if x.tzinfo else x.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def _exact_paths(paths):
    return bool(paths) and len(paths)==len(set(paths)) and not any(p.startswith("/") or ".." in p.split("/") or any(c in p for c in "*?[") for p in paths)

def _approval_errors(approvals, record_digest, prefix):
    errors=[]; seen={}
    for college in COLLEGES:
        subset=[a for a in approvals if a.get("collegeId")==college]
        if len({a.get("approverId") for a in subset})<4: errors.append(f"{prefix}-{college}-threshold-not-met")
        if len({a.get("controlDomainId") for a in subset})<4: errors.append(f"{prefix}-{college}-domains-not-independent")
        if any(a.get("recordDigest")!=record_digest for a in subset): errors.append(f"{prefix}-{college}-record-digest-mismatch")
        for a in subset:
            aid=a.get("approverId"); old=seen.get(aid)
            if old is not None and old!=college: errors.append(f"{prefix}-cross-college-identity-overlap")
            seen[aid]=college
    return errors

def _snapshot_errors(snapshot, prefix):
    errors=[]; colleges=snapshot.get("colleges",[]) if isinstance(snapshot,dict) else []
    if len(colleges)!=3: return [f"{prefix}-snapshot-college-count-invalid"]
    ids=[]; all_members={}
    for c in colleges:
        cid=c.get("id"); ids.append(cid)
        if c.get("threshold",0)<4: errors.append(f"{prefix}-threshold-weakened")
        if c.get("members",0)<5 or len(set(c.get("memberIds",[])))<5: errors.append(f"{prefix}-member-count-weakened")
        if c.get("distinctControlDomains",0)<4 or len(set(c.get("controlDomainIds",[])))<4: errors.append(f"{prefix}-control-domain-collapse")
        for m in c.get("memberIds",[]):
            old=all_members.get(m)
            if old is not None and old!=cid: errors.append(f"{prefix}-cross-college-member-overlap")
            all_members[m]=cid
    if set(ids)!=set(COLLEGES): errors.append(f"{prefix}-snapshot-colleges-invalid")
    if snapshot.get("unknownControlOverlap") is not False: errors.append(f"{prefix}-unknown-control-overlap")
    if not isinstance(snapshot.get("snapshotDigest"),str) or len(snapshot.get("snapshotDigest"))!=64: errors.append(f"{prefix}-snapshot-digest-invalid")
    return errors

def verify_case(case):
    errors=[]
    if case.get("a13Decision")!="verified" or case.get("a13Head")!=A13_HEAD or not case.get("a13ClosureCertificateValid"):
        errors.append("m0-a13-not-verified")
    initial=case.get("initialRefreezeDigest")
    if not isinstance(initial,str) or len(initial)!=64: errors.append("initial-refreeze-digest-invalid")
    cycles=case.get("cycles",[])
    if len(cycles)<MIN_CYCLES: errors.append("minimum-cycle-count-not-met")
    event_ids=set(); requests=set(); authorities=set(); refreezes=set(); revocation_count=0; transition_count=0
    previous_digest=initial; previous_closed=None; first_issued=None; last_closed=None; previous_snapshot=None
    for index,cycle in enumerate(cycles,1):
        prefix=f"cycle-{index}"
        if cycle.get("sequence")!=index: errors.append("cycle-sequence-gap")
        event=cycle.get("maintenanceEventId")
        if not event or event in event_ids: errors.append("maintenance-event-id-not-unique")
        event_ids.add(event)
        if cycle.get("maintenanceClass") not in ALLOWED_CLASSES: errors.append(f"{prefix}-class-not-authorized")
        if cycle.get("predecessorRefreezeDigest")!=previous_digest: errors.append("refreeze-chain-broken")
        successor=cycle.get("successorRefreezeDigest")
        if not isinstance(successor,str) or len(successor)!=64 or successor in refreezes: errors.append("successor-refreeze-invalid-or-reused")
        refreezes.add(successor); previous_digest=successor
        req=cycle.get("requestDigest"); auth=cycle.get("reopeningAuthorityDigest")
        if not isinstance(req,str) or len(req)!=64 or req in requests: errors.append("request-digest-invalid-or-reused")
        if not isinstance(auth,str) or len(auth)!=64 or auth in authorities: errors.append("authority-digest-invalid-or-reused")
        requests.add(req); authorities.add(auth)
        paths=cycle.get("affectedPaths",[])
        if not _exact_paths(paths): errors.append(f"{prefix}-scope-not-exact")
        if set(cycle.get("implementedPaths",[]))!=set(paths): errors.append(f"{prefix}-scope-expansion-or-omission")
        errors.extend(_approval_errors(cycle.get("approvals",[]),req,prefix))
        issued,expires,executed,closed=map(_dt,[cycle.get("issuedAt",""),cycle.get("expiresAt",""),cycle.get("executedAt",""),cycle.get("closedAt","")])
        if not all([issued,expires,executed,closed]) or not (issued < executed <= closed and issued < expires and executed <= expires): errors.append(f"{prefix}-time-invalid")
        else:
            maxlife=86400 if cycle.get("maintenanceClass")=="security-emergency" else 604800
            if (expires-issued).total_seconds()>maxlife: errors.append(f"{prefix}-authority-lifetime-exceeded")
            if previous_closed is not None and issued<=previous_closed: errors.append("cycle-overlap-or-nonmonotonic-time")
            previous_closed=closed; first_issued=first_issued or issued; last_closed=closed
        snapshot=cycle.get("governanceSnapshot",{}); errors.extend(_snapshot_errors(snapshot,prefix))
        current_snapshot=snapshot.get("snapshotDigest")
        transition=cycle.get("governanceTransition")
        if previous_snapshot is not None and current_snapshot!=previous_snapshot:
            if not isinstance(transition,dict): errors.append("governance-drift-undeclared")
            else:
                transition_count+=1
                if transition.get("fromSnapshotDigest")!=previous_snapshot or transition.get("toSnapshotDigest")!=current_snapshot: errors.append("governance-transition-chain-mismatch")
                if not transition.get("independentReviewValid"): errors.append("governance-transition-review-missing")
                errors.extend(_approval_errors(transition.get("approvals",[]),current_snapshot,"governance-transition"))
                effective=_dt(transition.get("effectiveAt",""))
                if not effective or (issued and effective>issued): errors.append("governance-transition-retroactive-or-late")
        elif transition is not None:
            errors.append("spurious-governance-transition")
        previous_snapshot=current_snapshot
        revocations=cycle.get("revocationEvents",[]); revocation_count+=len(revocations)
        earliest_revocation=None
        for rev in revocations:
            if rev.get("requestDigest")!=req: errors.append("revocation-request-digest-mismatch")
            subset=rev.get("approvals",[]); college=rev.get("collegeId")
            if college not in COLLEGES: errors.append("revocation-college-invalid")
            if len({a.get("approverId") for a in subset if a.get("collegeId")==college})<4: errors.append("revocation-threshold-not-met")
            if len({a.get("controlDomainId") for a in subset if a.get("collegeId")==college})<4: errors.append("revocation-domains-not-independent")
            if any(a.get("recordDigest")!=req for a in subset): errors.append("revocation-record-digest-mismatch")
            rt=_dt(rev.get("effectiveAt",""))
            if not rt: errors.append("revocation-time-invalid")
            elif earliest_revocation is None or rt<earliest_revocation: earliest_revocation=rt
            if rev.get("outcome") not in ("revoked-and-rolled-back","revoked-and-refrozen"): errors.append("revocation-outcome-invalid")
        if earliest_revocation:
            for w in cycle.get("authorizedWrites",[]):
                wt=_dt(w.get("at",""))
                if not wt or wt>=earliest_revocation: errors.append("post-revocation-write-detected")
        if not cycle.get("supersessionRecordValid"): errors.append(f"{prefix}-supersession-record-invalid")
        if not cycle.get("independentVerificationValid"): errors.append(f"{prefix}-independent-verification-missing")
        if not cycle.get("workflowConclusions") or any(x!="success" for x in cycle.get("workflowConclusions",[])): errors.append(f"{prefix}-workflow-inventory-not-green")
        if not cycle.get("refreezeManifestValid"): errors.append(f"{prefix}-refreeze-manifest-invalid")
        if not cycle.get("independentRefreezeReadbackValid"): errors.append(f"{prefix}-refreeze-readback-missing")
        if not cycle.get("closureCertificateValid"): errors.append(f"{prefix}-closure-certificate-invalid")
    if first_issued and last_closed and (last_closed-first_issued).total_seconds()<MIN_SPAN: errors.append("minimum-observed-span-not-met")
    if revocation_count<1: errors.append("revocation-exercise-missing")
    if not case.get("continuityCertificateValid"): errors.append("continuity-certificate-invalid")
    return {"verified":not errors,"errors":sorted(set(errors)),"summary":{"cycleCount":len(cycles),"revocationEventCount":revocation_count,"governanceTransitionCount":transition_count,"latestRefreezeDigest":previous_digest}}
