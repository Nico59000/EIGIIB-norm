#!/usr/bin/env python3
from datetime import datetime, timezone

F5_HEAD = "58945ceab905cb515dff076227bb2b387f907461"
FREEZE_ID = "eigiib-m0-final-freeze-v1"
COLLEGES = (
    "normative-authority-college",
    "operational-governance-college",
    "independent-verification-college",
)
ALLOWED_CLASSES = ("normative-correction", "security-emergency", "deprecation-or-withdrawal")

def _dt(value):
    try:
        x = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return x if x.tzinfo else x.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def verify_case(case):
    errors = []
    if case.get("f5Decision") != "frozen":
        errors.append("f5-not-frozen")
    if case.get("freezeId") != FREEZE_ID:
        errors.append("freeze-anchor-mismatch")
    if not case.get("freezeReadbackValid"):
        errors.append("freeze-readback-missing")
    if case.get("maintenanceClass") not in ALLOWED_CLASSES:
        errors.append("maintenance-class-not-authorized")
    paths = case.get("affectedPaths", [])
    if not paths or len(paths) != len(set(paths)):
        errors.append("scope-paths-invalid")
    if any(p.startswith("/") or ".." in p.split("/") or any(c in p for c in "*?[") for p in paths):
        errors.append("scope-not-exact")
    if case.get("implementedPaths") is not None and set(case.get("implementedPaths", [])) != set(paths):
        errors.append("scope-expansion-or-omission")
    request_digest = case.get("requestDigest")
    approvals = case.get("approvals", [])
    approver_to_college = {}
    for college in COLLEGES:
        subset = [a for a in approvals if a.get("collegeId") == college]
        if len({a.get("approverId") for a in subset}) < 4:
            errors.append(f"{college}-threshold-not-met")
        if len({a.get("controlDomainId") for a in subset}) < 4:
            errors.append(f"{college}-control-domains-not-independent")
        if any(a.get("requestDigest") != request_digest for a in subset):
            errors.append(f"{college}-request-digest-mismatch")
        for a in subset:
            aid = a.get("approverId")
            old = approver_to_college.get(aid)
            if old is not None and old != college:
                errors.append("cross-college-approver-overlap")
            approver_to_college[aid] = college
    issued, expires, executed = _dt(case.get("issuedAt","")), _dt(case.get("expiresAt","")), _dt(case.get("executedAt",""))
    if not issued or not expires or not executed or not (issued < expires):
        errors.append("reopening-time-invalid")
    else:
        max_life = 86400 if case.get("maintenanceClass") == "security-emergency" else 604800
        if (expires-issued).total_seconds() > max_life:
            errors.append("reopening-lifetime-exceeded")
        if executed > expires:
            errors.append("reopening-expired")
    if case.get("revoked"):
        errors.append("reopening-revoked")
    if case.get("predecessorHead") != F5_HEAD:
        errors.append("predecessor-head-mismatch")
    if case.get("inPlaceMutation"):
        errors.append("in-place-mutation-forbidden")
    successor = case.get("successorHead")
    if not isinstance(successor, str) or len(successor) != 40 or successor == F5_HEAD:
        errors.append("successor-head-invalid")
    if not case.get("independentVerificationValid"):
        errors.append("independent-verification-missing")
    if not case.get("supersessionRecordValid"):
        errors.append("supersession-record-invalid")
    if case.get("staleAuthorityReplay") != "rejected":
        errors.append("stale-authority-not-rejected")
    if not case.get("refreezeManifestValid"):
        errors.append("refreeze-manifest-invalid")
    if not case.get("independentRefreezeReadbackValid"):
        errors.append("independent-refreeze-readback-missing")
    conclusions = case.get("workflowConclusions", [])
    if not conclusions or any(x != "success" for x in conclusions):
        errors.append("workflow-inventory-not-green")
    if not case.get("closureCertificateValid"):
        errors.append("maintenance-closure-certificate-invalid")
    return {"verified": not errors, "errors": sorted(set(errors))}
