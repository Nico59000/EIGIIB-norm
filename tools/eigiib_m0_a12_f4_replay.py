#!/usr/bin/env python3
BUNDLE="96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
def verify_case(case):
 errors=[]
 if case.get("f3Decision")!="verified": errors.append("f3-not-T")
 if len(set(case.get("lostAuthorities",[])))<2: errors.append("insufficient-loss-declaration")
 approvals=case.get("approvals",[])
 if len({a.get('authorityId') for a in approvals})<5: errors.append("emergency-quorum-not-met")
 if len({a.get('controlDomainId') for a in approvals})<5: errors.append("approval-control-domains-not-independent")
 shares=case.get("recoveryShares",[])
 if len({s.get('shareId') for s in shares})<3: errors.append("recovery-threshold-not-met")
 if len({s.get('failureDomain') for s in shares})<3: errors.append("recovery-domains-not-independent")
 if case.get("recoveredArtifactSha256")!=BUNDLE: errors.append("recovered-artifact-mismatch")
 channels=case.get("freshChannels",[])
 if len(channels)<2 or any(not c.get("retentionLocked") or not c.get("deletionDenied") or not c.get("restoreExact") for c in channels): errors.append("fresh-channel-evidence-incomplete")
 if case.get("staleAuthorityReplay")!="rejected": errors.append("stale-authority-not-rejected")
 if case.get("e17BlockingRows")!=0: errors.append("e17-matrix-incomplete")
 return {"verified":not errors,"errors":errors}
