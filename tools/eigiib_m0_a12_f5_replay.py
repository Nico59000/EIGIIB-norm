#!/usr/bin/env python3
REQUIRED_BOUNDED={'universal-interoperability','future-unregistered-runner-compatibility'}
def verify_case(case):
 errors=[]
 if case.get('f4Decision')!='verified': errors.append('f4-not-T')
 if len(set(case.get('capabilityEvidenceDigests',[])))!=12: errors.append('adoptable-evidence-incomplete')
 if set(case.get('boundedClaims',[]))!=REQUIRED_BOUNDED: errors.append('bounded-claims-missing')
 approvals=case.get('collegeApprovals',[])
 if len({a.get('collegeId') for a in approvals})!=3: errors.append('college-convergence-incomplete')
 if any(len(set(a.get('approvers',[])))<4 for a in approvals): errors.append('college-threshold-not-met')
 if any(len(set(a.get('controlDomains',[])))<4 for a in approvals): errors.append('college-control-domains-not-independent')
 if not case.get('identicalRecordDigest'): errors.append('college-record-divergence')
 if not case.get('freshEvidence'): errors.append('stale-external-evidence')
 if not case.get('adoptionCertificateValid'): errors.append('adoption-certificate-invalid')
 if not case.get('freezeManifestValid'): errors.append('freeze-manifest-invalid')
 if not case.get('independentFreezeReadbackValid'): errors.append('freeze-readback-invalid')
 return {'verified':not errors,'errors':errors}
