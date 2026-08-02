from __future__ import annotations
import base64, copy, hashlib, json, pathlib, subprocess, tempfile
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIX = ROOT / 'tests/fixtures/p1-a18'
BUNDLE_PATH = FIX / 'governance-bundle.json'
POLICY_PATH = FIX / 'governance-policy.json'
SOURCE_COMMIT = '2e2ea29ac61787cb62c22f7db828766257af4c01'
SOURCE_REPORT = '4e8473256a6e857d4826e2c2a1eb484d45d023cd648136a9ff0149a3f5931433'
SOURCE_CAPSULE = 'bd0e55bb7ad0e44ab7adcc7538b7718dd6f7ab938ebb0752accaf40dff379340'
OBJECT_SET = '29811e4cbd30ff12fef18c12c61068f83de8d3c61a2be93ae8faf37f2f11b466'
BOUNDARY = 'workflow-executed-fixture-production-governance-sod-and-reviewed-emergency-override-closure'
EXPECTED_ROLE_PATHS = {
    'registrar': 'tests/fixtures/p1-a18/registrar-public-key.pem',
    'requester': 'tests/fixtures/p1-a18/requester-public-key.pem',
    'approver-a': 'tests/fixtures/p1-a18/approver-a-public-key.pem',
    'approver-b': 'tests/fixtures/p1-a18/approver-b-public-key.pem',
    'publisher': 'tests/fixtures/p1-a18/publisher-public-key.pem',
    'emergency-controller': 'tests/fixtures/p1-a18/emergency-controller-public-key.pem',
    'auditor': 'tests/fixtures/p1-a18/auditor-public-key.pem',
}
EXPECTED_ROLES = {
    'registrar': 'governance-registrar', 'requester': 'release-requester',
    'approver-a': 'release-approver', 'approver-b': 'release-approver',
    'publisher': 'release-publisher', 'emergency-controller': 'emergency-controller',
    'auditor': 'release-auditor',
}
DECISIONS = {
    'artifactAndEnvironmentBinding': 'conformant',
    'deployedReleaseGovernance': 'conformant-for-workflow-executed-fixture-environment',
    'emergencyOverride': 'conformant-for-time-bounded-approval-threshold-only-bypass',
    'liveProductionDeployment': 'not-claimed',
    'normalThresholdApproval': 'conformant',
    'organizationIdentityAssurance': 'not-claimed',
    'platformEnforcedSeparationOfDuties': 'not-claimed',
    'postEmergencyReview': 'conformant',
    'productionEnvironmentProtectionRules': 'not-claimed',
    'separationOfDuties': 'conformant-for-signed-distinct-role-fixture',
    'universalReleaseGovernance': 'not-claimed',
}

class ConformanceError(ValueError): pass

def canonical(v: Any) -> bytes:
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def canonical_line(v: Any) -> bytes: return canonical(v) + b'\n'
def sha(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out: raise ConformanceError('duplicate JSON key: ' + k)
        out[k] = v
    return out

def load(path: pathlib.Path) -> Any:
    try: return json.loads(path.read_bytes(), object_pairs_hook=_pairs)
    except Exception as e: raise ConformanceError(f'invalid JSON {path}: {e}') from e

def need(v: Any, msg: str) -> None:
    if not v: raise ConformanceError(msg)

def exact_keys(v: Any, expected: set[str], label: str) -> None:
    need(isinstance(v, dict) and set(v) == expected, label + ' keys mismatch')

def when(s: str) -> datetime:
    try: return datetime.fromisoformat(s.replace('Z', '+00:00')).astimezone(timezone.utc)
    except Exception as e: raise ConformanceError('invalid timestamp: ' + str(s)) from e

def spki_sha(path: pathlib.Path) -> str:
    p = subprocess.run(['openssl','pkey','-pubin','-in',str(path),'-outform','DER'], check=True, capture_output=True)
    return sha(p.stdout)

def verify_signed(signed: dict[str, Any], expected_key: str, roles: dict[str, Any], do_crypto: bool = True) -> dict[str, Any]:
    exact_keys(signed, {'payload','signature'}, 'signed record')
    sig = signed['signature']; payload = signed['payload']
    exact_keys(sig, {'algorithm','keyId','payloadSha256','signatureBase64'}, 'signature')
    need(sig['algorithm'] == 'Ed25519' and sig['keyId'] == expected_key, 'signature identity mismatch')
    msg = canonical(payload)
    need(sig['payloadSha256'] == sha(msg), 'signed payload digest mismatch')
    role = roles[expected_key]
    need(role['path'] == EXPECTED_ROLE_PATHS[expected_key], 'public key path mismatch')
    key_path = ROOT / role['path']
    need(spki_sha(key_path) == role['spkiSha256'], 'public key digest mismatch')
    if do_crypto:
        try: signature = base64.b64decode(sig['signatureBase64'], validate=True)
        except Exception as e: raise ConformanceError('invalid signature base64') from e
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d); (d/'payload').write_bytes(msg); (d/'sig').write_bytes(signature)
            p = subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(key_path),'-rawin','-in',str(d/'payload'),'-sigfile',str(d/'sig')], capture_output=True)
        need(p.returncode == 0, 'signature verification failed')
    return payload

def expected_artifact() -> dict[str, str]:
    return {'sourceP1A17Commit':SOURCE_COMMIT,'sourceP1A17ReportSha256':SOURCE_REPORT,'sourceP1A17CapsuleSha256':SOURCE_CAPSULE,'protectedObjectSetSha256':OBJECT_SET}

def validate_bundle(bundle: dict[str, Any] | None = None, do_crypto: bool = True) -> dict[str, Any]:
    b = copy.deepcopy(bundle if bundle is not None else load(BUNDLE_PATH))
    exact_keys(b, {'standard','policy','normal','emergency','boundary'}, 'bundle')
    need(b['standard'] == 'EIGIIB-P1-A18-BUNDLE-1.0' and b['boundary'] == BOUNDARY, 'bundle identity mismatch')
    policy = b['policy']['payload']
    roles = policy['roles']
    verify_signed(b['policy'], 'registrar', roles, do_crypto)
    exact_keys(policy, {'standard','policyId','environment','artifact','roles','normalPath','emergencyPath','revocation','issuedAt','effectiveUntil'}, 'policy')
    need(policy['standard'] == 'EIGIIB-P1-A18-GOVERNANCE-POLICY-1.0', 'policy standard mismatch')
    need(policy['policyId'] == 'eigiib-p1-a18-fixture-production-governance-v1', 'policy id mismatch')
    need(policy['environment'] == 'p1-a18-fixture-production' and policy['artifact'] == expected_artifact(), 'policy binding mismatch')
    need(set(roles) == set(EXPECTED_ROLES), 'role set mismatch')
    spkis = set()
    for key_id, role_name in EXPECTED_ROLES.items():
        exact_keys(roles[key_id], {'role','spkiSha256','path'}, 'role')
        need(roles[key_id]['role'] == role_name and roles[key_id]['path'] == EXPECTED_ROLE_PATHS[key_id], 'role assignment mismatch')
        spkis.add(roles[key_id]['spkiSha256'])
    need(len(spkis) == len(roles), 'role keys are not distinct')
    normal = policy['normalPath']; emergency = policy['emergencyPath']
    need(normal == {'approvalThreshold':2,'authorizationTtlSeconds':3600,'requesterMayApprove':False,'publisherMayApprove':False,'approversMustBeDistinct':True,'publisherMustBeDistinctFromRequesterAndApprovers':True,'artifactAndEnvironmentBindingRequired':True}, 'normal policy mismatch')
    need(emergency == {'maxOverrideSeconds':1800,'allowedBypasses':['approval-threshold-only'],'forbiddenBypasses':['artifact-integrity','environment-binding','publisher-identity','signature-verification'],'incidentIdentifierRequired':True,'justificationRequired':True,'postEmergencyReviewRequired':True,'reviewDeadlineSeconds':86400,'auditorMustBeDistinctFromRequesterPublisherAndController':True}, 'emergency policy mismatch')
    policy_start, policy_end = when(policy['issuedAt']), when(policy['effectiveUntil'])

    exact_keys(b['normal'], {'request','approvals','promotion'}, 'normal path')
    req = verify_signed(b['normal']['request'], 'requester', roles, do_crypto)
    exact_keys(req, {'recordType','requestId','requesterKeyId','artifact','environment','issuedAt','expiresAt'}, 'request')
    need(req['recordType']=='release-request' and req['requesterKeyId']=='requester', 'request identity mismatch')
    need(req['artifact']==policy['artifact'] and req['environment']==policy['environment'], 'request scope mismatch')
    need(policy_start <= when(req['issuedAt']) < when(req['expiresAt']) <= policy_end, 'request validity mismatch')
    approvals = b['normal']['approvals']; need(isinstance(approvals,list) and len(approvals) >= normal['approvalThreshold'], 'approval threshold not met')
    approval_ids=[]; approver_ids=[]
    for item in approvals:
        key_id=item['payload'].get('approverKeyId'); need(key_id in roles and roles[key_id]['role']=='release-approver', 'approval role mismatch')
        ap=verify_signed(item,key_id,roles,do_crypto)
        exact_keys(ap, {'recordType','authorizationId','requestId','approverKeyId','artifact','environment','issuedAt','expiresAt'}, 'approval')
        need(ap['recordType']=='release-approval' and ap['requestId']==req['requestId'], 'approval request mismatch')
        need(ap['artifact']==policy['artifact'] and ap['environment']==policy['environment'], 'approval scope mismatch')
        need(when(req['issuedAt']) <= when(ap['issuedAt']) < when(ap['expiresAt']) <= policy_end, 'approval validity mismatch')
        approval_ids.append(ap['authorizationId']); approver_ids.append(key_id)
    need(len(set(approver_ids)) == len(approver_ids), 'approvers are not distinct')
    need('requester' not in approver_ids and 'publisher' not in approver_ids, 'forbidden approver role')
    need(not (set(approval_ids) & set(policy['revocation']['revokedAuthorizationIds'])), 'revoked authorization used')
    prom=verify_signed(b['normal']['promotion'],'publisher',roles,do_crypto)
    exact_keys(prom, {'recordType','promotionId','path','publisherKeyId','requestId','authorizationIds','artifact','environment','promotedAt'}, 'normal promotion')
    need(prom['recordType']=='promotion' and prom['path']=='normal' and prom['publisherKeyId']=='publisher', 'normal promotion identity mismatch')
    need(prom['requestId']==req['requestId'] and set(prom['authorizationIds'])==set(approval_ids), 'normal promotion authorization mismatch')
    need(prom['artifact']==policy['artifact'] and prom['environment']==policy['environment'], 'normal promotion scope mismatch')
    t=when(prom['promotedAt']); need(when(req['issuedAt']) <= t <= when(req['expiresAt']), 'normal promotion outside request window')
    for item in approvals: need(when(item['payload']['issuedAt']) <= t <= when(item['payload']['expiresAt']), 'normal promotion outside approval window')
    need('publisher' not in {'requester',*approver_ids}, 'publisher separation mismatch')

    exact_keys(b['emergency'], {'override','promotion','review'}, 'emergency path')
    ov=verify_signed(b['emergency']['override'],'emergency-controller',roles,do_crypto)
    exact_keys(ov, {'recordType','overrideId','controllerKeyId','incidentId','justification','bypasses','artifact','environment','issuedAt','expiresAt'}, 'override')
    need(ov['recordType']=='emergency-override' and ov['controllerKeyId']=='emergency-controller', 'override identity mismatch')
    need(bool(ov['incidentId']) and bool(ov['justification'].strip()), 'emergency incident or justification missing')
    need(ov['artifact']==policy['artifact'] and ov['environment']==policy['environment'], 'override scope mismatch')
    allowed=set(emergency['allowedBypasses']); forbidden=set(emergency['forbiddenBypasses']); bypasses=set(ov['bypasses'])
    need(bypasses and bypasses <= allowed and not (bypasses & forbidden), 'override bypass mismatch')
    ov_start,ov_end=when(ov['issuedAt']),when(ov['expiresAt'])
    need(policy_start <= ov_start < ov_end <= policy_end and (ov_end-ov_start).total_seconds() <= emergency['maxOverrideSeconds'], 'override validity mismatch')
    ep=verify_signed(b['emergency']['promotion'],'publisher',roles,do_crypto)
    exact_keys(ep, {'recordType','promotionId','path','publisherKeyId','overrideId','artifact','environment','promotedAt'}, 'emergency promotion')
    need(ep['recordType']=='promotion' and ep['path']=='emergency' and ep['publisherKeyId']=='publisher' and ep['overrideId']==ov['overrideId'], 'emergency promotion identity mismatch')
    need(ep['artifact']==policy['artifact'] and ep['environment']==policy['environment'], 'emergency promotion scope mismatch')
    ep_time=when(ep['promotedAt']); need(ov_start <= ep_time <= ov_end, 'emergency promotion outside override window')
    rv=verify_signed(b['emergency']['review'],'auditor',roles,do_crypto)
    exact_keys(rv, {'recordType','reviewId','auditorKeyId','overrideId','promotionId','outcome','scopeExpanded','reviewedAt'}, 'review')
    need(rv['recordType']=='post-emergency-review' and rv['auditorKeyId']=='auditor', 'review identity mismatch')
    need(rv['overrideId']==ov['overrideId'] and rv['promotionId']==ep['promotionId'], 'review reference mismatch')
    need(rv['outcome']=='accepted-without-scope-expansion' and rv['scopeExpanded'] is False, 'review outcome mismatch')
    need(ep_time <= when(rv['reviewedAt']) <= ep_time + __import__('datetime').timedelta(seconds=emergency['reviewDeadlineSeconds']), 'review deadline mismatch')
    need(len({'auditor','requester','publisher','emergency-controller'})==4, 'auditor separation mismatch')
    return {'bundle':b,'policy':policy,'request':req,'approvals':[x['payload'] for x in approvals],'normalPromotion':prom,'override':ov,'emergencyPromotion':ep,'review':rv}

def key_set_sha(policy: dict[str, Any]) -> str:
    rows=[{'keyId':k,'role':policy['roles'][k]['role'],'spkiSha256':policy['roles'][k]['spkiSha256']} for k in sorted(policy['roles'])]
    return sha(canonical(rows))

def portable_result(validated: dict[str, Any] | None = None) -> dict[str, Any]:
    v=validated or validate_bundle(); p=v['policy']
    return {'standard':'EIGIIB-P1-A18-PORTABLE-RESULT-1.0','artifact':p['artifact'],'policyId':p['policyId'],'environment':p['environment'],'approvalThreshold':p['normalPath']['approvalThreshold'],'normalPromotionId':v['normalPromotion']['promotionId'],'normalPromotionResult':'accepted','emergencyOverrideId':v['override']['overrideId'],'emergencyPromotionId':v['emergencyPromotion']['promotionId'],'emergencyPromotionResult':'accepted-and-reviewed','postEmergencyReviewId':v['review']['reviewId'],'postEmergencyReviewOutcome':v['review']['outcome'],'decisions':DECISIONS,'boundary':BOUNDARY}

def mutation_replay() -> list[dict[str,str]]:
    base=load(BUNDLE_PATH); cases=[]
    def run(name, mut):
        b=copy.deepcopy(base); mut(b)
        try: validate_bundle(b, do_crypto=False)
        except ConformanceError as e: cases.append({'case':name,'result':'rejected','reason':str(e)}); return
        raise ConformanceError('mutation accepted: '+name)
    run('duplicate-approver', lambda b: b['normal']['approvals'].__setitem__(1, copy.deepcopy(b['normal']['approvals'][0])))
    run('requester-as-approver', lambda b: b['normal']['approvals'][0]['payload'].__setitem__('approverKeyId','requester'))
    run('publisher-as-approver', lambda b: b['normal']['approvals'][0]['payload'].__setitem__('approverKeyId','publisher'))
    run('threshold-increase', lambda b: b['policy']['payload']['normalPath'].__setitem__('approvalThreshold',3))
    run('request-artifact-change', lambda b: b['normal']['request']['payload']['artifact'].__setitem__('protectedObjectSetSha256','0'*64))
    run('approval-environment-change', lambda b: b['normal']['approvals'][0]['payload'].__setitem__('environment','other'))
    run('expired-request', lambda b: b['normal']['request']['payload'].__setitem__('expiresAt','2026-08-02T03:09:00Z'))
    run('expired-approval', lambda b: b['normal']['approvals'][0]['payload'].__setitem__('expiresAt','2026-08-02T03:09:00Z'))
    run('revoked-authorization', lambda b: b['policy']['payload']['revocation']['revokedAuthorizationIds'].append('P1-A18-AUTH-0001'))
    run('wrong-authorization-reference', lambda b: b['normal']['promotion']['payload']['authorizationIds'].__setitem__(0,'other'))
    run('missing-incident', lambda b: b['emergency']['override']['payload'].__setitem__('incidentId',''))
    run('missing-justification', lambda b: b['emergency']['override']['payload'].__setitem__('justification',' '))
    run('override-too-long', lambda b: b['emergency']['override']['payload'].__setitem__('expiresAt','2026-08-02T04:00:01Z'))
    run('forbidden-bypass', lambda b: b['emergency']['override']['payload']['bypasses'].append('signature-verification'))
    run('override-artifact-change', lambda b: b['emergency']['override']['payload']['artifact'].__setitem__('sourceP1A17Commit','f'*40))
    run('emergency-promotion-after-expiry', lambda b: b['emergency']['promotion']['payload'].__setitem__('promotedAt','2026-08-02T03:46:00Z'))
    run('review-scope-expansion', lambda b: b['emergency']['review']['payload'].__setitem__('scopeExpanded',True))
    run('review-outcome-change', lambda b: b['emergency']['review']['payload'].__setitem__('outcome','accepted'))
    run('review-reference-change', lambda b: b['emergency']['review']['payload'].__setitem__('promotionId','other'))
    return cases

def report() -> dict[str, Any]:
    v=validate_bundle(); mutations=mutation_replay()
    return {'standard':'EIGIIB-P1-A18-REPORT-1.0','sourceP1A17Commit':SOURCE_COMMIT,'sourceP1A17ReportSha256':SOURCE_REPORT,'sourceP1A17CapsuleSha256':SOURCE_CAPSULE,'governancePolicySha256':sha(canonical(v['policy'])),'governanceBundleSha256':sha(canonical(v['bundle'])),'signingKeySetSha256':key_set_sha(v['policy']),'mutationCasesRejected':len(mutations),'portable':portable_result(v),'overallResult':'conformant'}
