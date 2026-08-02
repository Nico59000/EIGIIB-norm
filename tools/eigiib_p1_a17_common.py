from __future__ import annotations
import base64, hashlib, json, pathlib, subprocess, tempfile, urllib.error, urllib.parse, urllib.request
from typing import Any
ROOT=pathlib.Path(__file__).resolve().parents[1]
FIX=ROOT/'tests/fixtures/p1-a17'
A16_COMMIT='020cbfc29aaeccb51606021669b7f381f2ec00f6'
A16_REPORT='da7f10bf5055b4e965792f02bfdf4b4add32767214208ad3d05e095fa67c91f5'
A16_CAPSULE='4e19c204fa557e993d9357cd4e6b1bf7fbd0710ebceaf8aea8f54562cd067406'
EVIDENCE_SHA='ae48cd09b18f5ddad99fb6eb92a5b663fdabc39b541fcb94a7c46c33fdccf825'
RESTORE_SHA='dc51cf8a23fa731b3b7375a36e82d2fd1a530b52cb4711cc3b92d181fd20d13e'
POLICY_SHA='63dc542b090e27dfac33961aaf81b41c95070a3969a117625e0c9d77573cb983'
POLICY_CAPSULE_SHA='5a0e738238cea382b2d1d5c4a94f3c9bc0be085fbe6dfcd4592966895854eb29'
POLICY_SPKI='49894e40b8f9a5bbce08be919e88da6c25d5c1bc29f637936ef8ff22721f6b34'
RELEASE_ID=363675194
RELEASE_NODE='RE_kwDOTpS9_M4VrT46'
RELEASE_TAG='eigiib-p1-a17-recovery-v1'
RELEASE_NAME='EIGIIB P1-A17 recovery replica fixture'
REGISTRY_REPO='nico59000/eigiib-norm-p1-a16'
REGISTRY='ghcr.io/'+REGISTRY_REPO
MANIFEST='sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8'
BOUNDARY='named-ghcr-primary-github-release-recovery-retention-and-single-location-restore-closure'
EXPECTED_DECISIONS={'administrativeDeletionPrevention':'not-claimed','correlatedProviderFailureResistance':'not-claimed','declaredRetentionPolicy':'conformant','durableAvailability':'conformant-for-observed-two-location-policy-bound-restore-window','futureAvailabilityGuarantee':'not-claimed','platformEnforcedRetention':'not-claimed','primaryLocationReadback':'conformant-at-capture-time','providerIndependentReplication':'not-claimed','recoveryLocationReadback':'conformant-at-capture-time','replication':'conformant-for-named-cross-service-two-location-scope','singleLocationRestore':'conformant-for-each-named-location-at-capture-time'}
OBJECTS=[('eigiib-p1-a14-fixed-1.1.archive.txt','sha256:14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682',190,'blob'),('eigiib-p1-a14-fixed-1.1.descriptor.json','sha256:762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1',776,'blob'),('eigiib-p1-a15-live-release-manifest.json','sha256:82e61dcf91be3cac21d93349e22829f27b1bdca057e813e584a1593c5a7d604b',1421,'blob'),('eigiib-p1-a16-oci-config.json','sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',2,'blob'),('eigiib-p1-a16-oci-manifest.json',MANIFEST,1493,'manifest')]
OBJECT_SET_SHA='29811e4cbd30ff12fef18c12c61068f83de8d3c61a2be93ae8faf37f2f11b466'
class ConformanceError(ValueError): pass
def canonical(value:Any)->bytes:return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def load(path:pathlib.Path)->Any:
    try:return json.loads(path.read_bytes(),object_pairs_hook=_pairs)
    except Exception as e:raise ConformanceError(f'invalid JSON {path}: {e}') from e
def _pairs(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise ConformanceError('duplicate JSON key: '+k)
        out[k]=v
    return out
def need(value,msg):
    if not value:raise ConformanceError(msg)
def keys(v,expected,label):need(isinstance(v,dict) and set(v)==set(expected),f'{label} keys mismatch')
def file_sha(name):return sha((FIX/name).read_bytes())
def spki(path):return sha(subprocess.run(['openssl','pkey','-pubin','-in',str(path),'-outform','DER'],check=True,capture_output=True).stdout)
def verify_capsule(name,key_name,standard,payload_standard,expected_spki):
    cap=load(FIX/name); keys(cap,['standard','algorithm','keyId','payload','signature'],'capsule')
    need(cap['standard']==standard and cap['algorithm']=='Ed25519','capsule header mismatch')
    need(cap['keyId']=='sha256:'+expected_spki and spki(FIX/key_name)==expected_spki,'capsule key mismatch')
    try:p=base64.b64decode(cap['payload'],validate=True);s=base64.b64decode(cap['signature'],validate=True)
    except Exception as e:raise ConformanceError('invalid capsule base64') from e
    with tempfile.TemporaryDirectory() as d:
        d=pathlib.Path(d);(d/'p').write_bytes(p);(d/'s').write_bytes(s)
        r=subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(FIX/key_name),'-rawin','-in',str(d/'p'),'-sigfile',str(d/'s')],capture_output=True)
    need(r.returncode==0,'capsule signature invalid'); pay=json.loads(p,object_pairs_hook=_pairs)
    need(canonical(pay)==p and pay['standard']==payload_standard,'capsule payload mismatch');return pay
def expected_objects():return [{'digest':d,'name':n,'size':s} for n,d,s,_ in OBJECTS]
def validate_all():
    need(file_sha('live-durability-evidence.json')==EVIDENCE_SHA,'evidence hash mismatch')
    need(file_sha('restore-manifest.json')==RESTORE_SHA,'restore manifest hash mismatch')
    need(file_sha('retention-policy.json')==POLICY_SHA,'policy hash mismatch')
    need(file_sha('retention-policy-capsule.json')==POLICY_CAPSULE_SHA,'policy capsule hash mismatch')
    ev=load(FIX/'live-durability-evidence.json'); po=load(FIX/'retention-policy.json'); rm=load(FIX/'restore-manifest.json')
    keys(ev,['boundary','capturedAt','decisions','primaryLocation','recoveryLocation','restoreReplay','retentionPolicy','sourceP1A16','standard'],'evidence')
    need(ev['standard']=='EIGIIB-P1-A17' and ev['capturedAt']=='2026-08-02T02:07:24Z' and ev['boundary']==BOUNDARY,'evidence authority mismatch')
    need(ev['sourceP1A16']=={'repository':'Nico59000/EIGIIB-norm','commit':A16_COMMIT,'reportSha256':A16_REPORT,'capsuleSha256':A16_CAPSULE,'registry':REGISTRY,'registryTag':'p1-a16-fixture-v1','manifestDigest':MANIFEST},'source binding mismatch')
    need(ev['decisions']==EXPECTED_DECISIONS,'decision mismatch')
    objs=expected_objects();need(ev['primaryLocation']['protectedObjects']==objs and ev['recoveryLocation']['protectedObjects']==objs,'protected objects mismatch')
    need(ev['primaryLocation']['protectedObjectSetSha256']==OBJECT_SET_SHA and ev['recoveryLocation']['protectedObjectSetSha256']==OBJECT_SET_SHA,'object set hash mismatch')
    rec=ev['recoveryLocation'];need(rec['releaseId']==RELEASE_ID and rec['releaseNodeId']==RELEASE_NODE and rec['tag']==RELEASE_TAG and rec['name']==RELEASE_NAME and rec['tagTargetCommit']==A16_COMMIT and rec['targetCommitish']==A16_COMMIT,'release identity mismatch')
    need(rec['draft'] is False and rec['prerelease'] is True and rec['immutable'] is False,'release state mismatch')
    need(len(rec['assets'])==9 and len({a['name'] for a in rec['assets']})==9,'release asset set mismatch')
    for a in rec['assets']:
        keys(a,['apiDigest','assetId','browserDownloadUrl','name','nodeId','publicDownloadSha256','sha256','size'],'asset')
        need(a['apiDigest']=='sha256:'+a['sha256'] and a['publicDownloadSha256']==a['sha256'],'asset digest mismatch')
        need(a['browserDownloadUrl'].startswith('https://github.com/Nico59000/EIGIIB-norm/releases/download/'+RELEASE_TAG+'/'),'asset URL mismatch')
    need(ev['restoreReplay']=={'crossLocationByteIdentity':'conformant','primaryOnly':{'objectCount':5,'protectedObjectSetSha256':OBJECT_SET_SHA,'result':'conformant'},'recoveryOnly':{'objectCount':5,'protectedObjectSetSha256':OBJECT_SET_SHA,'result':'conformant'}},'restore evidence mismatch')
    keys(po,['boundary','claims','deletionPreconditions','effectiveAt','locations','minimumRetentionDays','policyId','protectedObjectSet','requiredLocationCount','restoreAuditIntervalDays','sourceP1A16','standard'],'policy')
    need(po['standard']=='EIGIIB-P1-A17-RETENTION-POLICY-1.0' and po['policyId']=='eigiib-p1-a17-retention-policy-v1' and po['boundary']==BOUNDARY,'policy identity mismatch')
    need(po['minimumRetentionDays']==90 and po['restoreAuditIntervalDays']==7 and po['requiredLocationCount']==2,'policy thresholds mismatch')
    need(po['claims']=={'administrativeDeletionPrevention':'not-claimed','declaredRetentionPolicy':'conformant','futureAvailabilityGuarantee':'not-claimed','platformEnforcedRetention':'not-claimed','providerIndependentReplication':'not-claimed'},'policy claims mismatch')
    pp=verify_capsule('retention-policy-capsule.json','retention-policy-public-key.pem','EIGIIB-P1-A17-RETENTION-CAPSULE-1.0','EIGIIB-P1-A17-RETENTION-CAPSULE-PAYLOAD-1.0',POLICY_SPKI)
    need(pp['retentionPolicySha256']==POLICY_SHA and pp['sourceP1A16Commit']==A16_COMMIT and pp['boundary']==BOUNDARY,'policy capsule binding mismatch')
    keys(rm,['assets','boundary','protectedObjectSetSha256','protectedObjects','recoveryRelease','retentionPolicy','sourceP1A16','standard'],'restore manifest')
    need(rm['standard']=='EIGIIB-P1-A17-RESTORE-MANIFEST-1.0' and rm['boundary']==BOUNDARY and rm['protectedObjectSetSha256']==OBJECT_SET_SHA,'restore manifest identity mismatch')
    need(sorted(rm['protectedObjects'],key=lambda x:x['name'])==objs,'restore protected objects mismatch')
    need(rm['recoveryRelease']['releaseId']==RELEASE_ID and rm['recoveryRelease']['tag']==RELEASE_TAG and rm['recoveryRelease']['targetCommitish']==A16_COMMIT,'restore release mismatch')
    final_spki=spki(FIX/'evidence-registrar-public-key.pem'); fp=verify_capsule('capsule.json','evidence-registrar-public-key.pem','EIGIIB-P1-A17-CAPSULE-1.0','EIGIIB-P1-A17-CAPSULE-PAYLOAD-1.0',final_spki)
    need(fp['sequence']==62 and fp['evidenceSha256']==EVIDENCE_SHA and fp['restoreManifestSha256']==RESTORE_SHA and fp['retentionPolicySha256']==POLICY_SHA and fp['recoveryReleaseId']==RELEASE_ID and fp['protectedObjectSetSha256']==OBJECT_SET_SHA and fp['boundary']==BOUNDARY,'final capsule binding mismatch')
    return ev,po,rm,final_spki
def portable_result():
    ev,_,_,_=validate_all()
    return {'standard':'EIGIIB-P1-A17-PORTABLE-RESULT-1.0','sourceP1A16':ev['sourceP1A16'],'retentionPolicy':ev['retentionPolicy'],'primaryLocator':ev['primaryLocation']['locator'],'recoveryRepository':ev['recoveryLocation']['repository'],'recoveryReleaseId':RELEASE_ID,'recoveryReleaseTag':RELEASE_TAG,'recoveryReleaseTargetCommit':A16_COMMIT,'protectedObjects':expected_objects(),'protectedObjectSetSha256':OBJECT_SET_SHA,'restoreManifestSha256':RESTORE_SHA,'decisions':EXPECTED_DECISIONS,'boundary':BOUNDARY}
def report():
    _,_,_,fspki=validate_all()
    return {'standard':'EIGIIB-P1-A17-REPORT-1.0','sourceP1A16Commit':A16_COMMIT,'sourceP1A16ReportSha256':A16_REPORT,'sourceP1A16CapsuleSha256':A16_CAPSULE,'evidenceSha256':EVIDENCE_SHA,'restoreManifestSha256':RESTORE_SHA,'retentionPolicySha256':POLICY_SHA,'retentionPolicyCapsuleSha256':POLICY_CAPSULE_SHA,'capsuleSha256':file_sha('capsule.json'),'evidenceRegistrarSpkiSha256':fspki,'portable':portable_result(),'overallResult':'conformant'}
def request(url,headers=None):
    req=urllib.request.Request(url,headers={'User-Agent':'eigiib-p1-a17/1.0',**(headers or {})})
    try:
        with urllib.request.urlopen(req,timeout=90) as r:return r.status,r.read(),dict(r.headers)
    except urllib.error.HTTPError as e:return e.code,e.read(),dict(e.headers)
def token():
    q=urllib.parse.urlencode({'service':'ghcr.io','scope':f'repository:{REGISTRY_REPO}:pull'});s,b,_=request('https://ghcr.io/token?'+q);need(s==200,'token request failed');v=json.loads(b);return v.get('token') or v.get('access_token')
def live_primary():
    t=token(); observed=[]
    for n,d,size,kind in OBJECTS:
        path=('manifests/' if kind=='manifest' else 'blobs/')+d; accept='application/vnd.oci.image.manifest.v1+json' if kind=='manifest' else 'application/octet-stream'
        s,b,_=request(f'https://ghcr.io/v2/{REGISTRY_REPO}/{path}',{'Authorization':'Bearer '+t,'Accept':accept});need(s==200 and len(b)==size and 'sha256:'+sha(b)==d,'primary live mismatch: '+n);observed.append({'name':n,'digest':d,'size':size})
    return observed
def live_recovery():
    s,b,_=request(f'https://api.github.com/repos/Nico59000/EIGIIB-norm/releases/tags/{RELEASE_TAG}');need(s==200,'release API failed');r=json.loads(b);need(r['id']==RELEASE_ID and not r['draft'] and r['prerelease'],'release live state mismatch')
    assets={a['name']:a for a in r['assets']}; observed=[]
    for n,d,size,_ in OBJECTS:
        need(n in assets,'recovery asset missing: '+n);s,b,_=request(assets[n]['browser_download_url'],{'Accept':'application/octet-stream'});need(s==200 and len(b)==size and 'sha256:'+sha(b)==d,'recovery live mismatch: '+n);observed.append({'name':n,'digest':d,'size':size})
    return observed
def route(name,observed):return {'standard':'EIGIIB-P1-A17-ROUTE-RESULT-1.0','route':name,'observed':observed,'portable':portable_result()}
