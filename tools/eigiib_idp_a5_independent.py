#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,hashlib,json
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
STD='EIGIIB-IDP-A5-SELECTIVE-TRANSPARENCY-FREEZE-1.0'; HEAD='58a103c2fa11b32380c0d7a8bb03d29017242d29'
def j(x): return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def z(s):
    if not isinstance(s,str) or not s.endswith('Z'): raise ValueError('non-Z time')
    return datetime.fromisoformat(s[:-1]+'+00:00')
def sig(pk,p,s): Ed25519PublicKey.from_public_bytes(base64.b64decode(pk,validate=True)).verify(base64.b64decode(s,validate=True),j(p))
def check(a,pb):
    try:
        d=hashlib.sha256(pb).hexdigest(); assert a['standard']==STD; assert a['source']=={'a4Head':HEAD,'a4ProjectionSha256':d}
        pol=a['reviewPolicy']; assert (pol['threshold'],pol['authorityCount'],pol['distinctControlDomains'],pol['releaseRequiresThresholdSignatures'])==(2,3,True,True)
        ps=a['authorityProfiles']; assert len(ps)==3
        ids={x['authorityId']:x for x in ps}; assert len(ids)==3 and len({x['controlDomainId'] for x in ps})==3 and len({x['identityRoot'] for x in ps})==3
        ok={}; times=[]
        for e in a['reviews']:
            p=e['payload']; assert p['authorityId'] in ids and p['projectionDigest']==d and p['sourceA4Head']==HEAD and p['boundary']=='public-projection-only-no-private-opening'; sig(ids[p['authorityId']]['publicKey'],p,e['signature']); times.append(z(p['reviewedAt']))
            if p['decision']=='approve': ok[p['authorityId']]=p['reviewId']
        assert len(ok)>=2
        rp=a['release']['payload']; assert rp['projectionDigest']==d and rp['sourceA4Head']==HEAD and rp['threshold']==2 and set(rp['approvalReviewIds']).issubset(set(ok.values())) and len(rp['approvalReviewIds'])==2 and z(rp['approvedAt'])>=max(times)
        rs=set()
        for s in a['release']['signatures']:
            assert s['authorityId'] in ok and s['authorityId'] not in rs; sig(ids[s['authorityId']]['publicKey'],rp,s['signature']); rs.add(s['authorityId'])
        assert len(rs)>=2
        ad=hashlib.sha256(j({'reviews':a['reviews'],'releasePayload':rp,'releaseSignatures':a['release']['signatures']})).hexdigest()
        fp=a['freeze']['payload']; assert fp['releaseId']==rp['releaseId'] and fp['projectionDigest']==d and fp['approvalSetDigest']==ad and fp['state']=='frozen' and fp['successorPolicy']=='append-only-supersession-required' and z(fp['frozenAt'])>=z(rp['approvedAt'])
        assert a['freeze']['freezeDigest']==hashlib.sha256(j(fp)).hexdigest()
        return []
    except Exception as e: return [f'independent rejection: {type(e).__name__}']
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--authority',type=Path,required=True); ap.add_argument('--projection',type=Path,required=True); ap.add_argument('--json',action='store_true'); x=ap.parse_args(); a=json.loads(x.authority.read_text()); f=check(a,x.projection.read_bytes()); out={'standard':STD,'result':'conformant' if not f else 'nonconformant','findings':f,'tool':'eigiib-idp-a5-independent'}; print(json.dumps(out,sort_keys=True,separators=(',',':')) if x.json else out['result']); return 0 if not f else 2
if __name__=='__main__': raise SystemExit(main())
