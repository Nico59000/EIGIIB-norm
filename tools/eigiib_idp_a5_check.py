#!/usr/bin/env python3
from __future__ import annotations
import argparse, base64, hashlib, json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STANDARD='EIGIIB-IDP-A5-SELECTIVE-TRANSPARENCY-FREEZE-1.0'
SOURCE_HEAD='58a103c2fa11b32380c0d7a8bb03d29017242d29'
EST={
 'independent-review-of-exact-public-projection',
 'two-of-three-multi-authority-release-approval',
 'exact-public-projection-replay',
 'append-only-final-selective-transparency-freeze',
}
LIM={
 'production-reviewer-identity-or-key-custody',
 'publication-of-any-real-restricted-artifact',
 'public-opening-of-opaque-commitments',
 'universal-confidentiality-or-unlinkability',
 'authorization-to-publish-any-projection-not-bound-to-this-release',
}

def canon(x:Any)->bytes:
    return json.dumps(x,sort_keys=True,separators=(',',':')).encode()

def strict(path:Path)->dict[str,Any]:
    def hook(pairs):
        d={}
        for k,v in pairs:
            if k in d: raise ValueError(f'duplicate JSON member: {k}')
            d[k]=v
        return d
    x=json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=hook)
    if not isinstance(x,dict): raise ValueError('root must be object')
    return x

def instant(v:str)->datetime:
    if not isinstance(v,str) or not v.endswith('Z'): raise ValueError('timestamp must be RFC3339 UTC Z')
    dt=datetime.fromisoformat(v[:-1]+'+00:00')
    if dt.tzinfo != timezone.utc: raise ValueError('timestamp must be UTC')
    return dt

def verify_sig(pub_b64:str,payload:dict[str,Any],sig_b64:str):
    try:
        pub=base64.b64decode(pub_b64,validate=True); sig=base64.b64decode(sig_b64,validate=True)
        if len(pub)!=32 or len(sig)!=64: raise ValueError('invalid Ed25519 encoding width')
        Ed25519PublicKey.from_public_bytes(pub).verify(sig,canon(payload))
    except Exception as exc:
        raise ValueError('invalid Ed25519 signature') from exc

def evaluate(authority:dict[str,Any],projection_bytes:bytes)->list[str]:
    f=[]
    try:
        if authority.get('standard')!=STANDARD: raise ValueError('wrong standard')
        source=authority.get('source'); policy=authority.get('reviewPolicy')
        if not isinstance(source,dict) or set(source)!={'a4Head','a4ProjectionSha256'}: raise ValueError('source boundary invalid')
        pd=hashlib.sha256(projection_bytes).hexdigest()
        if source['a4Head']!=SOURCE_HEAD or source['a4ProjectionSha256']!=pd: raise ValueError('projection source digest mismatch')
        if policy!={'threshold':2,'authorityCount':3,'distinctControlDomains':True,'releaseRequiresThresholdSignatures':True}: raise ValueError('review policy mismatch')
        profiles=authority.get('authorityProfiles')
        if not isinstance(profiles,list) or len(profiles)!=3: raise ValueError('authority profile count mismatch')
        byid={}; domains=set(); roots=set(); keys=set()
        expected_profile={'authorityId','role','controlDomainId','identityRoot','keyId','algorithm','publicKey'}
        for p in profiles:
            if not isinstance(p,dict) or set(p)!=expected_profile: raise ValueError('authority profile not closed')
            aid=p['authorityId']
            if aid in byid: raise ValueError('duplicate authority id')
            if p['role']!='independent-disclosure-reviewer' or p['algorithm']!='ed25519': raise ValueError('authority role or algorithm mismatch')
            if p['controlDomainId'] in domains or p['identityRoot'] in roots or p['keyId'] in keys: raise ValueError('authority independence violation')
            domains.add(p['controlDomainId']); roots.add(p['identityRoot']); keys.add(p['keyId']); byid[aid]=p
        reviews=authority.get('reviews')
        if not isinstance(reviews,list): raise ValueError('reviews malformed')
        approved={}; review_ids=set(); reviewed_times=[]
        for env in reviews:
            if not isinstance(env,dict) or set(env)!={'payload','signature'}: raise ValueError('review envelope not closed')
            p=env['payload']
            if set(p)!={'reviewId','authorityId','projectionDigest','sourceA4Head','decision','reviewedAt','boundary'}: raise ValueError('review payload not closed')
            if p['reviewId'] in review_ids: raise ValueError('duplicate review id')
            review_ids.add(p['reviewId'])
            aid=p['authorityId']
            if aid not in byid: raise ValueError('unknown review authority')
            if p['projectionDigest']!=pd or p['sourceA4Head']!=SOURCE_HEAD: raise ValueError('review projection binding mismatch')
            if p['boundary']!='public-projection-only-no-private-opening': raise ValueError('review boundary mismatch')
            rt=instant(p['reviewedAt']); reviewed_times.append(rt)
            verify_sig(byid[aid]['publicKey'],p,env['signature'])
            if p['decision']=='approve':
                if aid in approved: raise ValueError('authority approved more than once')
                approved[aid]=p['reviewId']
            elif p['decision']!='reject': raise ValueError('unknown review decision')
        if len(approved)<policy['threshold']: raise ValueError('review threshold not met')
        release=authority.get('release')
        if not isinstance(release,dict) or set(release)!={'payload','signatures'}: raise ValueError('release envelope not closed')
        rp=release['payload']
        if set(rp)!={'releaseId','projectionDigest','sourceA4Head','approvalReviewIds','threshold','approvedAt','decision'}: raise ValueError('release payload not closed')
        if rp['projectionDigest']!=pd or rp['sourceA4Head']!=SOURCE_HEAD or rp['threshold']!=2 or rp['decision']!='approved-for-declared-public-projection': raise ValueError('release payload mismatch')
        if len(rp['approvalReviewIds'])!=2 or set(rp['approvalReviewIds'])-set(approved.values()): raise ValueError('release approval set mismatch')
        approved_at=instant(rp['approvedAt'])
        if reviewed_times and approved_at < max(reviewed_times): raise ValueError('release precedes review')
        sigs=release['signatures']
        if not isinstance(sigs,list): raise ValueError('release signatures malformed')
        release_signers=set()
        for s in sigs:
            if not isinstance(s,dict) or set(s)!={'authorityId','signature'}: raise ValueError('release signature entry not closed')
            aid=s['authorityId']
            if aid in release_signers: raise ValueError('duplicate release signer')
            if aid not in approved: raise ValueError('release signer lacks approving review')
            verify_sig(byid[aid]['publicKey'],rp,s['signature']); release_signers.add(aid)
        if len(release_signers)<2: raise ValueError('release signature threshold not met')
        aps=hashlib.sha256(canon({'reviews':reviews,'releasePayload':rp,'releaseSignatures':sigs})).hexdigest()
        freeze=authority.get('freeze')
        if not isinstance(freeze,dict) or set(freeze)!={'payload','freezeDigest'}: raise ValueError('freeze envelope not closed')
        fp=freeze['payload']
        if set(fp)!={'freezeId','releaseId','projectionDigest','approvalSetDigest','frozenAt','state','successorPolicy'}: raise ValueError('freeze payload not closed')
        if fp['releaseId']!=rp['releaseId'] or fp['projectionDigest']!=pd or fp['approvalSetDigest']!=aps: raise ValueError('freeze binding mismatch')
        if fp['state']!='frozen' or fp['successorPolicy']!='append-only-supersession-required': raise ValueError('freeze policy mismatch')
        if instant(fp['frozenAt']) < approved_at: raise ValueError('freeze precedes release')
        if freeze['freezeDigest']!=hashlib.sha256(canon(fp)).hexdigest(): raise ValueError('freeze digest mismatch')
        cb=authority.get('claimBoundary')
        if not isinstance(cb,dict) or set(cb)!={'establishes','doesNotImply'} or set(cb['establishes'])!=EST or set(cb['doesNotImply'])!=LIM: raise ValueError('claim boundary mismatch')
    except (KeyError,TypeError,ValueError) as exc:
        f.append(str(exc))
    return f

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--authority',type=Path,required=True); ap.add_argument('--projection',type=Path,required=True); ap.add_argument('--json',action='store_true'); args=ap.parse_args()
    try: findings=evaluate(strict(args.authority),args.projection.read_bytes())
    except Exception as exc: findings=[str(exc)]
    out={'standard':STANDARD,'result':'conformant' if not findings else 'nonconformant','findings':findings,'tool':'eigiib-idp-a5-check'}
    print(json.dumps(out,sort_keys=True,separators=(',',':')) if args.json else out['result'])
    return 0 if not findings else 2
if __name__=='__main__': raise SystemExit(main())
