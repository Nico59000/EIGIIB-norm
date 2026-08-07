#!/usr/bin/env python3
from __future__ import annotations
import argparse,copy,json,tempfile
from pathlib import Path
import importlib.util
ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
    s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
A=load(ROOT/'tools/eigiib_idp_a5_check.py','a5a'); B=load(ROOT/'tools/eigiib_idp_a5_independent.py','a5b')
BASE=json.loads((ROOT/'conformance/idp-a5-release-authority.json').read_text()); PB=(ROOT/'conformance/idp-a5-public-projection.json').read_bytes()
def reject(mut,pb=PB):
    x=copy.deepcopy(BASE); mut(x)
    return bool(A.evaluate(x,pb)) and bool(B.check(x,pb))
def main():
    cases=[]
    cases.append(('positive',not A.evaluate(BASE,PB) and not B.check(BASE,PB)))
    muts=[
      ('wrong-source-head',lambda x:x['source'].__setitem__('a4Head','0'*40)),
      ('wrong-projection-digest',lambda x:x['source'].__setitem__('a4ProjectionSha256','0'*64)),
      ('threshold-weakened',lambda x:x['reviewPolicy'].__setitem__('threshold',1)),
      ('duplicate-control-domain',lambda x:x['authorityProfiles'][1].__setitem__('controlDomainId',x['authorityProfiles'][0]['controlDomainId'])),
      ('review-projection-mismatch',lambda x:x['reviews'][0]['payload'].__setitem__('projectionDigest','0'*64)),
      ('review-signature-corrupt',lambda x:x['reviews'][0].__setitem__('signature','A'+x['reviews'][0]['signature'][1:])),
      ('release-one-signature',lambda x:x['release'].__setitem__('signatures',x['release']['signatures'][:1])),
      ('release-duplicate-signer',lambda x:x['release']['signatures'][1].__setitem__('authorityId',x['release']['signatures'][0]['authorityId'])),
      ('release-before-review',lambda x:x['release']['payload'].__setitem__('approvedAt','2030-01-04T11:00:00Z')),
      ('freeze-before-release',lambda x:x['freeze']['payload'].__setitem__('frozenAt','2030-01-04T11:00:00Z')),
      ('freeze-approval-digest-mismatch',lambda x:x['freeze']['payload'].__setitem__('approvalSetDigest','0'*64)),
      ('freeze-digest-mismatch',lambda x:x['freeze'].__setitem__('freezeDigest','0'*64)),
      ('successor-policy-weakened',lambda x:x['freeze']['payload'].__setitem__('successorPolicy','mutable')),
      ('unknown-release-review',lambda x:x['release']['payload'].__setitem__('approvalReviewIds',['review-alpha-001','review-gamma-999'])),
    ]
    cases += [(n,reject(m)) for n,m in muts]
    cases.append(('projection-byte-drift', reject(lambda x:None, PB+b' ')))
    ok=all(v for _,v in cases); out={'standard':'EIGIIB-IDP-A5-MATRIX-1.0','result':'conformant' if ok else 'nonconformant','cases':[{'name':n,'pass':v} for n,v in cases]}; print(json.dumps(out,sort_keys=True,separators=(',',':'))); return 0 if ok else 2
if __name__=='__main__': raise SystemExit(main())
