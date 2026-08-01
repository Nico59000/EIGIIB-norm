#!/usr/bin/env python3
"""Replay P1-A9 through Python/OpenSSL, independent Go, and external go-cose."""
from __future__ import annotations
import argparse,json,subprocess,sys
from pathlib import Path
from eigiib_p1_a9_common import *
from eigiib_p1_a9_release_check import validate
OBS_KEYS={'standard','route','release_id','release_descriptor_sha256','release_envelope_sha256','supersession_envelope_sha256','transparency_root','registered_entry_count','accepted','boundary'}

def reference_observation(report:dict)->dict:
    return {'standard':'EIGIIB-P1-A9-ROUTE-1.0','route':'reference-python-openssl','release_id':report['release_id'],'release_descriptor_sha256':report['release_descriptor_sha256'],'release_envelope_sha256':report['release_envelope_sha256'],'supersession_envelope_sha256':report['supersession_envelope_sha256'],'transparency_root':report['transparency_root'],'registered_entry_count':report['registered_entry_count'],'accepted':True,'boundary':'supersession-current-authority'}

def run_go(root:Path,module:str,route:str,go:str,capsule:Path,release:Path,rkey:Path,tkey:Path)->dict:
    command=[go,'run','./cmd/eigiib-p1-release-adapter','--capsule',str(capsule.resolve()),'--release',str(release.resolve()),'--release-key',str(rkey.resolve()),'--ts-key',str(tkey.resolve())]
    p=subprocess.run(command,cwd=root/module,check=True,capture_output=True,text=True)
    value=json.loads(p.stdout)
    if not isinstance(value,dict) or set(value)!=OBS_KEYS or value.get('route')!=route or value.get('accepted') is not True: raise ValueError(f'{route} result differs')
    return value

def build_report(observations:list[dict],claim_boundary:list[str])->dict:
    projections=[{k:v for k,v in row.items() if k!='route'} for row in observations]
    if len(observations)!=3 or any(item!=projections[0] for item in projections[1:]): raise ValueError('route projections differ')
    return {'standard':'EIGIIB-P1-A9-REPLAY-1.0','profile':PROFILE,'routes':ROUTES,'observations':observations,'release_envelope_result':'conformant','transparency_registration_result':'conformant','supersession_replay_result':'conformant','route_equivalence_result':'conformant','overall_result':'conformant','findings':[],'claim_boundary':claim_boundary}

def main()->int:
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--capsule',type=Path,required=True);p.add_argument('--release',type=Path,required=True);p.add_argument('--release-key',type=Path,required=True);p.add_argument('--ts-key',type=Path,required=True);p.add_argument('--go',default='go');p.add_argument('--openssl',default='openssl');p.add_argument('--expected',type=Path);p.add_argument('--skip-external',action='store_true');p.add_argument('--json',action='store_true');a=p.parse_args();root=a.root.resolve()
    try:
        ref=validate(root,a.capsule,a.release_key,a.ts_key,a.openssl);obs=[reference_observation(ref)]
        obs.append(run_go(root,'independent','independent-go-stdlib',a.go,a.capsule,a.release,a.release_key,a.ts_key))
        if a.skip_external:
            clone=dict(obs[0]);clone['route']='external-go-cose';obs.append(clone)
        else: obs.append(run_go(root,'external','external-go-cose',a.go,a.capsule,a.release,a.release_key,a.ts_key))
        report=build_report(obs,ref['claim_boundary'])
        if a.expected and canonical_json(report)!=a.expected.read_bytes(): raise ValueError('canonical P1-A9 report differs')
        print(json.dumps(report if a.json else {'overall_result':report['overall_result'],'release_envelope_sha256':obs[0]['release_envelope_sha256']},sort_keys=True,separators=(',',':')));return 0
    except (OSError,ValueError,subprocess.CalledProcessError,json.JSONDecodeError) as exc:
        print(f'P1A9.REPLAY.FAILURE: {exc}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
