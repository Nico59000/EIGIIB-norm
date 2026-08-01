#!/usr/bin/env python3
"""Verify the authenticated, registered and superseding P1-A9 release authority."""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from eigiib_p1_a9_common import *
from eigiib_p1_a9_crypto import *

def validate(root:Path,capsule_path:Path,release_key_path:Path,ts_key_path:Path,openssl:str='openssl')->dict:
    capsule_raw=capsule_path.read_bytes(); capsule=strict_json(capsule_raw)
    if not exact_keys(capsule,{'claimBoundary','profile','publicKeys','releaseEnvelope','sourceRelease','standard','supersession','transparency'}): raise ValueError('capsule fields')
    if capsule['standard']!=STANDARD or capsule['profile']!=PROFILE: raise ValueError('capsule constants')
    release_path=confined(root,capsule['sourceRelease']['path']); release_raw=release_path.read_bytes(); release_doc=strict_json(release_raw)
    if capsule['sourceRelease']!={'identity':identity(release_raw),'path':capsule['sourceRelease']['path'],'releaseId':release_doc['releaseId']}: raise ValueError('source release identity')
    release_pem=release_key_path.read_text(encoding='utf-8'); ts_pem=ts_key_path.read_text(encoding='utf-8')
    _,release_der=parse_public_key_pem(release_pem); _,ts_der=parse_public_key_pem(ts_pem)
    if capsule['publicKeys']!={'releaseSignerSpki':identity(release_der),'transparencyServiceSpki':identity(ts_der)}: raise ValueError('public key identity')
    release_env=decode_b64(capsule['releaseEnvelope']['data'])
    if capsule['releaseEnvelope']!={'data':capsule['releaseEnvelope']['data'],'identity':identity(release_env),'payloadType':RELEASE_PAYLOAD_TYPE}: raise ValueError('release envelope carrier')
    parse_dsse(release_env,RELEASE_PAYLOAD_TYPE,release_raw,release_pem,openssl)
    sup=capsule['supersession']; sup_payload=decode_b64(sup['payload']['data']); sup_env=decode_b64(sup['envelope']['data'])
    if sup['relation']!=RELATION or sup['payload']['identity']!=identity(sup_payload) or sup['envelope']['identity']!=identity(sup_env) or sup['envelope']['payloadType']!=SUPERSESSION_PAYLOAD_TYPE: raise ValueError('supersession carrier')
    parse_dsse(sup_env,SUPERSESSION_PAYLOAD_TYPE,sup_payload,release_pem,openssl)
    sup_doc=strict_json(sup_payload)
    expected_sup={
      'claimBoundary':{'doesNotImply':['content-revocation','security-vulnerability-remediation','maintainer-or-legal-authorization','external-publication-or-distribution-withdrawal','trusted-effective-time']},
      'predecessor':{'authorityType':'detached-release-digest','releaseDescriptor':identity(release_raw),'releaseId':release_doc['releaseId'],'sequence':0},
      'preserves':{'releaseDescriptor':identity(release_raw)},
      'relation':RELATION,'standard':'EIGIIB-P1-A9-SUPERSESSION-1.0',
      'successor':{'authorityType':'authenticated-release-envelope','releaseEnvelope':identity(release_env),'releaseId':release_doc['releaseId'],'sequence':1},
    }
    if sup_doc!=expected_sup: raise ValueError('supersession semantics')
    trans=capsule['transparency']; entries=trans.get('entries') if isinstance(trans,dict) else None
    if trans.get('treeSize')!=2 or not isinstance(entries,list) or len(entries)!=2 or [e.get('kind') for e in entries]!=['release-envelope','supersession-envelope'] or [e.get('leafIndex') for e in entries]!=[0,1]: raise ValueError('transparency coordinates')
    statement_raw=[decode_b64(e['signedStatement']['data']) for e in entries]
    receipt_raw=[decode_b64(e['receipt']['data']) for e in entries]
    for i,e in enumerate(entries):
        if e['signedStatement']['identity']!=identity(statement_raw[i]) or e['receipt']['identity']!=identity(receipt_raw[i]): raise ValueError('transparency identity')
        reg=e['registration']
        if reg!={'method':'POST','resource':'/entries','status':201,'location':'https://transparency.example/entries/'+identity(statement_raw[i])['digest'],'mode':'fixture-no-network'}: raise ValueError('registration transcript')
    parse_statement(statement_raw[0],'release-envelope',release_env,release_raw,release_doc['authorityRoot'],release_pem,openssl)
    parse_statement(statement_raw[1],'supersession-envelope',sup_env,release_raw,RELATION,release_pem,openssl)
    root=node_hash(leaf_hash(statement_raw[0]),leaf_hash(statement_raw[1]))
    if trans['root']!={'algorithm':'rfc9162-sha256','bytes':32,'digest':root.hex()}: raise ValueError('transparency root')
    parse_receipt(receipt_raw[0],'release-envelope',statement_raw[0],0,leaf_hash(statement_raw[1]),root,ts_pem,openssl)
    parse_receipt(receipt_raw[1],'supersession-envelope',statement_raw[1],1,leaf_hash(statement_raw[0]),root,ts_pem,openssl)
    if not isinstance(capsule['claimBoundary'],dict) or not isinstance(capsule['claimBoundary'].get('doesNotImply'),list) or len(capsule['claimBoundary']['doesNotImply'])<8: raise ValueError('claim boundary')
    return {
      'standard':STANDARD,'profile':PROFILE,'tool':'eigiib-p1-a9-release-check','tool_version':'0.1.0',
      'release_id':release_doc['releaseId'],'release_descriptor_sha256':identity(release_raw)['digest'],'release_envelope_sha256':identity(release_env)['digest'],
      'supersession_envelope_sha256':identity(sup_env)['digest'],'transparency_root':root.hex(),'registered_entry_count':2,
      'release_envelope_result':'conformant','transparency_registration_result':'conformant','supersession_replay_result':'conformant','graph_acyclic_result':'conformant','unique_current_authority_result':'conformant','overall_result':'conformant','findings':[],
      'claim_boundary':capsule['claimBoundary']['doesNotImply'],
    }

def main()->int:
    p=argparse.ArgumentParser(); p.add_argument('root',type=Path); p.add_argument('--capsule',type=Path,required=True); p.add_argument('--release-key',type=Path,required=True); p.add_argument('--ts-key',type=Path,required=True); p.add_argument('--openssl',default='openssl'); p.add_argument('--expected',type=Path); p.add_argument('--json',action='store_true'); a=p.parse_args()
    try:
        report=validate(a.root.resolve(),a.capsule,a.release_key,a.ts_key,a.openssl)
        if a.expected and canonical_json(report)!=a.expected.read_bytes(): raise ValueError('canonical report differs')
        print(json.dumps(report if a.json else {'overall_result':report['overall_result'],'release_envelope_sha256':report['release_envelope_sha256']},sort_keys=True,separators=(',',':')))
        return 0
    except (OSError,ValueError,subprocess.CalledProcessError) as exc:
        print(f'P1A9.RELEASE.FAILURE: {exc}',file=sys.stderr); return 2
if __name__=='__main__': raise SystemExit(main())
