"""DSSE, COSE and Receipt verification primitives for P1-A9."""
from __future__ import annotations
import hashlib, subprocess, tempfile
from pathlib import Path
from typing import Any
from eigiib_p1_a7_cose_codec import CborMap,CborTag,decode_cbor,encode_cbor,parse_public_key_pem
from eigiib_p1_a9_common import *

def verify_ed25519(pem:str,message:bytes,signature:bytes,openssl:str)->bool:
    with tempfile.TemporaryDirectory(prefix='eigiib-p1-a9-') as td:
        d=Path(td); (d/'key.pem').write_text(pem,encoding='utf-8',newline='\n'); (d/'msg').write_bytes(message); (d/'sig').write_bytes(signature)
        p=subprocess.run([openssl,'pkeyutl','-verify','-pubin','-inkey',str(d/'key.pem'),'-rawin','-in',str(d/'msg'),'-sigfile',str(d/'sig')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return p.returncode==0

def dsse_pae(payload_type:str,payload:bytes)->bytes:
    return b'DSSEv1 '+str(len(payload_type.encode())).encode()+b' '+payload_type.encode()+b' '+str(len(payload)).encode()+b' '+payload

def parse_dsse(raw:bytes,payload_type:str,expected_payload:bytes,key_pem:str,openssl:str)->dict[str,Any]:
    doc=strict_json(raw)
    if not exact_keys(doc,{'standard','bundle'}) or doc['standard']!='EIGIIB-P1-A9-DSSE-1.0': raise ValueError('DSSE carrier')
    env=doc['bundle'].get('dsseEnvelope') if isinstance(doc['bundle'],dict) else None
    if not exact_keys(env,{'payload','payloadType','signatures'}) or env['payloadType']!=payload_type: raise ValueError('DSSE shape')
    payload=decode_b64(env['payload'])
    if payload!=expected_payload: raise ValueError('DSSE payload binding')
    signatures=env['signatures']
    if not isinstance(signatures,list) or len(signatures)!=1 or not exact_keys(signatures[0],{'keyid','sig'}): raise ValueError('DSSE signature carrier')
    _,der=parse_public_key_pem(key_pem)
    expected='p1-a9-ed25519-spki-sha256:'+hashlib.sha256(der).hexdigest()
    if signatures[0]['keyid']!=expected: raise ValueError('DSSE keyid')
    sig=decode_b64(signatures[0]['sig'])
    if len(sig)!=64 or not verify_ed25519(key_pem,dsse_pae(payload_type,payload),sig,openssl): raise ValueError('DSSE signature')
    return identity(raw)

def map_dict(value:CborMap)->dict[Any,Any]:
    return {k:v for k,v in value.pairs}

def parse_statement(raw:bytes,kind:str,envelope_raw:bytes,release_raw:bytes,extra:Any,key_pem:str,openssl:str)->dict[str,Any]:
    value=decode_cbor(raw)
    if encode_cbor(value)!=raw or not isinstance(value,CborTag) or value.number!=18 or not isinstance(value.value,list) or len(value.value)!=4: raise ValueError('statement structure')
    protected_raw,unprotected,payload,signature=value.value
    if not isinstance(protected_raw,bytes) or not isinstance(unprotected,CborMap) or unprotected.pairs or not isinstance(payload,bytes) or not isinstance(signature,bytes) or len(signature)!=64: raise ValueError('statement structure')
    protected=decode_cbor(protected_raw)
    if encode_cbor(protected)!=protected_raw or not isinstance(protected,CborMap): raise ValueError('statement protected')
    _,der=parse_public_key_pem(key_pem)
    expected={1:-8,3:'application/cbor',4:hashlib.sha256(der).digest(),15:CborMap(((1,'https://eigiib.example/p1-a9/release-authority'),(2,'urn:eigiib:p1-a9:'+kind))),16:STATEMENT_TYPE}
    if map_dict(protected)!=expected: raise ValueError('statement headers')
    body=decode_cbor(payload)
    if encode_cbor(body)!=payload or not isinstance(body,CborMap): raise ValueError('statement payload')
    release_doc=strict_json(release_raw)
    expected_body={1:kind,2:hashlib.sha256(envelope_raw).digest(),3:len(envelope_raw),4:hashlib.sha256(release_raw).digest(),5:release_doc['releaseId'],6:extra}
    if map_dict(body)!=expected_body: raise ValueError('statement binding')
    if not verify_ed25519(key_pem,encode_cbor(['Signature1',protected_raw,b'',payload]),signature,openssl): raise ValueError('statement signature')
    return identity(raw)

def leaf_hash(raw:bytes)->bytes: return hashlib.sha256(b'\x00'+raw).digest()
def node_hash(left:bytes,right:bytes)->bytes: return hashlib.sha256(b'\x01'+left+right).digest()

def parse_receipt(raw:bytes,kind:str,statement_raw:bytes,index:int,sibling:bytes,expected_root:bytes,key_pem:str,openssl:str)->dict[str,Any]:
    value=decode_cbor(raw)
    if encode_cbor(value)!=raw or not isinstance(value,CborTag) or value.number!=18 or not isinstance(value.value,list) or len(value.value)!=4: raise ValueError('receipt structure')
    protected_raw,unprotected,payload,signature=value.value
    if not isinstance(protected_raw,bytes) or not isinstance(unprotected,CborMap) or payload is not None or not isinstance(signature,bytes) or len(signature)!=64: raise ValueError('receipt structure')
    protected=decode_cbor(protected_raw)
    if encode_cbor(protected)!=protected_raw or not isinstance(protected,CborMap): raise ValueError('receipt headers')
    _,der=parse_public_key_pem(key_pem)
    subject='urn:eigiib:p1-a9:'+kind+':'+hashlib.sha256(statement_raw).hexdigest()
    expected={1:-8,4:hashlib.sha256(der).digest(),15:CborMap(((1,'https://eigiib.example/p1-a9/transparency-service'),(2,subject))),16:RECEIPT_TYPE,395:1}
    if map_dict(protected)!=expected: raise ValueError('receipt headers')
    if len(unprotected.pairs)!=1 or not unprotected.has(396): raise ValueError('receipt proof')
    proof_map=unprotected.get(396)
    if not isinstance(proof_map,CborMap) or len(proof_map.pairs)!=1 or not proof_map.has(-1): raise ValueError('receipt proof')
    proofs=proof_map.get(-1)
    if not isinstance(proofs,list) or len(proofs)!=1 or not isinstance(proofs[0],bytes): raise ValueError('receipt proof')
    proof=decode_cbor(proofs[0])
    if encode_cbor(proof)!=proofs[0] or not isinstance(proof,list) or len(proof)!=3: raise ValueError('receipt proof')
    tree,leaf,path=proof
    if tree!=2 or leaf!=index or path!=[sibling]: raise ValueError('receipt coordinates')
    root=node_hash(leaf_hash(statement_raw),sibling) if index==0 else node_hash(sibling,leaf_hash(statement_raw))
    if root!=expected_root: raise ValueError('receipt root')
    if not verify_ed25519(key_pem,encode_cbor(['Signature1',protected_raw,b'',root]),signature,openssl): raise ValueError('receipt signature')
    return identity(raw)
