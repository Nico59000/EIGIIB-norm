"""Shared constants and strict carriers for P1-A9."""
from __future__ import annotations
import base64, hashlib, json
from pathlib import Path
from typing import Any
STANDARD='EIGIIB-P1-A9-1.0'
PROFILE='authenticated-release-registration-supersession-v1'
ROUTES=['reference-python-openssl','independent-go-stdlib','external-go-cose']
RELEASE_PAYLOAD_TYPE='application/vnd.eigiib.release+json'
SUPERSESSION_PAYLOAD_TYPE='application/vnd.eigiib.release-supersession+json'
STATEMENT_TYPE='application/scitt-statement+cose'
RECEIPT_TYPE='application/scitt-receipt+cose'
RELATION='authority-carrier-upgrade'

def canonical_json(value: Any)->bytes:
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode('utf-8')

def strict_json(raw:bytes)->Any:
    def hook(rows):
        out={}
        for k,v in rows:
            if k in out: raise ValueError(f'duplicate JSON member: {k}')
            out[k]=v
        return out
    return json.loads(raw.decode('utf-8'),object_pairs_hook=hook,parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))

def decode_b64(value:Any)->bytes:
    if not isinstance(value,str) or not value: raise ValueError('base64 carrier')
    raw=base64.b64decode(value.encode('ascii'),validate=True)
    if base64.b64encode(raw).decode('ascii')!=value: raise ValueError('noncanonical base64')
    return raw

def identity(raw:bytes)->dict[str,Any]:
    return {'algorithm':'sha256','digest':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}

def exact_keys(value:Any,names:set[str])->bool:
    return isinstance(value,dict) and set(value)==names

def confined(root:Path,rel:str)->Path:
    if not isinstance(rel,str) or not rel or '\\' in rel or rel.startswith('/') or any(p in {'','.','..'} for p in rel.split('/')):
        raise ValueError('unsafe path')
    candidate=(root/rel).resolve(); base=root.resolve()
    if candidate!=base and base not in candidate.parents: raise ValueError('path escape')
    if not candidate.is_file(): raise ValueError('missing file')
    return candidate
