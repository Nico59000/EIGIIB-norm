#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, importlib.util, json
from pathlib import Path

CTX_FIELDS=("channelId","direction","localPrincipalId","remotePrincipalId","localEndpointId","remoteEndpointId","transportProfileId","expectedPinsetId","allowedClasses")

def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod

def sha(obj):
    return hashlib.sha256((json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode()).hexdigest()

def item(data, collection, ident):
    matches=[x for x in data[collection] if x.get("id")==ident]
    if len(matches)!=1: raise ValueError(f"mutation target {collection}/{ident}")
    return matches[0]

def mutate(base, ops):
    data=copy.deepcopy(base)
    for op in ops:
        if op.get("kind")=="recompute-context":
            b=item(data,"bindings",op["bindingId"])
            b["contextCommitment"]=sha({k:b[k] for k in CTX_FIELDS})
        else:
            item(data,op["collection"],op["id"])[op["field"]]=op["value"]
    return data

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("repo",nargs="?",default="."); ap.add_argument("--json",action="store_true")
    ns=ap.parse_args(); root=Path(ns.repo)
    matrix=json.loads((root/"conformance/idp-a2-verifier-matrix.json").read_text(encoding="utf-8"))
    base=json.loads((root/matrix["baseline"]).read_text(encoding="utf-8"))
    ref=load(root/"tools/eigiib_idp_a2_check.py","idp_a2_ref")
    ind=load(root/"tools/eigiib_idp_a2_independent.py","idp_a2_ind")
    rows=[]; bad=[]
    for v in matrix["vectors"]:
        data=mutate(base,v["mutations"])
        rr="CONFORMANT" if not ref.validate(data) else "NON_CONFORMANT"
        ir="CONFORMANT" if not ind.validate(data) else "NON_CONFORMANT"
        ok=(rr==v["expected"]==ir)
        rows.append({"id":v["id"],"expected":v["expected"],"reference":rr,"independent":ir,"ok":ok})
        if not ok: bad.append(v["id"])
    out={"standard":"EIGIIB-IDP-A2-0.1","result":"CONFORMANT" if not bad else "NON_CONFORMANT","vectors":rows}
    print(json.dumps(out,sort_keys=True) if ns.json else out["result"]+("\n"+"\n".join(bad) if bad else ""))
    return 1 if bad else 0
if __name__=="__main__": raise SystemExit(main())
