#!/usr/bin/env python3
from __future__ import annotations
import argparse,copy,importlib.util,json
from pathlib import Path

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def apply(data,mutation):
    if mutation is None:return data
    cur=data; path=mutation["path"]
    for part in path[:-1]:cur=cur[part]
    cur[path[-1]]=mutation["value"]
    return data
def main():
    p=argparse.ArgumentParser();p.add_argument("root",nargs="?",default=".");p.add_argument("--json",action="store_true");n=p.parse_args()
    base=Path(n.root).resolve();m=json.loads((base/"conformance/idp-a3-verifier-matrix.json").read_text());ev=m["evaluationAt"];original=json.loads((base/m["basePath"]).read_text())
    ref=load(base/"tools/eigiib_idp_a3_check.py","idp_a3_ref");ind=load(base/"tools/eigiib_idp_a3_independent.py","idp_a3_ind")
    rows=[];ok=True
    for v in m["vectors"]:
        d=apply(copy.deepcopy(original),v.get("mutation"));r1="CONFORMANT" if not ref.validate(d,ev) else "NON_CONFORMANT";r2="CONFORMANT" if not ind.verify(d,ev) else "NON_CONFORMANT";agree=(r1==r2==v["expected"]);ok=ok and agree;rows.append({"id":v["id"],"expected":v["expected"],"reference":r1,"independent":r2,"agree":agree})
    out={"standard":"EIGIIB-IDP-A3-0.1","evaluationAt":ev,"result":"CONFORMANT" if ok else "NON_CONFORMANT","vectors":rows};print(json.dumps(out,sort_keys=True) if n.json else out["result"]);return 0 if ok else 1
if __name__=="__main__":raise SystemExit(main())
