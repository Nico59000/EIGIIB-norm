#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, importlib.util, json
from pathlib import Path
from typing import Any


def load_module(name: str, path: Path):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None: raise RuntimeError(f"cannot load {path}")
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def strict_json(path: Path)->dict[str,Any]:
    def hook(pairs):
        out={}
        for key,value in pairs:
            if key in out: raise ValueError(f"duplicate JSON member: {key}")
            out[key]=value
        return out
    value=json.loads(path.read_text(encoding="utf-8"),object_pairs_hook=hook)
    if not isinstance(value,dict): raise ValueError(f"{path} root must be object")
    return value


def descend(root: Any, dotted: str)->Any:
    current=root
    for part in dotted.split("."):
        current=current[int(part)] if isinstance(current,list) else current[part]
    return current


def source_value(bundle: dict[str,Any], dotted: str)->Any:
    first,rest=dotted.split(".",1)
    return copy.deepcopy(descend(bundle[first],rest))


def apply(bundle: dict[str,Any], mutation: dict[str,Any] | None)->None:
    if mutation is None: return
    target=mutation["target"]
    root_name,rest=target.split(".",1) if "." in target else (target,"")
    target_object=bundle[root_name] if not rest else descend(bundle[root_name],rest)
    op=mutation["op"]; key=mutation["key"]
    if op in {"add","replace"}: target_object[key]=copy.deepcopy(mutation["value"])
    elif op=="copy": target_object[key]=source_value(bundle,mutation["from"])
    else: raise ValueError(f"unsupported mutation op: {op}")


def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("root",type=Path); parser.add_argument("--json",action="store_true"); args=parser.parse_args()
    root=args.root.resolve()
    reference=load_module("idp_a4_ref",root/"tools/eigiib_idp_a4_check.py")
    independent=load_module("idp_a4_ind",root/"tools/eigiib_idp_a4_independent.py")
    public=strict_json(root/"conformance/idp-a4-public-transparency.json")
    private=strict_json(root/"tests/fixtures/idp-a4/synthetic-private-witness.json")
    matrix=strict_json(root/"conformance/idp-a4-verifier-matrix.json")
    findings=[]; observations=[]
    for case in matrix.get("cases",[]):
        bundle={"public":copy.deepcopy(public),"private":copy.deepcopy(private)}
        apply(bundle,case.get("mutation"))
        ref_result="conformant" if not reference.evaluate(bundle["public"],bundle["private"]) else "nonconformant"
        independent_ok,_=independent.decide(bundle["public"],bundle["private"])
        independent_result="conformant" if independent_ok else "nonconformant"
        expected=case.get("expected")
        ok=ref_result==expected and independent_result==expected and ref_result==independent_result
        observations.append({"id":case.get("id"),"expected":expected,"reference":ref_result,"independent":independent_result,"result":"pass" if ok else "fail"})
        if not ok: findings.append(case.get("id"))
    out={"standard":"EIGIIB-IDP-A4-VERIFIER-MATRIX-1.0","caseCount":len(observations),"observations":observations,"result":"conformant" if not findings else "nonconformant","findings":findings}
    print(json.dumps(out,sort_keys=True,separators=(",",":")) if args.json else out["result"])
    return 0 if not findings else 2


if __name__=="__main__": raise SystemExit(main())
