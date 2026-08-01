#!/usr/bin/env python3
"""Closed standard-library JSON Schema subset validator for P1-A13."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
from typing import Any
from eigiib_p1_a13_common import strict_json

class Validator:
    def __init__(self, schemas: dict[str, dict[str, Any]]): self.schemas=schemas
    def resolve(self, schema: dict[str, Any], ref: str, current: str) -> tuple[dict[str, Any], str]:
        if ref.startswith("#/"):
            target=self.schemas[current]
            for part in ref[2:].split("/"): target=target[part.replace("~1","/").replace("~0","~")]
            return target,current
        if "#" in ref:
            name,fragment=ref.split("#",1)
            target=self.schemas[name]
            if fragment.startswith("/"):
                for part in fragment[1:].split("/"): target=target[part]
            return target,name
        return self.schemas[ref],ref
    def validate(self, value: Any, schema: dict[str, Any], current: str, path: str="$" ) -> None:
        if "$ref" in schema:
            target,name=self.resolve(schema,schema["$ref"],current); self.validate(value,target,name,path); return
        for part in schema.get("allOf",[]): self.validate(value,part,current,path)
        if "const" in schema and value!=schema["const"]: raise ValueError(f"{path}: const")
        if "enum" in schema and value not in schema["enum"]: raise ValueError(f"{path}: enum")
        typ=schema.get("type")
        if typ:
            ok={"object":isinstance(value,dict),"array":isinstance(value,list),"string":isinstance(value,str),"integer":isinstance(value,int) and not isinstance(value,bool),"boolean":isinstance(value,bool),"null":value is None}.get(typ,True)
            if not ok: raise ValueError(f"{path}: type {typ}")
        if isinstance(value,dict):
            req=schema.get("required",[])
            missing=[k for k in req if k not in value]
            if missing: raise ValueError(f"{path}: missing {missing}")
            props=schema.get("properties",{})
            if schema.get("additionalProperties") is False:
                extra=set(value)-set(props)
                if extra: raise ValueError(f"{path}: extra {sorted(extra)}")
            if len(value)<schema.get("minProperties",0): raise ValueError(f"{path}: minProperties")
            for k,v in value.items():
                if k in props: self.validate(v,props[k],current,f"{path}.{k}")
        if isinstance(value,list):
            if len(value)<schema.get("minItems",0): raise ValueError(f"{path}: minItems")
            if "maxItems" in schema and len(value)>schema["maxItems"]: raise ValueError(f"{path}: maxItems")
            if schema.get("uniqueItems"):
                seen=set()
                for item in value:
                    token=json.dumps(item,sort_keys=True,separators=(",",":"))
                    if token in seen: raise ValueError(f"{path}: duplicate item")
                    seen.add(token)
            if "items" in schema:
                for i,item in enumerate(value): self.validate(item,schema["items"],current,f"{path}[{i}]")
        if isinstance(value,str):
            if len(value)<schema.get("minLength",0): raise ValueError(f"{path}: minLength")
            if "pattern" in schema and re.fullmatch(schema["pattern"],value) is None: raise ValueError(f"{path}: pattern")
        if isinstance(value,int) and not isinstance(value,bool) and value<schema.get("minimum",value): raise ValueError(f"{path}: minimum")

def main()->int:
    parser=argparse.ArgumentParser(); parser.add_argument("root",type=Path); args=parser.parse_args()
    try:
        root=args.root.resolve(); schema_dir=root/"schemas"
        names=["eigiib-p1-a13-capsule.schema.json","eigiib-p1-a13-replay-report.schema.json","eigiib-p1-a13-route-result.schema.json"]
        schemas={name:strict_json((schema_dir/name).read_bytes()) for name in names}
        validator=Validator(schemas)
        pairs=[("tests/fixtures/p1-a13/capsule.json",names[0]),("tests/fixtures/p1-a13/expected-report.json",names[1]),("tests/fixtures/p1-a13/expected-replay.json",names[2])]
        for rel,name in pairs: validator.validate(strict_json((root/rel).read_bytes()),schemas[name],name)
        print("conformant"); return 0
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print(f"non-conformant: {exc}",file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())
