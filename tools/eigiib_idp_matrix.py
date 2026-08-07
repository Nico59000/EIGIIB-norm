#!/usr/bin/env python3
from __future__ import annotations
import argparse, importlib.util, json
from pathlib import Path

def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

def main():
    p=argparse.ArgumentParser(); p.add_argument("root", nargs="?", default="."); p.add_argument("--json",action="store_true"); ns=p.parse_args(); root=Path(ns.root)
    ref=load(root/"tools/eigiib_idp_check.py","idp_ref"); ind=load(root/"tools/eigiib_idp_independent.py","idp_ind")
    matrix=json.loads((root/"conformance/idp-a1-verifier-matrix.json").read_text())
    rows=[]; ok=True
    for case in matrix["cases"]:
        data=json.loads((root/case["path"]).read_text()); a=ref.validate(data); b=ind.validate(data); expected=sorted(case["expectedFindings"])
        passed=(a==b==expected); ok &= passed; rows.append({"id":case["id"],"passed":passed,"reference":a,"independent":b,"expected":expected})
    out={"standard":matrix["standard"],"result":"CONFORMANT" if ok else "NON_CONFORMANT","rows":rows}
    print(json.dumps(out,sort_keys=True) if ns.json else out["result"]); return 0 if ok else 1
if __name__=="__main__": raise SystemExit(main())
