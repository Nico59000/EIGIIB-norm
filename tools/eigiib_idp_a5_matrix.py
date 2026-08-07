#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, importlib.util, json, tempfile
from pathlib import Path

NEGATIVE=[
    "insufficient-approvals",
    "duplicate-review-authority",
    "unknown-review-authority",
    "review-projection-digest-mismatch",
    "review-after-freeze",
    "approved-by-mismatch",
    "freeze-projection-digest-mismatch",
    "publication-authorized-true",
    "publication-disposition-published",
    "projection-byte-mutation",
    "source-head-mismatch",
    "source-path-mismatch",
    "threshold-zero",
    "authority-principal-collision",
    "authority-control-domain-collision",
    "authority-identity-root-collision",
    "approval-with-findings",
    "reject-listed-as-approver",
]

def canon(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def mutate(name,p,projection_text):
    x=copy.deepcopy(p); proj=projection_text
    if name=="insufficient-approvals":
        x["reviews"][1]["decision"]="reject"; x["reviews"][1]["findings"]=["synthetic-policy-objection"]; x["freeze"]["approvedBy"]=["reviewer-alpha"]; x["reviewSetDigest"]=canon(x["reviews"])
    elif name=="duplicate-review-authority":
        x["reviews"][1]["authorityId"]="reviewer-alpha"; x["freeze"]["approvedBy"]=["reviewer-alpha"]; x["reviewSetDigest"]=canon(x["reviews"])
    elif name=="unknown-review-authority":
        x["reviews"][1]["authorityId"]="reviewer-unknown"; x["freeze"]["approvedBy"]=["reviewer-alpha","reviewer-unknown"]; x["reviewSetDigest"]=canon(x["reviews"])
    elif name=="review-projection-digest-mismatch":
        x["reviews"][1]["projectionDigest"]="0"*64; x["reviewSetDigest"]=canon(x["reviews"])
    elif name=="review-after-freeze":
        x["reviews"][1]["reviewedAt"]="2030-01-04T12:20:00Z"; x["reviewSetDigest"]=canon(x["reviews"])
    elif name=="approved-by-mismatch":
        x["freeze"]["approvedBy"]=["reviewer-alpha"]
    elif name=="freeze-projection-digest-mismatch":
        x["freeze"]["projectionDigest"]="0"*64
    elif name=="publication-authorized-true":
        x["freeze"]["publicationAuthorized"]=True
    elif name=="publication-disposition-published":
        x["freeze"]["publicationDisposition"]="published"
    elif name=="projection-byte-mutation":
        proj=projection_text+" "
    elif name=="source-head-mismatch":
        x["source"]["head"]="0"*40
    elif name=="source-path-mismatch":
        x["source"]["registryPath"]="conformance/other.json"
    elif name=="threshold-zero":
        x["reviewPolicy"]["requiredApprovals"]=0
    elif name=="authority-principal-collision":
        x["authorities"][1]["principalId"]=x["authorities"][0]["principalId"]; x["authoritySetDigest"]=canon(x["authorities"])
    elif name=="authority-control-domain-collision":
        x["authorities"][1]["controlDomainId"]=x["authorities"][0]["controlDomainId"]; x["authoritySetDigest"]=canon(x["authorities"])
    elif name=="authority-identity-root-collision":
        x["authorities"][1]["identityRoot"]=x["authorities"][0]["identityRoot"]; x["authoritySetDigest"]=canon(x["authorities"])
    elif name=="approval-with-findings":
        x["reviews"][0]["findings"]=["synthetic-unresolved-finding"]; x["reviewSetDigest"]=canon(x["reviews"])
    elif name=="reject-listed-as-approver":
        x["reviews"].append({
            "reviewId":"review-gamma-001","authorityId":"reviewer-gamma",
            "projectionDigest":x["projection"]["sha256"],"decision":"reject",
            "reviewedAt":"2030-01-04T12:06:00Z","findings":["synthetic-policy-objection"]
        })
        x["freeze"]["approvedBy"]=["reviewer-alpha","reviewer-beta","reviewer-gamma"]
        x["reviewSetDigest"]=canon(x["reviews"])
    else:
        raise ValueError(name)
    return x,proj

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",type=Path,nargs="?",default=Path(".")); ap.add_argument("--json",action="store_true"); a=ap.parse_args()
    root=a.root
    package_path=root/"conformance/idp-a5-release-authorization.json"
    source=root/"conformance/idp-a4-public-transparency.json"
    projection=root/"conformance/idp-a5-public-projection.json"
    ref=load("idp_a5_ref",root/"tools/eigiib_idp_a5_check.py")
    ind=load("idp_a5_ind",root/"tools/eigiib_idp_a5_independent.py")
    base=json.loads(package_path.read_text(encoding="utf-8")); proj_text=projection.read_text(encoding="utf-8")
    cases=[]
    r=ref.evaluate(base,source,projection); i=ind.inspect(base,source,projection)
    cases.append({"case":"positive","reference":"conformant" if not r else "nonconformant","independent":"conformant" if not i else "nonconformant","pass":not r and not i})
    with tempfile.TemporaryDirectory() as td:
        td=Path(td)
        for name in NEGATIVE:
            pkg,pt=mutate(name,base,proj_text)
            pp=td/(name+".json"); qp=td/(name+".projection.json")
            pp.write_text(json.dumps(pkg,indent=2)+"\n",encoding="utf-8"); qp.write_text(pt,encoding="utf-8")
            rr=ref.evaluate(pkg,source,qp); ii=ind.inspect(pkg,source,qp)
            cases.append({"case":name,"reference":"nonconformant" if rr else "conformant","independent":"nonconformant" if ii else "conformant","pass":bool(rr) and bool(ii)})
    overall=all(c["pass"] for c in cases)
    out={"standard":"EIGIIB-IDP-A5-DIFFERENTIAL-MATRIX-1.0","result":"conformant" if overall else "nonconformant","cases":cases}
    print(json.dumps(out,sort_keys=True,separators=(",",":")) if a.json else out["result"])
    return 0 if overall else 2

if __name__=="__main__":
    raise SystemExit(main())
