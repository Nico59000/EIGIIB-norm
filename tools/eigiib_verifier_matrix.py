#!/usr/bin/env python3
"""Validate and replay the EIGIIB P1-A5 independent verifier matrix."""
from __future__ import annotations
import argparse, hashlib, json, subprocess, sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

TOOL_VERSION="0.1.0"; STANDARD="EIGIIB-P1-A5-1.0"; PROFILE="independent-verifier-matrix-v1"
CHAIN_IDENTITY={"algorithm":"sha256","digest":"8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d","bytes":2182}
EXPECTED_ROUTES=[{"id":"reference-python-openssl","language":"python-3.13","crypto":"openssl-ed25519","entrypoint":"tools/eigiib_interop_chain_hardening_check.py","independenceClass":"reference-executable-closure"},{"id":"independent-go-stdlib","language":"go-1.26.5","crypto":"go-stdlib-crypto-ed25519","entrypoint":"independent/cmd/eigiib-p1-independent","independenceClass":"independent-json-cbor-crypto-route"}]
EXPECTED_PLATFORMS=[{"id":"linux-x64","runner":"ubuntu-24.04","required":True},{"id":"macos-arm64","runner":"macos-15","required":True},{"id":"windows-x64","runner":"windows-2025","required":True}]
BOUNDARIES=["verifier-agreement-does-not-imply-eigiib-claim-truth","cross-platform-replay-does-not-imply-production-environment-equivalence","independent-code-path-does-not-imply-independent-trust-roots","matrix-success-does-not-imply-absence-of-shared-specification-error","go-stdlib-verification-does-not-imply-trusted-go-toolchain","github-runner-diversity-does-not-imply-operator-or-hardware-independence","p1-a5-does-not-replace-p1-a1-p1-a2-p1-a3-p1-a4-authorities"]
PROJECTION_FIELDS=["manifest_binding_result","p1a1_replay_result","p1a2_replay_result","p1a3_replay_result","cross_capsule_binding_result","end_to_end_result","chain_identity"]
@dataclass(order=True)
class Finding: severity:str; code:str; path:str; message:str

def strict_json_loads(raw:bytes,code:str)->Any:
 def hook(pairs):
  out={}
  for k,v in pairs:
   if k in out: raise ValueError(f"duplicate JSON member: {k}")
   out[k]=v
  return out
 try:return json.loads(raw.decode(),object_pairs_hook=hook,parse_constant=lambda x:(_ for _ in()).throw(ValueError(f"non-finite JSON number: {x}")))
 except Exception as exc:raise ValueError(f"{code}: {exc}") from exc

def identity(raw):return {"algorithm":"sha256","digest":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}
def confined(root,rel):
 if not isinstance(rel,str) or not rel or Path(rel).is_absolute():raise ValueError("path must be a non-empty repository-relative string")
 p=(root/rel).resolve(strict=False)
 try:p.relative_to(root)
 except ValueError as exc:raise ValueError("path escapes repository root") from exc
 return p

def validate_manifest(root,manifest):
 if not isinstance(manifest,dict) or set(manifest)!={"standard","profile","status","sourceChain","routes","platforms","expectedResult","claimBoundary"}:raise ValueError("matrix fields differ from P1-A5 contract")
 if manifest.get("standard")!=STANDARD or manifest.get("profile")!=PROFILE or manifest.get("status")!="fixture-replay":raise ValueError("matrix constants differ from P1-A5 contract")
 if manifest.get("sourceChain")!={"manifest":"tests/fixtures/p1-a4/chain.json","identity":CHAIN_IDENTITY}:raise ValueError("source chain binding differs from P1-A5 contract")
 if manifest.get("routes")!=EXPECTED_ROUTES:raise ValueError("verifier routes differ from the closed P1-A5 matrix")
 if manifest.get("platforms")!=EXPECTED_PLATFORMS:raise ValueError("platform matrix differs from the closed P1-A5 matrix")
 if manifest.get("claimBoundary")!={"authority":"p1_verifier_matrix_contract","doesNotImply":BOUNDARIES}:raise ValueError("claim boundary differs from P1-A5 contract")
 expected=manifest.get("expectedResult")
 if not isinstance(expected,dict) or set(expected)!={"path","identity"}:raise ValueError("expectedResult binding is invalid")
 path=confined(root,expected.get("path"));raw=path.read_bytes()
 if expected.get("identity")!=identity(raw):raise ValueError("expected result identity differs from exact file bytes")
 obj=strict_json_loads(raw,"P1A5.EXPECTED")
 if not isinstance(obj,dict):raise ValueError("expected result must be object")
 return path,obj

def projection(obj):return {f:obj.get(f) for f in PROJECTION_FIELDS}
def run_json(command,cwd):
 try:cp=subprocess.run(command,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
 except OSError as exc:return 127,None,str(exc)
 err=cp.stderr.decode(errors="replace").strip()
 try:o=strict_json_loads(cp.stdout,"P1A5.SUBPROCESS")
 except ValueError:o=None
 return cp.returncode,o if isinstance(o,dict) else None,err

def result(findings,states):
 return {"tool":"eigiib-verifier-matrix","tool_version":TOOL_VERSION,"standard":STANDARD,"structural_result":"non-conformant" if findings else "conformant","matrix_contract_result":states.get("matrix","not-evaluated"),"reference_route_result":states.get("reference","not-evaluated"),"reference_closure_result":states.get("reference_closure","not-evaluated"),"independent_route_result":states.get("independent","not-evaluated"),"differential_result":states.get("differential","not-evaluated"),"expected_projection_result":states.get("expected","not-evaluated"),"cross_platform_matrix_result":"required-by-p1-a5-ci","trust_result":"not-evaluated-by-p1-a5","production_interoperability_result":"not-evaluated-by-p1-a5","findings":[asdict(f) for f in sorted(findings)]}

def check_repository(root,go="go",openssl="openssl"):
 root=root.resolve();findings=[];states={};mp=root/"tests/fixtures/p1-a5/matrix.json";sp=root/"conformance/p1-a5-verifier-matrix.json"
 try:manifest=strict_json_loads(mp.read_bytes(),"P1A5.MATRIX");expected_path,expected=validate_manifest(root,manifest);states["matrix"]="conformant"
 except (OSError,ValueError) as exc:return result([Finding("error","P1A5.MATRIX.INVALID",str(mp),str(exc))],states)
 wanted={"standard":STANDARD,"status":"structural-only","profile":PROFILE,"matrix_manifest":"tests/fixtures/p1-a5/matrix.json","reference_route":"python-3.13-openssl-p1-a4-h0.2","independent_route":"go-1.26.5-stdlib-ed25519-cbor","required_runners":["ubuntu-24.04","macos-15","windows-2025"],"network_mode":"none","production_replays":[]}
 try:
  if strict_json_loads(sp.read_bytes(),"P1A5.STATE")!=wanted:raise ValueError("structural state differs from P1-A5 contract")
 except (OSError,ValueError) as exc:findings.append(Finding("error","P1A5.STATE.INVALID",str(sp),str(exc)))
 rc,baseline,err=run_json([sys.executable,"tools/eigiib_interop_chain.py","check",".","--openssl",openssl,"--json"],root)
 if rc or not baseline or baseline.get("end_to_end_result")!="conformant":findings.append(Finding("error","P1A5.REFERENCE.BASELINE","tools/eigiib_interop_chain.py",err or "reference baseline failed"));states["reference"]="invalid"
 else:states["reference"]="conformant"
 rc,hardened,err=run_json([sys.executable,"tools/eigiib_interop_chain_hardening_check.py",".","--openssl",openssl,"--json"],root)
 if rc or not hardened or hardened.get("hardening_result")!="conformant" or hardened.get("baseline_replay_result")!="valid" or hardened.get("implementation_binding_result")!="valid":findings.append(Finding("error","P1A5.REFERENCE.CLOSURE","tools/eigiib_interop_chain_hardening_check.py",err or "reference executable closure failed"));states["reference_closure"]="invalid"
 else:states["reference_closure"]="conformant"
 rc,independent,err=run_json([go,"run","./cmd/eigiib-p1-independent","-root",".."],root/"independent")
 if rc or not independent or independent.get("end_to_end_result")!="conformant":findings.append(Finding("error","P1A5.INDEPENDENT.ROUTE","independent/cmd/eigiib-p1-independent",err or "independent route failed"));states["independent"]="invalid"
 else:states["independent"]="conformant"
 if independent is not None and independent!=expected:findings.append(Finding("error","P1A5.EXPECTED.MISMATCH",str(expected_path),"independent route result differs from the checked-in canonical result"));states["expected"]="invalid"
 elif independent is not None:states["expected"]="conformant"
 if baseline is not None and independent is not None:
  if projection(baseline)!=projection(independent):findings.append(Finding("error","P1A5.DIFFERENTIAL.DIVERGENCE","P1-A4/P1-A5","reference and independent projections differ"));states["differential"]="divergent"
  else:states["differential"]="equivalent"
 return result(findings,states)

def main():
 p=argparse.ArgumentParser();s=p.add_subparsers(dest="command",required=True);c=s.add_parser("check");c.add_argument("root",nargs="?",type=Path,default=Path("."));c.add_argument("--go",default="go");c.add_argument("--openssl",default="openssl");c.add_argument("--json",action="store_true");a=p.parse_args();out=check_repository(a.root,a.go,a.openssl)
 if a.json:print(json.dumps(out,indent=2,sort_keys=True))
 else:
  print(out["structural_result"])
  for x in out["findings"]:print(f"{x['severity']}: {x['code']}: {x['path']}: {x['message']}")
 return 0 if out["structural_result"]=="conformant" else 1
if __name__=="__main__":raise SystemExit(main())
