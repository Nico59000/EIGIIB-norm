#!/usr/bin/env python3
"""EIGIIB-E9 degraded operation, fallback and partial-trust checker."""
from __future__ import annotations
import argparse, json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0"
MAX_OBJECTS = 100_000

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

class Checker:
    def __init__(self, root: Path, registry: Path, convergence: Path | None = None):
        self.root = root.resolve(); self.registry_path = registry; self.convergence_path = convergence
        self.findings: list[Finding] = []; self.obj: dict[str,Any] = {}
        self.dependencies={}; self.capabilities={}; self.modes={}; self.observations={}; self.fallbacks={}; self.policies={}; self.decisions={}
        self.e8_cutovers=set(); self.degraded_verified=0; self.fallback_verified=0; self.partial_verified=0; self.nominal_verified=0
        self.valid_positive_decisions=set()

    def add(self,severity,code,message,path=""):
        self.findings.append(Finding(severity,code,path,message))

    def safe_path(self, raw: str) -> Path | None:
        if not isinstance(raw,str) or not raw:
            self.add("error","E9.PATH.INVALID","path must be non-empty",str(raw)); return None
        p=Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error","E9.PATH.ESCAPE","path escapes repository",raw); return None
        c=(self.root/p).resolve(strict=False)
        try: c.relative_to(self.root)
        except ValueError:
            self.add("error","E9.PATH.ESCAPE","resolved path escapes repository",raw); return None
        if not c.exists() or not c.is_file():
            self.add("error","E9.PATH.MISSING","file does not exist",raw); return None
        try: c.resolve(strict=True).relative_to(self.root)
        except (OSError,ValueError):
            self.add("error","E9.PATH.SYMLINK","unsafe resolved path",raw); return None
        return c

    def load_json(self, rel: Path, code: str, required=True):
        p=(self.root/rel).resolve(strict=False)
        if not p.exists() and not required: return None
        s=self.safe_path(str(rel))
        if s is None: return None
        try: d=json.loads(s.read_text(encoding="utf-8"))
        except (OSError,UnicodeError,json.JSONDecodeError) as exc:
            self.add("error",f"{code}.PARSE",f"cannot parse JSON: {exc}",str(rel)); return None
        if not isinstance(d,dict): self.add("error",f"{code}.TYPE","registry root must be object",str(rel)); return None
        return d

    def load(self):
        d=self.load_json(self.registry_path,"E9.REGISTRY")
        if d is None: return False
        self.obj=d
        if d.get("standard") != STANDARD: self.add("error","E9.STANDARD","unsupported E9 standard identifier",str(self.registry_path))
        if not isinstance(d.get("revision"),str) or not d.get("revision"): self.add("error","E9.REVISION","revision must be non-empty string",str(self.registry_path))
        arrays=["dependencies","capabilities","modes","observations","fallbacks","policies","decisions"]
        total=0
        for k in arrays:
            v=d.get(k)
            if not isinstance(v,list): self.add("error","E9.COLLECTION",f"{k} must be array",str(self.registry_path))
            else: total += len(v)
        if total>MAX_OBJECTS: self.add("error","E9.RESOURCE","object count exceeds checker limit")
        self.load_e8(); return True

    def load_e8(self):
        if not self.convergence_path: return
        d=self.load_json(self.convergence_path,"E9.E8",required=False)
        if not d: return
        for x in d.get("cutover_decisions",[]):
            if isinstance(x,dict) and x.get("state")=="verified" and isinstance(x.get("id"),str): self.e8_cutovers.add(x["id"])

    def map_items(self,key,code):
        out={}
        for i,item in enumerate(self.obj.get(key,[])):
            loc=f"{self.registry_path}#/{key}/{i}"
            if not isinstance(item,dict): self.add("error",f"{code}.TYPE","item must be object",loc); continue
            iid=item.get("id")
            if not isinstance(iid,str) or not iid: self.add("error",f"{code}.ID","item requires non-empty id",loc); continue
            if iid in out: self.add("error",f"{code}.DUPLICATE",f"duplicate id: {iid}",loc)
            out[iid]=item
        return out

    def check_base(self):
        self.dependencies=self.map_items("dependencies","E9.DEP")
        self.capabilities=self.map_items("capabilities","E9.CAP")
        self.modes=self.map_items("modes","E9.MODE")
        self.observations=self.map_items("observations","E9.OBS")
        self.fallbacks=self.map_items("fallbacks","E9.FALLBACK")
        self.policies=self.map_items("policies","E9.POLICY")
        for did,d in self.dependencies.items():
            if d.get("kind") not in {"authority","verifier","witness","registry","storage","network","relying-party-set","service","other"}: self.add("error","E9.DEP.KIND","invalid dependency kind",f"dependency:{did}")
        for cid,c in self.capabilities.items():
            loc=f"capability:{cid}"
            if c.get("impact") not in {"observe","read","write","publish","admin"}: self.add("error","E9.CAP.IMPACT","invalid impact",loc)
            if c.get("minimum_availability") not in {"available","degraded"}: self.add("error","E9.CAP.MINIMUM","invalid minimum_availability",loc)
            req=c.get("required_dependencies",[])
            if not isinstance(req,list): self.add("error","E9.CAP.REQS","required_dependencies must be array",loc)
            else:
                for r in req:
                    if r not in self.dependencies: self.add("error","E9.CAP.DEP_REF",f"unresolved dependency: {r}",loc)
        for mid,m in self.modes.items():
            loc=f"mode:{mid}"
            if m.get("kind") not in {"nominal","degraded","fallback","isolated","read-only"}: self.add("error","E9.MODE.KIND","invalid mode kind",loc)
            if m.get("assurance") not in {"full","partial","minimal"}: self.add("error","E9.MODE.ASSURANCE","invalid assurance",loc)
            allow=m.get("allowed_capabilities",[]); deny=m.get("denied_capabilities",[])
            if not isinstance(allow,list) or not isinstance(deny,list): self.add("error","E9.MODE.CAPS","allowed/denied capabilities must be arrays",loc); continue
            for r in allow+deny:
                if r not in self.capabilities: self.add("error","E9.MODE.CAP_REF",f"unresolved capability: {r}",loc)
            overlap=set(allow)&set(deny)
            if overlap: self.add("error","E9.MODE.OVERLAP",f"capability both allowed and denied: {sorted(overlap)}",loc)
            susp=m.get("suspended_guarantees",[])
            if m.get("kind")!="nominal" and m.get("assurance")=="full" and not deny and not susp:
                self.add("error","E9.MODE.NOT_REDUCED","non-nominal mode must expose reduced or substituted semantics",loc)
        for oid,o in self.observations.items():
            loc=f"observation:{oid}"
            if o.get("dependency") not in self.dependencies: self.add("error","E9.OBS.DEP_REF","unresolved dependency",loc)
            if o.get("state") not in {"available","degraded","unavailable","unknown","not-applicable"}: self.add("error","E9.OBS.STATE","invalid observation state",loc)
            ev=o.get("evidence",[])
            if not isinstance(ev,list): self.add("error","E9.OBS.EVIDENCE","evidence must be array",loc); continue
            for e in ev:
                if isinstance(e,dict) and "path" in e: self.safe_path(e["path"])
                elif not isinstance(e,(str,dict)): self.add("error","E9.OBS.EVIDENCE","invalid evidence item",loc)
        for fid,f in self.fallbacks.items():
            loc=f"fallback:{fid}"
            if f.get("source") not in self.dependencies or f.get("substitute") not in self.dependencies: self.add("error","E9.FALLBACK.DEP_REF","unresolved fallback dependency",loc)
            if f.get("source")==f.get("substitute"): self.add("error","E9.FALLBACK.SAME","fallback source and substitute must differ",loc)
            if f.get("state") not in {"planned","eligible","active","failed","retired"}: self.add("error","E9.FALLBACK.STATE","invalid fallback state",loc)
            ev=f.get("evidence",[])
            if not isinstance(ev,list): self.add("error","E9.FALLBACK.EVIDENCE","evidence must be array",loc)
            if isinstance(ev,list):
                for e in ev:
                    if isinstance(e,dict) and "path" in e: self.safe_path(e["path"])
                    elif not isinstance(e,(str,dict)): self.add("error","E9.FALLBACK.EVIDENCE","invalid evidence item",loc)
            if f.get("state")=="active" and (not isinstance(ev,list) or not ev): self.add("error","E9.FALLBACK.NO_EVIDENCE","active fallback requires evidence",loc)
        for pid,p in self.policies.items():
            loc=f"policy:{pid}"
            if p.get("mode") not in self.modes: self.add("error","E9.POLICY.MODE_REF","unresolved mode",loc)
            if p.get("unknown_disposition") not in {"deny","hold","fallback"}: self.add("error","E9.POLICY.UNKNOWN","invalid unknown_disposition",loc)
            for k in ("required_dependencies","allowed_degraded_dependencies"):
                v=p.get(k,[])
                if not isinstance(v,list): self.add("error","E9.POLICY.DEPS",f"{k} must be array",loc)
                else:
                    for r in v:
                        if r not in self.dependencies: self.add("error","E9.POLICY.DEP_REF",f"unresolved dependency: {r}",loc)
            caps=p.get("allowed_capabilities",[])
            if not isinstance(caps,list): self.add("error","E9.POLICY.CAPS","allowed_capabilities must be array",loc)
            else:
                for r in caps:
                    if r not in self.capabilities: self.add("error","E9.POLICY.CAP_REF",f"unresolved capability: {r}",loc)
            if not isinstance(p.get("require_e8_cutover_for_nominal",False),bool): self.add("error","E9.POLICY.E8_BOOL","require_e8_cutover_for_nominal must be boolean",loc)

    def obs_map(self, refs, loc):
        out={}
        if not isinstance(refs,list): self.add("error","E9.DECISION.OBS","observations must be array",loc); return out
        for r in refs:
            o=self.observations.get(r)
            if o is None: self.add("error","E9.DECISION.OBS_REF",f"unresolved observation: {r}",loc); continue
            ev=o.get("evidence",[])
            if not isinstance(ev,list) or not ev: self.add("error","E9.DECISION.OBS_EVIDENCE",f"positive decision observation lacks evidence: {r}",loc); continue
            dep=o.get("dependency")
            if dep in out:
                self.add("error","E9.DECISION.OBS_DUPLICATE",f"multiple observations selected for dependency: {dep}",loc)
                continue
            out[dep]=o
        return out

    def selected_fallbacks(self, refs, obs, policy, loc):
        out={}
        if not isinstance(refs,list): self.add("error","E9.DECISION.FALLBACKS","fallbacks must be array",loc); return out
        for r in refs:
            f=self.fallbacks.get(r)
            if f is None: self.add("error","E9.DECISION.FALLBACK_REF",f"unresolved fallback: {r}",loc); continue
            if f.get("state")!="active": self.add("error","E9.DECISION.FALLBACK_STATE",f"selected fallback not active: {r}",loc); continue
            src=obs.get(f.get("source")); sub=obs.get(f.get("substitute"))
            if src is None or src.get("state") not in {"degraded","unavailable","unknown"}: self.add("error","E9.DECISION.FALLBACK_SOURCE",f"fallback source not observed degraded/unavailable/unknown: {r}",loc); continue
            if sub is None or sub.get("state") not in {"available","degraded"}: self.add("error","E9.DECISION.FALLBACK_SUBSTITUTE",f"fallback substitute not usable: {r}",loc); continue
            if src.get("state")=="unknown" and policy.get("unknown_disposition")!="fallback":
                self.add("error","E9.DECISION.UNKNOWN_FALLBACK",f"policy does not permit fallback from unknown source: {r}",loc); continue
            if sub.get("state")=="degraded" and f.get("substitute") not in policy.get("allowed_degraded_dependencies",[]):
                self.add("error","E9.DECISION.FALLBACK_SUBSTITUTE",f"degraded substitute is not policy-permitted: {r}",loc); continue
            out[f.get("source")]=f
        return out

    def dep_satisfied(self, dep, cap, policy, obs, fallbacks):
        o=obs.get(dep); minimum=cap.get("minimum_availability")
        if not o: return False
        st=o.get("state")
        if st=="available": return True
        if st=="degraded":
            if cap.get("policy_requirement"): return dep in policy.get("allowed_degraded_dependencies",[]) or dep in fallbacks
            if minimum=="degraded" and dep in policy.get("allowed_degraded_dependencies",[]): return True
            return dep in fallbacks
        if st=="unavailable": return dep in fallbacks
        if st=="unknown": return policy.get("unknown_disposition")=="fallback" and dep in fallbacks
        return False

    def check_decisions(self):
        self.decisions=self.map_items("decisions","E9.DECISION")
        for did,d in self.decisions.items():
            loc=f"decision:{did}"; state=d.get("state")
            if state not in {"degraded-safe","fallback-verified","partial-trust-available","nominal-restored","unsafe","unavailable"}: self.add("error","E9.DECISION.STATE","invalid decision state",loc); continue
            if state in {"unsafe","unavailable"}: continue
            mode=self.modes.get(d.get("mode")); policy=self.policies.get(d.get("policy"))
            if mode is None or policy is None: self.add("error","E9.DECISION.REF","unresolved mode or policy",loc); continue
            if policy.get("mode")!=d.get("mode"): self.add("error","E9.DECISION.POLICY_MODE","policy does not govern selected mode",loc)
            obs=self.obs_map(d.get("observations",[]),loc)
            fb=self.selected_fallbacks(d.get("fallbacks",[]),obs,policy,loc)
            for dep in policy.get("required_dependencies",[]):
                pseudo={"minimum_availability":"available","policy_requirement":True}
                if not self.dep_satisfied(dep,pseudo,policy,obs,fb): self.add("error","E9.DECISION.REQUIRED_DEP",f"required dependency not satisfied: {dep}",loc)
            requested=d.get("capabilities",[])
            if not isinstance(requested,list): self.add("error","E9.DECISION.CAPS","capabilities must be array",loc); requested=[]
            for cid in requested:
                cap=self.capabilities.get(cid)
                if cap is None: self.add("error","E9.DECISION.CAP_REF",f"unresolved capability: {cid}",loc); continue
                if cid not in mode.get("allowed_capabilities",[]): self.add("error","E9.DECISION.MODE_CAP",f"capability not allowed by mode: {cid}",loc)
                if cid not in policy.get("allowed_capabilities",[]): self.add("error","E9.DECISION.POLICY_CAP",f"capability not allowed by policy: {cid}",loc)
                for dep in cap.get("required_dependencies",[]):
                    if not self.dep_satisfied(dep,cap,policy,obs,fb): self.add("error","E9.DECISION.CAP_DEP",f"capability {cid} dependency not satisfied: {dep}",loc)
            if mode.get("assurance")=="full":
                used={dep for cid in requested for dep in self.capabilities.get(cid,{}).get("required_dependencies",[])} | set(policy.get("required_dependencies",[]))
                for dep in used:
                    o=obs.get(dep)
                    if o is None or o.get("state")!="available" or dep in fb: self.add("error","E9.DECISION.FULL_ASSURANCE","full assurance requires direct available dependencies without fallback",loc); break
            if state=="fallback-verified":
                if mode.get("kind")!="fallback": self.add("error","E9.DECISION.FALLBACK_MODE","fallback-verified requires fallback mode",loc)
                if not fb: self.add("error","E9.DECISION.FALLBACK_REQUIRED","fallback-verified requires at least one valid active fallback",loc)
            if state=="degraded-safe" and mode.get("kind") not in {"degraded","isolated","read-only"}:
                self.add("error","E9.DECISION.DEGRADED_MODE","degraded-safe requires degraded/isolated/read-only mode",loc)
            if state=="partial-trust-available" and mode.get("assurance")=="full":
                self.add("error","E9.DECISION.PARTIAL_ASSURANCE","partial-trust-available cannot claim full assurance",loc)
            if state=="nominal-restored":
                if mode.get("kind")!="nominal": self.add("error","E9.DECISION.NOMINAL_MODE","nominal restoration requires nominal mode",loc)
                if fb: self.add("error","E9.DECISION.NOMINAL_FALLBACK","nominal restoration cannot rely on active fallback",loc)
                for dep in policy.get("required_dependencies",[]):
                    o=obs.get(dep)
                    if o is None or o.get("state")!="available": self.add("error","E9.DECISION.NOMINAL_DEP",f"nominal dependency not directly available: {dep}",loc)
                if policy.get("require_e8_cutover_for_nominal") and d.get("e8_cutover") not in self.e8_cutovers: self.add("error","E9.DECISION.E8","required E8 cutover fact is absent",loc)
            else:
                if mode.get("kind")=="nominal": self.add("error","E9.DECISION.NONNOMINAL","degraded/fallback/partial decision cannot claim nominal mode",loc)
                if not mode.get("denied_capabilities",[]) and not mode.get("suspended_guarantees",[]) and not fb and mode.get("assurance")=="full": self.add("error","E9.DECISION.NOT_REDUCED","non-nominal decision exposes no reduced/substituted semantics",loc)
            if any(f.severity=="error" and f.path==loc for f in self.findings): continue
            self.valid_positive_decisions.add(did)
            if state=="degraded-safe": self.degraded_verified += 1
            elif state=="fallback-verified": self.fallback_verified += 1
            elif state=="partial-trust-available": self.partial_verified += 1
            elif state=="nominal-restored": self.nominal_verified += 1

    def run(self):
        if self.load(): self.check_base(); self.check_decisions()
        findings=sorted(self.findings,key=lambda x:(x.severity,x.code,x.path,x.message)); errors=sum(f.severity=="error" for f in findings)
        positive_ok = errors == 0
        return {"tool":"eigiib-degraded-check","tool_version":TOOL_VERSION,"standard":STANDARD,"revision":self.obj.get("revision","unknown"),
                "structural_result":"non-conformant" if errors else "conformant",
                "degraded_operation_result":"verified" if positive_ok and self.degraded_verified else "not-evaluated",
                "fallback_result":"verified" if positive_ok and self.fallback_verified else "not-evaluated",
                "partial_trust_result":"verified" if positive_ok and self.partial_verified else "not-evaluated",
                "nominal_restoration_result":"verified" if positive_ok and self.nominal_verified else "not-evaluated",
                "findings":[asdict(f) for f in findings]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="."); ap.add_argument("--registry",default="conformance/degraded.json"); ap.add_argument("--convergence",default="conformance/convergence.json"); ap.add_argument("--json",action="store_true"); a=ap.parse_args()
    r=Checker(Path(a.root),Path(a.registry),Path(a.convergence)).run(); print(json.dumps(r,indent=2,sort_keys=True) if a.json else r["structural_result"]); return 1 if r["structural_result"]=="non-conformant" else 0
if __name__=="__main__": raise SystemExit(main())
