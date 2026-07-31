#!/usr/bin/env python3
"""Additive EIGIIB-E9 hardening checks."""
from __future__ import annotations
import argparse, json
from dataclasses import dataclass, asdict
from pathlib import Path

TOOL_VERSION="0.2.0"
STANDARD="EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0"

@dataclass(order=True)
class Finding:
    severity:str
    code:str
    path:str
    message:str

class Checker:
    def __init__(self,root:Path,registry:Path):
        self.root=root.resolve(); self.registry_path=registry; self.findings=[]; self.obj={}
    def add(self,code,message,path=""):
        self.findings.append(Finding("error",code,path,message))
    def safe_path(self,raw):
        if not isinstance(raw,str) or not raw:
            self.add("E9H.PATH.INVALID","path must be non-empty",str(raw)); return False
        p=Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("E9H.PATH.ESCAPE","path escapes repository",raw); return False
        c=(self.root/p).resolve(strict=False)
        try: c.relative_to(self.root)
        except ValueError:
            self.add("E9H.PATH.ESCAPE","resolved path escapes repository",raw); return False
        if not c.exists() or not c.is_file():
            self.add("E9H.PATH.MISSING","evidence file does not exist",raw); return False
        try: c.resolve(strict=True).relative_to(self.root)
        except (OSError,ValueError):
            self.add("E9H.PATH.ESCAPE","unsafe resolved evidence path",raw); return False
        return True
    def load(self):
        p=(self.root/self.registry_path).resolve(strict=False)
        try: p.relative_to(self.root)
        except ValueError:
            self.add("E9H.REGISTRY.PATH","registry escapes repository",str(self.registry_path)); return False
        try: d=json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            self.add("E9H.REGISTRY.PARSE",f"cannot parse registry: {exc}",str(self.registry_path)); return False
        if not isinstance(d,dict): self.add("E9H.REGISTRY.TYPE","registry root must be object",str(self.registry_path)); return False
        self.obj=d
        if d.get("standard")!=STANDARD: self.add("E9H.STANDARD","unsupported E9 standard",str(self.registry_path))
        return True
    def evidence_item(self,e,code,loc):
        if isinstance(e,str):
            if not e: self.add(code,"evidence id must be non-empty",loc)
            return
        if isinstance(e,dict) and isinstance(e.get("path"),str) and e.get("path"):
            self.safe_path(e["path"]); return
        self.add(code,"evidence item must be non-empty id or path object",loc)
    def run_checks(self):
        for i,m in enumerate(self.obj.get("modes",[])):
            if not isinstance(m,dict): continue
            loc=f"mode:{m.get('id',i)}"
            a=m.get("preserved_guarantees",[]); b=m.get("suspended_guarantees",[])
            if isinstance(a,list) and isinstance(b,list):
                overlap=set(a)&set(b)
                if overlap: self.add("E9H.MODE.GUARANTEE_OVERLAP",f"guarantee both preserved and suspended: {sorted(overlap)}",loc)
        for key,code in (("observations","E9H.OBS.EVIDENCE"),("fallbacks","E9H.FALLBACK.EVIDENCE")):
            for i,item in enumerate(self.obj.get(key,[])):
                if not isinstance(item,dict): continue
                loc=f"{key[:-1]}:{item.get('id',i)}"; ev=item.get("evidence",[])
                if isinstance(ev,list):
                    for e in ev: self.evidence_item(e,code,loc)
        caps={x.get("id"):x for x in self.obj.get("capabilities",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        obs={x.get("id"):x for x in self.obj.get("observations",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        fbs={x.get("id"):x for x in self.obj.get("fallbacks",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        for i,d in enumerate(self.obj.get("decisions",[])):
            if not isinstance(d,dict) or d.get("state") in {"unsafe","unavailable"}: continue
            loc=f"decision:{d.get('id',i)}"
            selected_obs={}
            for r in d.get("observations",[]) if isinstance(d.get("observations",[]),list) else []:
                o=obs.get(r)
                if o and isinstance(o.get("dependency"),str): selected_obs[o["dependency"]]=o
            selected_fb={}
            for r in d.get("fallbacks",[]) if isinstance(d.get("fallbacks",[]),list) else []:
                f=fbs.get(r)
                if f and f.get("state")=="active" and isinstance(f.get("source"),str): selected_fb[f["source"]]=f
            for cid in d.get("capabilities",[]) if isinstance(d.get("capabilities",[]),list) else []:
                c=caps.get(cid)
                if not c or c.get("minimum_availability")!="available": continue
                for dep in c.get("required_dependencies",[]) if isinstance(c.get("required_dependencies",[]),list) else []:
                    direct=selected_obs.get(dep)
                    if direct and direct.get("state")=="available": continue
                    f=selected_fb.get(dep)
                    if not f: continue
                    sub=selected_obs.get(f.get("substitute"))
                    if sub and sub.get("state")=="degraded":
                        self.add("E9H.CAP.FALLBACK_MINIMUM",f"capability {cid} requires available but fallback substitute is degraded",loc)
    def run(self):
        if self.load(): self.run_checks()
        fs=sorted(self.findings,key=lambda x:(x.code,x.path,x.message))
        return {"tool":"eigiib-degraded-hardening-check","tool_version":TOOL_VERSION,"standard":STANDARD,"revision":self.obj.get("revision","unknown"),"hardening_result":"non-conformant" if fs else "conformant","findings":[asdict(f) for f in fs]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="."); ap.add_argument("--registry",default="conformance/degraded.json"); ap.add_argument("--json",action="store_true"); a=ap.parse_args()
    r=Checker(Path(a.root),Path(a.registry)).run(); print(json.dumps(r,indent=2,sort_keys=True) if a.json else r["hardening_result"]); return 1 if r["hardening_result"]=="non-conformant" else 0
if __name__=="__main__": raise SystemExit(main())
