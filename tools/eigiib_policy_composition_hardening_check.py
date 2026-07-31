#!/usr/bin/env python3
"""EIGIIB-E13 hardening 0.2: required-state and waiver-context guards."""
from __future__ import annotations
import argparse, importlib.util, json, sys
from dataclasses import dataclass, asdict
from pathlib import Path

TOOL_VERSION="0.2.0"
STANDARD="EIGIIB-E13-hardening-0.2"

@dataclass(order=True)
class Finding:
    severity:str; code:str; path:str; message:str

class Checker:
    def __init__(self,root:Path,registry:Path,automation:Path):
        self.root=root.resolve(); self.registry_path=registry; self.automation_path=automation
        self.findings=[]; self.required_ok=0; self.waiver_ok=0; self.state_ok=0
    def add(self,s,c,m,p=""): self.findings.append(Finding(s,c,p,m))
    def load_json(self,rel,code):
        p=(self.root/rel).resolve(strict=False)
        try: p.relative_to(self.root)
        except ValueError: self.add("error",f"{code}.PATH","path escapes repository",str(rel)); return None
        if not p.exists() or not p.is_file(): self.add("error",f"{code}.MISSING","file missing",str(rel)); return None
        try: d=json.loads(p.read_text(encoding="utf-8"))
        except Exception as e: self.add("error",f"{code}.PARSE",str(e),str(rel)); return None
        if not isinstance(d,dict): self.add("error",f"{code}.TYPE","root must be object",str(rel)); return None
        return d
    @staticmethod
    def index(items):
        return {x.get("id"):x for x in items if isinstance(x,dict) and isinstance(x.get("id"),str)}
    def baseline(self):
        path=self.root/"tools/eigiib_policy_composition_check.py"
        spec=importlib.util.spec_from_file_location("e13baseline",path)
        mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
        r=mod.Checker(self.root,self.registry_path,self.automation_path).run()
        if r["structural_result"]!="conformant":
            self.add("error","E13H.BASELINE","baseline E13 checker is non-conformant",str(self.registry_path))
    def check(self):
        profiles=self.index(self.obj.get("composition_profiles",[]))
        requests=self.index(self.obj.get("requests",[]))
        decisions=self.index(self.obj.get("decisions",[]))
        exceptions=self.index(self.obj.get("exceptions",[]))
        contexts=self.index(self.auto.get("contexts",[]))
        proposals=self.index(self.auto.get("proposals",[]))
        e10=self.index(self.auto.get("decisions",[]))
        known={"authorized","denied","held","unavailable"}

        for rid,r in requests.items():
            loc=f"request:{rid}"
            selected=[]; by_policy={}
            for did in r.get("decisions",[]):
                d=e10.get(did)
                if not d: continue
                selected.append(d); by_policy[d.get("policy")]=d
                if d.get("state") not in known:
                    self.add("error","E13H.UPSTREAM.STATE","selected E10 decision has unknown state",loc)
            if selected and all(d.get("state") in known for d in selected): self.state_ok+=1

            composed=next((d for d in decisions.values() if d.get("request")==rid),None)
            profile=profiles.get(r.get("profile"))
            if composed and composed.get("state")=="permitted" and profile:
                missing_conclusive=[]
                for m in profile.get("members",[]):
                    if not isinstance(m,dict) or not m.get("required"): continue
                    d=by_policy.get(m.get("policy"))
                    if d is None or d.get("state") not in {"authorized","denied"}:
                        missing_conclusive.append(m.get("policy"))
                if missing_conclusive:
                    self.add("error","E13H.REQUIRED.CONCLUSIVE",f"permitted composition has required non-conclusive members: {missing_conclusive}",loc)
                else:
                    self.required_ok+=1

        for xid,x in exceptions.items():
            if x.get("state")!="active" or x.get("kind")!="obligation-waiver": continue
            loc=f"exception:{xid}"
            req=requests.get(x.get("request")); d=e10.get(x.get("e10_decision"))
            if not req or not d: continue
            p=proposals.get(d.get("proposal")); ctx=contexts.get(req.get("context"))
            if p is None:
                self.add("error","E13H.WAIVER.PROPOSAL","waiver E10 proposal does not resolve",loc); continue
            if p.get("context")!=req.get("context") or d.get("context")!=req.get("context"):
                self.add("error","E13H.WAIVER.CONTEXT","waiver authorization uses another context",loc)
            if d.get("context_revision")!=req.get("context_revision") or ctx is None or ctx.get("revision")!=req.get("context_revision"):
                self.add("error","E13H.WAIVER.CONTEXT_REVISION","waiver authorization context revision differs from request",loc)
            if not any(f.path==loc and f.severity=="error" for f in self.findings): self.waiver_ok+=1

    def run(self):
        self.obj=self.load_json(self.registry_path,"E13H.REGISTRY") or {}
        self.auto=self.load_json(self.automation_path,"E13H.E10") or {}
        if self.obj and self.auto:
            self.baseline()
            if not any(f.code=="E13H.BASELINE" for f in self.findings): self.check()
        errors=any(f.severity=="error" for f in self.findings)
        def cap(n): return "not-evaluated" if errors or n==0 else "verified"
        return {"tool":"eigiib_policy_composition_hardening_check.py","tool_version":TOOL_VERSION,"standard":STANDARD,
                "structural_result":"non-conformant" if errors else "conformant",
                "required_member_result":cap(self.required_ok),"waiver_context_result":cap(self.waiver_ok),
                "upstream_state_result":cap(self.state_ok),
                "findings":[asdict(f) for f in sorted(self.findings)]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default=".")
    ap.add_argument("--registry",default="conformance/policy-composition.json")
    ap.add_argument("--automation",default="conformance/automation.json"); ap.add_argument("--json",action="store_true")
    a=ap.parse_args(); r=Checker(Path(a.root),Path(a.registry),Path(a.automation)).run()
    print(json.dumps(r,indent=2,sort_keys=True)); return 1 if r["structural_result"]=="non-conformant" else 0
if __name__=="__main__": raise SystemExit(main())
