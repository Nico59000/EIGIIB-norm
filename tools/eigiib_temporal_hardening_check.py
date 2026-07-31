#!/usr/bin/env python3
"""EIGIIB-E11 hardening 0.2: exact E10 boundary, renewal-chain, and replay-observation guards."""
from __future__ import annotations
import argparse, importlib.util, json, sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

TOOL_VERSION="0.2.0"
STANDARD="EIGIIB-E11-hardening-0.2"

@dataclass(order=True)
class Finding:
    severity:str; code:str; path:str; message:str

class Checker:
    def __init__(self,root:Path,registry:Path,automation:Path):
        self.root=root.resolve(); self.registry_path=registry; self.automation_path=automation; self.findings=[]
        self.obj={}; self.auto={}; self.binding_ok=0; self.chain_ok=0; self.replay_ok=0
    def add(self,s,c,m,p=""): self.findings.append(Finding(s,c,p,m))
    def load_json(self,rel,code):
        p=(self.root/rel).resolve(strict=False)
        try: p.relative_to(self.root)
        except ValueError: self.add("error",f"{code}.PATH","path escapes repository",str(rel)); return None
        if not p.exists() or not p.is_file(): self.add("error",f"{code}.MISSING","file missing",str(rel)); return None
        try: d=json.loads(p.read_text())
        except Exception as e: self.add("error",f"{code}.PARSE",str(e),str(rel)); return None
        if not isinstance(d,dict): self.add("error",f"{code}.TYPE","root must be object",str(rel)); return None
        return d
    def baseline(self):
        path=self.root/"tools/eigiib_temporal_check.py"
        spec=importlib.util.spec_from_file_location("e11baseline",path); mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
        r=mod.Checker(self.root,self.registry_path,self.automation_path).run()
        if r["structural_result"]!="conformant": self.add("error","E11H.BASELINE","baseline E11 checker is non-conformant",str(self.registry_path))
    @staticmethod
    def boundary(x:dict[str,Any]):
        b=x.get("e10_boundary")
        if not isinstance(b,dict): return None
        keys=("proposal_revision","policy_revision","context_revision")
        if set(b)!=set(keys) or any(not isinstance(b.get(k),str) or not b[k] for k in keys): return None
        return tuple(b[k] for k in keys)
    def run(self):
        self.obj=self.load_json(self.registry_path,"E11H.REGISTRY") or {}
        self.auto=self.load_json(self.automation_path,"E11H.E10") or {}
        if self.obj and self.auto: self.baseline(); self.check()
        return self.result()
    def check(self):
        domains={x.get("id"):x for x in self.obj.get("time_domains",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        obs={x.get("id"):x for x in self.obj.get("observations",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        policies={x.get("id"):x for x in self.obj.get("policies",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        leases={x.get("id"):x for x in self.obj.get("leases",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        replays={x.get("id"):x for x in self.obj.get("replay_assertions",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        decisions={x.get("id"):x for x in self.obj.get("temporal_decisions",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        e10={x.get("id"):x for x in self.auto.get("decisions",[]) if isinstance(x,dict) and isinstance(x.get("id"),str)}
        approved={}
        pair_count={}
        for r in self.obj.get("renewals",[]):
            if not isinstance(r,dict) or r.get("state")!="approved": continue
            old,new=r.get("predecessor"),r.get("successor")
            approved[(old,new)]=approved.get((old,new),0)+1
            pair_count[old]=pair_count.get(old,0)+1
        for old,n in pair_count.items():
            if n>1: self.add("error","E11H.RENEWAL.FORK","multiple approved renewal successors for one predecessor",f"lease:{old}")
        for lid,l in leases.items():
            pred=l.get("predecessor")
            if not pred: continue
            p=leases.get(pred); loc=f"lease:{lid}"
            if p is None: self.add("error","E11H.LEASE.PREDECESSOR_REF","predecessor does not resolve",loc); continue
            if (l.get("subject_kind"),l.get("subject"),l.get("domain"))!=(p.get("subject_kind"),p.get("subject"),p.get("domain")):
                self.add("error","E11H.LEASE.IDENTITY","predecessor edge changes subject or domain",loc)
            if isinstance(l.get("generation"),int) and isinstance(p.get("generation"),int) and l["generation"]!=p["generation"]+1:
                self.add("error","E11H.LEASE.GENERATION","predecessor edge generation is not +1",loc)
            if isinstance(l.get("issued_tick"),int) and isinstance(p.get("issued_tick"),int) and l["issued_tick"]<p["issued_tick"]:
                self.add("error","E11H.LEASE.BACKDATED","successor issued_tick precedes predecessor",loc)
            if isinstance(l.get("valid_until"),int) and isinstance(p.get("valid_until"),int) and l["valid_until"]<=p["valid_until"]:
                self.add("error","E11H.LEASE.EXTENSION","successor does not extend validity end",loc)
        for did,d in decisions.items():
            loc=f"decision:{did}"; p=policies.get(d.get("policy")); o=obs.get(d.get("observation"))
            if p is None or o is None: continue
            dom=domains.get(p.get("domain"))
            if d.get("state") in {"valid","grace-valid"} and (dom is None or dom.get("status")!="active"):
                self.add("error","E11H.DOMAIN.ACTIVE","positive temporal state requires active time domain",loc)
            if isinstance(o.get("tick"),int) and isinstance(o.get("uncertainty"),int) and o["uncertainty"]>o["tick"]:
                self.add("error","E11H.OBS.ORIGIN","observation uncertainty crosses below domain origin",loc)
            if p.get("require_e10_authorized"):
                up=e10.get(d.get("subject")); b=self.boundary(d)
                if up is None: self.add("error","E11H.E10.REF","E10 subject does not resolve",loc)
                elif b is None: self.add("error","E11H.E10.BOUNDARY","temporal decision requires exact e10_boundary",loc)
                else:
                    ub=(up.get("proposal_revision"),up.get("policy_revision"),up.get("context_revision"))
                    if b!=ub: self.add("error","E11H.E10.BOUNDARY","temporal decision boundary differs from E10 decision revisions",loc)
                    else: self.binding_ok+=1
            lid=d.get("lease")
            if lid:
                l=leases.get(lid); b=self.boundary(d); lb=self.boundary(l) if l else None
                if l and p.get("require_e10_authorized") and (lb is None or lb!=b): self.add("error","E11H.LEASE.BOUNDARY","lease boundary differs from temporal decision E10 boundary",loc)
                cur=l
                while cur and cur.get("predecessor"):
                    old=cur.get("predecessor"); new=cur.get("id")
                    if approved.get((old,new),0)!=1: self.add("error","E11H.RENEWAL.EVIDENCE","used successor lease lacks exactly one approved renewal edge",loc); break
                    cur=leases.get(old)
                else:
                    if l: self.chain_ok+=1
            rid=d.get("replay_assertion")
            if rid:
                r=replays.get(rid); b=self.boundary(d); rb=self.boundary(r) if r else None
                if r is not None:
                    if r.get("observation")!=d.get("observation"): self.add("error","E11H.REPLAY.OBSERVATION","replay assertion not bound to evaluation observation",loc)
                    if p.get("require_e10_authorized") and (rb is None or rb!=b): self.add("error","E11H.REPLAY.BOUNDARY","replay assertion boundary differs from temporal decision E10 boundary",loc)
                    if r.get("observation")==d.get("observation") and (not p.get("require_e10_authorized") or rb==b): self.replay_ok+=1
    def result(self):
        errs=any(f.severity=="error" for f in self.findings)
        def cap(n): return "not-evaluated" if errs or n==0 else "verified"
        return {"tool":"eigiib_temporal_hardening_check.py","tool_version":TOOL_VERSION,"standard":STANDARD,
                "structural_result":"non-conformant" if errs else "conformant","binding_result":cap(self.binding_ok),
                "renewal_chain_result":cap(self.chain_ok),"replay_binding_result":cap(self.replay_ok),
                "findings":[asdict(f) for f in sorted(self.findings)]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="."); ap.add_argument("--registry",default="conformance/temporal.json"); ap.add_argument("--automation",default="conformance/automation.json"); ap.add_argument("--json",action="store_true")
    a=ap.parse_args(); r=Checker(Path(a.root),Path(a.registry),Path(a.automation)).run(); print(json.dumps(r,indent=2,sort_keys=True)); return 1 if r["structural_result"]=="non-conformant" else 0
if __name__=="__main__": raise SystemExit(main())
