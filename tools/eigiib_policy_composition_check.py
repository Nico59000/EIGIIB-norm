#!/usr/bin/env python3
"""Static EIGIIB-E13 checker for multi-policy composition, conflicts and obligations."""
from __future__ import annotations
import argparse, json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0+E12-1.0+E13-1.0"

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

class Checker:
    def __init__(self, root: Path, registry: Path, automation: Path):
        self.root=root.resolve(); self.registry_path=registry; self.automation_path=automation
        self.findings:list[Finding]=[]
        self.valid_requests:set[str]=set()
        self.valid_exceptions:set[str]=set()
        self.composed_count=0; self.conflict_count=0; self.residual_count=0

    def add(self,s,c,m,p=""): self.findings.append(Finding(s,c,p,m))
    def has_error(self, loc): return any(f.severity=="error" and f.path==loc for f in self.findings)

    def confined(self, rel:Path, code:str, must_exist=False):
        if rel.is_absolute():
            self.add("error",f"{code}.PATH","path must be repository-relative",str(rel)); return None
        p=(self.root/rel).resolve(strict=False)
        try: p.relative_to(self.root)
        except ValueError:
            self.add("error",f"{code}.PATH","path escapes repository",str(rel)); return None
        if must_exist and (not p.exists() or not p.is_file()):
            self.add("error",f"{code}.MISSING","referenced file missing",str(rel)); return None
        return p

    def load_json(self, rel:Path, code:str):
        p=self.confined(rel,code,True)
        if p is None: return None
        try: obj=json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            self.add("error",f"{code}.PARSE",str(e),str(rel)); return None
        if not isinstance(obj,dict):
            self.add("error",f"{code}.TYPE","JSON root must be object",str(rel)); return None
        return obj

    def map_items(self,obj,key,code):
        xs=obj.get(key,[])
        if not isinstance(xs,list):
            self.add("error",f"{code}.TYPE",f"{key} must be array",key); return {}
        out={}
        for i,x in enumerate(xs):
            loc=f"{key}[{i}]"
            if not isinstance(x,dict):
                self.add("error",f"{code}.ITEM","item must be object",loc); continue
            ident=x.get("id")
            if not isinstance(ident,str) or not ident:
                self.add("error",f"{code}.ID","id must be non-empty string",loc); continue
            if ident in out:
                self.add("error",f"{code}.DUPLICATE",f"duplicate id {ident}",loc); continue
            out[ident]=x
        return out

    def evidence_valid(self, ev, loc, code):
        if not isinstance(ev,list) or not ev:
            self.add("error",code,"material evidence array required",loc); return False
        ok=True
        for x in ev:
            if isinstance(x,str) and x:
                continue
            if isinstance(x,dict) and set(x)=={"path"} and isinstance(x.get("path"),str) and x["path"]:
                if self.confined(Path(x["path"]),code,True) is None: ok=False
            else:
                self.add("error",code,"evidence item must be non-empty id or confined path object",loc); ok=False
        return ok

    def check_profiles(self):
        algorithms={"all-authorized","deny-overrides","permit-overrides","priority-order"}
        for pid,p in self.profiles.items():
            loc=f"profile:{pid}"
            if not isinstance(p.get("revision"),str) or not p["revision"]:
                self.add("error","E13.PROFILE.REVISION","revision must be non-empty string",loc)
            alg=p.get("algorithm")
            if alg not in algorithms: self.add("error","E13.PROFILE.ALGORITHM","unsupported composition algorithm",loc)
            members=p.get("members")
            if not isinstance(members,list) or len(members)<2:
                self.add("error","E13.PROFILE.MEMBERS","composition requires at least two policy members",loc); continue
            seen=set(); required=0; priorities=[]
            for i,m in enumerate(members):
                if not isinstance(m,dict):
                    self.add("error","E13.PROFILE.MEMBER","member must be object",loc); continue
                pol=m.get("policy")
                if not isinstance(pol,str) or pol not in self.e10_policies:
                    self.add("error","E13.PROFILE.POLICY_REF","member E10 policy does not resolve",loc)
                if pol in seen: self.add("error","E13.PROFILE.POLICY_DUPLICATE","policy appears more than once",loc)
                seen.add(pol)
                if not isinstance(m.get("required"),bool):
                    self.add("error","E13.PROFILE.REQUIRED","member required must be boolean",loc)
                elif m["required"]: required+=1
                if alg=="priority-order":
                    pr=m.get("priority")
                    if not isinstance(pr,int) or isinstance(pr,bool):
                        self.add("error","E13.PROFILE.PRIORITY","priority-order requires integer priority for every member",loc)
                    else: priorities.append(pr)
                elif "priority" in m:
                    self.add("error","E13.PROFILE.PRIORITY_UNUSED","priority is only valid for priority-order",loc)
            if required==0: self.add("error","E13.PROFILE.REQUIRED_EMPTY","at least one policy member must be required",loc)
            if alg=="priority-order" and len(priorities)!=len(set(priorities)):
                self.add("error","E13.PROFILE.PRIORITY_DUPLICATE","priority-order priorities must be unique",loc)
            if not isinstance(p.get("allow_obligation_waivers"),bool):
                self.add("error","E13.PROFILE.WAIVER_FLAG","allow_obligation_waivers must be boolean",loc)

    def member_map(self, profile):
        return {m.get("policy"):m for m in profile.get("members",[]) if isinstance(m,dict) and isinstance(m.get("policy"),str)}

    def check_requests(self):
        for rid,r in self.requests.items():
            loc=f"request:{rid}"
            profile=self.profiles.get(r.get("profile"))
            if profile is None:
                self.add("error","E13.REQUEST.PROFILE","composition profile does not resolve",loc); continue
            for k in ("revision","action","scope","target","actor","requested_executor","context","context_revision"):
                if not isinstance(r.get(k),str) or not r[k]:
                    self.add("error","E13.REQUEST.FIELD",f"{k} must be non-empty string",loc)
            ds=r.get("decisions")
            if not isinstance(ds,list) or not ds or any(not isinstance(x,str) or not x for x in ds) or len(ds)!=len(set(ds)):
                self.add("error","E13.REQUEST.DECISIONS","decisions must be non-empty unique id array",loc); continue
            members=self.member_map(profile)
            by_policy={}
            for did in ds:
                d=self.e10_decisions.get(did)
                if d is None:
                    self.add("error","E13.REQUEST.DECISION_REF",f"E10 decision does not resolve: {did}",loc); continue
                pol=d.get("policy")
                if pol not in members:
                    self.add("error","E13.REQUEST.POLICY_MEMBER","E10 decision policy is not in composition profile",loc); continue
                if pol in by_policy:
                    self.add("error","E13.REQUEST.POLICY_DUPLICATE","more than one E10 decision selected for one policy",loc)
                by_policy[pol]=d
                proposal=self.e10_proposals.get(d.get("proposal"))
                context=self.e10_contexts.get(d.get("context"))
                if proposal is None or context is None:
                    self.add("error","E13.REQUEST.UPSTREAM_REF","E10 proposal/context does not resolve",loc); continue
                if proposal.get("policy")!=pol or proposal.get("context")!=r.get("context") or d.get("context")!=r.get("context"):
                    self.add("error","E13.REQUEST.UPSTREAM_BOUNDARY","proposal/decision policy or context differs from request",loc)
                for k in ("action","scope","target","actor","requested_executor"):
                    if proposal.get(k)!=r.get(k):
                        self.add("error","E13.REQUEST.SUBJECT_BINDING",f"E10 proposal {k} differs from composition request",loc)
                if d.get("proposal_revision")!=proposal.get("revision") or d.get("policy_revision")!=self.e10_policies.get(pol,{}).get("revision"):
                    self.add("error","E13.REQUEST.REVISION_BINDING","E10 decision revision boundary is stale",loc)
                if context.get("revision")!=r.get("context_revision") or d.get("context_revision")!=r.get("context_revision"):
                    self.add("error","E13.REQUEST.CONTEXT_REVISION","E10 context revision differs from request",loc)
            if not self.has_error(loc): self.valid_requests.add(rid)

    def check_obligation_definitions(self):
        phases={"pre-decision","pre-commit","post-commit","audit"}
        triggers={"authorized","denied","always"}
        for oid,o in self.obligation_defs.items():
            loc=f"obligation:{oid}"
            p=self.profiles.get(o.get("profile"))
            if p is None: self.add("error","E13.OBLIGATION.PROFILE","profile does not resolve",loc); continue
            if o.get("source_policy") not in self.member_map(p):
                self.add("error","E13.OBLIGATION.POLICY","source_policy is not a member of profile",loc)
            if o.get("phase") not in phases: self.add("error","E13.OBLIGATION.PHASE","invalid obligation phase",loc)
            if o.get("trigger") not in triggers: self.add("error","E13.OBLIGATION.TRIGGER","invalid obligation trigger",loc)
            for k in ("mandatory","waivable"):
                if not isinstance(o.get(k),bool): self.add("error","E13.OBLIGATION.FLAG",f"{k} must be boolean",loc)

    def check_exceptions(self):
        active_for={}
        for xid,x in self.exceptions.items():
            loc=f"exception:{xid}"
            if x.get("kind")!="obligation-waiver":
                self.add("error","E13.EXCEPTION.KIND","only obligation-waiver is defined by E13 baseline",loc)
            if x.get("state") not in {"active","retired","contested","unavailable"}:
                self.add("error","E13.EXCEPTION.STATE","invalid exception state",loc)
            request=self.requests.get(x.get("request")); obligation=self.obligation_defs.get(x.get("obligation"))
            if request is None or obligation is None:
                self.add("error","E13.EXCEPTION.REF","request/obligation does not resolve",loc); continue
            profile=self.profiles.get(request.get("profile"),{})
            if obligation.get("profile")!=request.get("profile"):
                self.add("error","E13.EXCEPTION.PROFILE","obligation belongs to another profile",loc)
            if x.get("state")!="active": continue
            if not profile.get("allow_obligation_waivers") or not obligation.get("waivable"):
                self.add("error","E13.EXCEPTION.NOT_ALLOWED","profile/obligation does not permit waiver",loc)
            d=self.e10_decisions.get(x.get("e10_decision"))
            if d is None or d.get("state")!="authorized":
                self.add("error","E13.EXCEPTION.AUTHORIZATION","active waiver requires E10 authorized decision",loc)
            else:
                prop=self.e10_proposals.get(d.get("proposal"))
                if prop is None or prop.get("action")!="eigiib:e13:waive-obligation" or prop.get("target")!=x.get("obligation"):
                    self.add("error","E13.EXCEPTION.BINDING","waiver authorization proposal must target exact obligation",loc)
            self.evidence_valid(x.get("evidence"),loc,"E13.EXCEPTION.EVIDENCE")
            key=(x.get("request"),x.get("obligation"))
            active_for[key]=active_for.get(key,0)+1
            if not self.has_error(loc): self.valid_exceptions.add(xid)
        for key,n in active_for.items():
            if n>1: self.add("error","E13.EXCEPTION.MULTIPLE","multiple active waivers for one request/obligation",f"request:{key[0]}")

    def check_evaluations(self):
        states={"satisfied","pending","failed","waived","unavailable"}
        self.eval_by_key={}
        for eid,e in self.evaluations.items():
            loc=f"obligation_evaluation:{eid}"
            if e.get("state") not in states: self.add("error","E13.EVAL.STATE","invalid obligation evaluation state",loc)
            req=self.requests.get(e.get("request")); ob=self.obligation_defs.get(e.get("obligation"))
            if req is None or ob is None:
                self.add("error","E13.EVAL.REF","request/obligation does not resolve",loc); continue
            if ob.get("profile")!=req.get("profile"):
                self.add("error","E13.EVAL.PROFILE","obligation belongs to another profile",loc)
            key=(e.get("request"),e.get("obligation"))
            if key in self.eval_by_key: self.add("error","E13.EVAL.DUPLICATE","duplicate evaluation for request/obligation",loc)
            self.eval_by_key[key]=e
            if e.get("state") in {"satisfied","failed"}:
                self.evidence_valid(e.get("evidence"),loc,"E13.EVAL.EVIDENCE")
            if e.get("state")=="waived":
                xid=e.get("exception")
                if xid not in self.valid_exceptions:
                    self.add("error","E13.EVAL.WAIVER","waived evaluation lacks valid active exception",loc)
                elif self.exceptions[xid].get("request")!=e.get("request") or self.exceptions[xid].get("obligation")!=e.get("obligation"):
                    self.add("error","E13.EVAL.WAIVER_BINDING","exception does not bind this request/obligation",loc)

    def active_obligations(self, request):
        profile_id=request.get("profile")
        selected={}
        for did in request.get("decisions",[]):
            d=self.e10_decisions.get(did)
            if d: selected[d.get("policy")]=d.get("state")
        active=[]
        for oid,o in self.obligation_defs.items():
            if o.get("profile")!=profile_id: continue
            state=selected.get(o.get("source_policy"))
            trig=o.get("trigger")
            if trig=="always" and state is not None: active.append((oid,o))
            elif trig==state: active.append((oid,o))
        return active

    def derive_base(self, request, profile):
        members=self.member_map(profile)
        selected={}
        for did in request.get("decisions",[]):
            d=self.e10_decisions.get(did)
            if d and d.get("policy") in members: selected[d["policy"]]=d
        if any(m.get("required") and p not in selected for p,m in members.items()):
            return "held"
        states=[d.get("state") for d in selected.values()]
        if not states: return "held"
        if all(s=="unavailable" for s in states): return "unavailable"
        alg=profile.get("algorithm")
        if alg=="all-authorized":
            if "denied" in states: return "denied"
            if any(s in {"held","unavailable"} for s in states): return "held"
            return "permitted" if all(s=="authorized" for s in states) else "held"
        if alg=="deny-overrides":
            if "denied" in states: return "denied"
            if any(s in {"held","unavailable"} for s in states): return "held"
            return "permitted" if "authorized" in states else "held"
        if alg=="permit-overrides":
            if "authorized" in states: return "permitted"
            if "denied" in states: return "denied"
            return "held" if "held" in states else "unavailable"
        if alg=="priority-order":
            ordered=sorted(((members[p]["priority"], d) for p,d in selected.items()), key=lambda z:z[0])
            if not ordered: return "held"
            s=ordered[0][1].get("state")
            return {"authorized":"permitted","denied":"denied","held":"held","unavailable":"unavailable"}.get(s,"held")
        return "held"

    def check_decisions(self):
        states={"permitted","denied","held","unavailable"}
        seen_req={}
        for did,d in self.decisions.items():
            loc=f"decision:{did}"
            if d.get("state") not in states: self.add("error","E13.DECISION.STATE","invalid composed decision state",loc); continue
            req=self.requests.get(d.get("request")); profile=self.profiles.get(d.get("profile"))
            if req is None or profile is None:
                self.add("error","E13.DECISION.REF","request/profile does not resolve",loc); continue
            if req.get("profile")!=d.get("profile"):
                self.add("error","E13.DECISION.PROFILE","decision profile differs from request profile",loc)
            if d.get("request") in seen_req:
                self.add("error","E13.DECISION.DUPLICATE_REQUEST","multiple composed decisions for one request",loc)
            seen_req[d.get("request")]=did
            if d.get("request") not in self.valid_requests:
                self.add("error","E13.DECISION.REQUEST_INVALID","decision requires structurally valid request",loc); continue

            selected=[self.e10_decisions[x] for x in req.get("decisions",[]) if x in self.e10_decisions]
            if any(x.get("state")=="authorized" for x in selected) and any(x.get("state")=="denied" for x in selected):
                self.conflict_count += 1

            expected=self.derive_base(req,profile)
            active=self.active_obligations(req)
            blockers=0; residual=0
            for oid,o in active:
                ev=self.eval_by_key.get((req.get("id"),oid))
                if o.get("mandatory") and o.get("phase")=="pre-decision":
                    if ev is None or ev.get("state") not in {"satisfied","waived"}:
                        blockers+=1
                elif o.get("mandatory") and o.get("phase")!="pre-decision":
                    if ev is None or ev.get("state") not in {"satisfied","waived"}:
                        residual+=1
            if expected=="permitted" and blockers: expected="held"
            self.residual_count += residual
            if d.get("state")!=expected:
                self.add("error","E13.DECISION.DERIVATION",f"declared state {d.get('state')} differs from mechanically derived {expected}",loc)
            if not self.has_error(loc) and d.get("state")=="permitted": self.composed_count += 1

    def run(self):
        obj=self.load_json(self.registry_path,"E13.REGISTRY") or {}
        auto=self.load_json(self.automation_path,"E13.E10") or {}
        if obj.get("standard") not in {None,STANDARD}:
            self.add("error","E13.STANDARD",f"standard must be {STANDARD}",str(self.registry_path))
        self.profiles=self.map_items(obj,"composition_profiles","E13.PROFILE")
        self.requests=self.map_items(obj,"requests","E13.REQUEST")
        self.obligation_defs=self.map_items(obj,"obligation_definitions","E13.OBLIGATION")
        self.evaluations=self.map_items(obj,"obligation_evaluations","E13.EVAL")
        self.exceptions=self.map_items(obj,"exceptions","E13.EXCEPTION")
        self.decisions=self.map_items(obj,"decisions","E13.DECISION")
        self.e10_policies=self.map_items(auto,"policies","E13.UPSTREAM.POLICY")
        self.e10_contexts=self.map_items(auto,"contexts","E13.UPSTREAM.CONTEXT")
        self.e10_proposals=self.map_items(auto,"proposals","E13.UPSTREAM.PROPOSAL")
        self.e10_decisions=self.map_items(auto,"decisions","E13.UPSTREAM.DECISION")
        self.check_profiles(); self.check_requests(); self.check_obligation_definitions()
        self.check_exceptions(); self.check_evaluations(); self.check_decisions()
        failed=any(f.severity=="error" for f in self.findings)
        def cap(n): return "not-evaluated" if failed or n==0 else "verified"
        return {
            "tool":"eigiib-policy-composition-check",
            "tool_version":TOOL_VERSION,
            "standard":STANDARD,
            "structural_result":"non-conformant" if failed else "conformant",
            "composition_result":cap(self.composed_count),
            "conflict_observation_result":cap(self.conflict_count),
            "residual_obligation_result":cap(self.residual_count),
            "findings":[asdict(f) for f in sorted(self.findings)],
        }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default=".")
    ap.add_argument("--registry",default="conformance/policy-composition.json")
    ap.add_argument("--automation",default="conformance/automation.json")
    ap.add_argument("--json",action="store_true")
    a=ap.parse_args(); r=Checker(Path(a.root),Path(a.registry),Path(a.automation)).run()
    print(json.dumps(r,indent=2,sort_keys=True))
    return 1 if r["structural_result"]=="non-conformant" else 0

if __name__=="__main__": raise SystemExit(main())
