#!/usr/bin/env python3
"""EIGIIB-E11 temporal validity, freshness, leases, and replay-resistance checker.

Static by design. It never reads the host clock. All temporal conclusions are
relative to explicit observations in declared time domains.
"""
from __future__ import annotations
import argparse, json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0+E11-1.0"
MAX_OBJECTS = 100_000
VALID_E10_STATES = {"authorized", "denied", "held", "unavailable"}
TEMPORAL_STATES = {"valid", "grace-valid", "expired", "not-yet-valid", "stale", "replay-rejected", "indeterminate", "unavailable"}

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

class Checker:
    def __init__(self, root: Path, registry: Path, automation: Path | None = None):
        self.root=root.resolve(); self.registry_path=registry; self.automation_path=automation
        self.findings:list[Finding]=[]; self.obj:dict[str,Any]={}
        self.domains={}; self.sources={}; self.observations={}; self.policies={}; self.leases={}; self.renewals={}; self.replays={}; self.decisions={}
        self.e10_states:dict[str,str]={}
        self.time_verified=0; self.lease_verified=0; self.renewal_verified=0; self.replay_verified=0; self.temporal_valid=0; self.temporal_grace=0

    def add(self,severity,code,message,path=""):
        self.findings.append(Finding(severity,code,path,message))
    def has_error(self,loc):
        return any(f.severity=="error" and f.path==loc for f in self.findings)

    def safe_path(self,raw:str)->Path|None:
        if not isinstance(raw,str) or not raw:
            self.add("error","E11.PATH.INVALID","path must be non-empty",str(raw)); return None
        p=Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error","E11.PATH.ESCAPE","path escapes repository",raw); return None
        c=(self.root/p).resolve(strict=False)
        try: c.relative_to(self.root)
        except ValueError:
            self.add("error","E11.PATH.ESCAPE","resolved path escapes repository",raw); return None
        if not c.exists() or not c.is_file():
            self.add("error","E11.PATH.MISSING","file does not exist",raw); return None
        try: c.resolve(strict=True).relative_to(self.root)
        except (OSError,ValueError):
            self.add("error","E11.PATH.SYMLINK","unsafe resolved path",raw); return None
        return c

    def evidence_valid(self,ev:Any,loc:str)->bool:
        if not isinstance(ev,list) or not ev:
            self.add("error","E11.EVIDENCE.EMPTY","evidence must be non-empty array",loc); return False
        ok=True
        for item in ev:
            if isinstance(item,str):
                if not item:
                    self.add("error","E11.EVIDENCE.ITEM","evidence id must be non-empty",loc); ok=False
            elif isinstance(item,dict):
                if set(item)!={"path"} or not isinstance(item.get("path"),str) or not item["path"]:
                    self.add("error","E11.EVIDENCE.ITEM","evidence object must contain only non-empty path",loc); ok=False
                elif self.safe_path(item["path"]) is None: ok=False
            else:
                self.add("error","E11.EVIDENCE.ITEM","invalid evidence item",loc); ok=False
        return ok

    def load_json(self,rel:Path,code:str,required=True):
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
        d=self.load_json(self.registry_path,"E11.REGISTRY")
        if d is None: return False
        self.obj=d
        if d.get("standard")!=STANDARD: self.add("error","E11.STANDARD","unsupported E11 standard identifier",str(self.registry_path))
        if not isinstance(d.get("revision"),str) or not d.get("revision"): self.add("error","E11.REVISION","revision must be non-empty string",str(self.registry_path))
        arrays=["time_domains","time_sources","observations","policies","leases","renewals","replay_assertions","temporal_decisions"]
        total=0
        for k in arrays:
            v=d.get(k)
            if not isinstance(v,list): self.add("error","E11.COLLECTION",f"{k} must be array",str(self.registry_path))
            else: total+=len(v)
        if total>MAX_OBJECTS: self.add("error","E11.RESOURCE","object count exceeds checker limit")
        self.load_e10(); return True

    def load_e10(self):
        if not self.automation_path: return
        d=self.load_json(self.automation_path,"E11.E10",required=False)
        if not d: return
        for x in d.get("decisions",[]):
            if isinstance(x,dict) and isinstance(x.get("id"),str) and x.get("state") in VALID_E10_STATES:
                self.e10_states[x["id"]]=x["state"]

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
        self.domains=self.map_items("time_domains","E11.DOMAIN")
        self.sources=self.map_items("time_sources","E11.SOURCE")
        self.observations=self.map_items("observations","E11.OBS")
        self.policies=self.map_items("policies","E11.POLICY")
        self.leases=self.map_items("leases","E11.LEASE")
        self.renewals=self.map_items("renewals","E11.RENEWAL")
        self.replays=self.map_items("replay_assertions","E11.REPLAY")
        for did,d in self.domains.items():
            loc=f"domain:{did}"
            if d.get("unit") not in {"tick","second","millisecond","microsecond","nanosecond","logical"}: self.add("error","E11.DOMAIN.UNIT","invalid time-domain unit",loc)
            if d.get("ordering")!="total": self.add("error","E11.DOMAIN.ORDER","E11 reference profile requires total ordering",loc)
            if d.get("status") not in {"active","retired","unknown"}: self.add("error","E11.DOMAIN.STATUS","invalid domain status",loc)
        for sid,s in self.sources.items():
            loc=f"source:{sid}"
            if s.get("domain") not in self.domains: self.add("error","E11.SOURCE.DOMAIN_REF","unresolved time domain",loc)
            if s.get("kind") not in {"wall","monotonic","external","witnessed","logical","unknown"}: self.add("error","E11.SOURCE.KIND","invalid source kind",loc)
            if s.get("status") not in {"active","suspended","retired","unknown"}: self.add("error","E11.SOURCE.STATUS","invalid source status",loc)
        for oid,o in self.observations.items():
            loc=f"observation:{oid}"; src=self.sources.get(o.get("source"))
            if src is None: self.add("error","E11.OBS.SOURCE_REF","unresolved time source",loc)
            if not isinstance(o.get("tick"),int) or o.get("tick")<0: self.add("error","E11.OBS.TICK","tick must be non-negative integer",loc)
            if not isinstance(o.get("uncertainty"),int) or o.get("uncertainty")<0: self.add("error","E11.OBS.UNCERTAINTY","uncertainty must be non-negative integer",loc)
            self.evidence_valid(o.get("evidence",[]),loc)
        for pid,p in self.policies.items():
            loc=f"policy:{pid}"
            if not isinstance(p.get("revision"),str) or not p.get("revision"): self.add("error","E11.POLICY.REVISION","revision required",loc)
            if p.get("domain") not in self.domains: self.add("error","E11.POLICY.DOMAIN_REF","unresolved time domain",loc)
            for k in ("require_e10_authorized","require_lease","require_replay_guard","allow_grace"):
                if not isinstance(p.get(k),bool): self.add("error","E11.POLICY.BOOL",f"{k} must be boolean",loc)
            for k in ("max_observation_uncertainty","grace_ticks","max_renewal_depth"):
                if not isinstance(p.get(k),int) or p.get(k)<0: self.add("error","E11.POLICY.INT",f"{k} must be non-negative integer",loc)
            ma=p.get("max_lease_age_ticks")
            if ma is not None and (not isinstance(ma,int) or ma<0): self.add("error","E11.POLICY.AGE","max_lease_age_ticks must be null or non-negative integer",loc)
            if not p.get("allow_grace") and p.get("grace_ticks")!=0: self.add("error","E11.POLICY.GRACE","grace_ticks must be zero when grace is disabled",loc)
        for lid,l in self.leases.items():
            loc=f"lease:{lid}"
            if l.get("domain") not in self.domains: self.add("error","E11.LEASE.DOMAIN_REF","unresolved time domain",loc)
            if l.get("subject_kind") not in {"e10-decision","delegation","approval","execution","other"}: self.add("error","E11.LEASE.SUBJECT_KIND","invalid subject kind",loc)
            if not isinstance(l.get("subject"),str) or not l.get("subject"): self.add("error","E11.LEASE.SUBJECT","subject required",loc)
            for k in ("generation","issued_tick","valid_from","valid_until"):
                if not isinstance(l.get(k),int) or l.get(k)<0: self.add("error","E11.LEASE.TIME",f"{k} must be non-negative integer",loc)
            if all(isinstance(l.get(k),int) for k in ("issued_tick","valid_from","valid_until")):
                if l["valid_from"]>=l["valid_until"]: self.add("error","E11.LEASE.WINDOW","valid_from must be < valid_until",loc)
                if l["issued_tick"]>l["valid_from"]: self.add("error","E11.LEASE.ISSUED","issued_tick must be <= valid_from",loc)
            if l.get("status") not in {"active","suspended","revoked","retired","unknown"}: self.add("error","E11.LEASE.STATUS","invalid lease status",loc)
            if l.get("status")=="active": self.evidence_valid(l.get("evidence",[]),loc)
            elif "evidence" in l and l.get("evidence"): self.evidence_valid(l.get("evidence"),loc)
            if "predecessor" in l and l["predecessor"] is not None and (not isinstance(l["predecessor"],str) or not l["predecessor"]): self.add("error","E11.LEASE.PREDECESSOR","predecessor must be non-empty string or null",loc)
        seen_replay={}
        for rid,r in self.replays.items():
            loc=f"replay:{rid}"
            for k in ("namespace","token","subject"):
                if not isinstance(r.get(k),str) or not r.get(k): self.add("error","E11.REPLAY.FIELD",f"{k} required",loc)
            if r.get("state") not in {"available","consumed","replayed","unknown"}: self.add("error","E11.REPLAY.STATE","invalid replay state",loc)
            key=(r.get("namespace"),r.get("token"))
            if key in seen_replay: self.add("error","E11.REPLAY.DUPLICATE",f"duplicate namespace/token also in {seen_replay[key]}",loc)
            else: seen_replay[key]=rid
            self.evidence_valid(r.get("evidence",[]),loc)
        self.check_renewals()

    def check_renewals(self):
        for rid,r in self.renewals.items():
            loc=f"renewal:{rid}"; old=self.leases.get(r.get("predecessor")); new=self.leases.get(r.get("successor"))
            if old is None or new is None: self.add("error","E11.RENEWAL.REF","unresolved predecessor or successor lease",loc); continue
            if r.get("state") not in {"approved","rejected","unavailable"}: self.add("error","E11.RENEWAL.STATE","invalid renewal state",loc)
            if r.get("state")=="approved": self.evidence_valid(r.get("evidence",[]),loc)
            if new.get("predecessor")!=old.get("id"): self.add("error","E11.RENEWAL.PREDECESSOR","successor does not name predecessor",loc)
            if old.get("subject")!=new.get("subject") or old.get("subject_kind")!=new.get("subject_kind") or old.get("domain")!=new.get("domain"):
                self.add("error","E11.RENEWAL.IDENTITY","renewal must preserve subject kind, subject and time domain",loc)
            if isinstance(old.get("generation"),int) and isinstance(new.get("generation"),int) and new["generation"]!=old["generation"]+1:
                self.add("error","E11.RENEWAL.GENERATION","successor generation must increment by one",loc)
            if isinstance(old.get("valid_until"),int) and isinstance(new.get("valid_until"),int) and new["valid_until"]<=old["valid_until"]:
                self.add("error","E11.RENEWAL.EXTENSION","successor must extend validity end",loc)
            if not self.has_error(loc) and r.get("state")=="approved": self.renewal_verified+=1
        for lid in self.leases:
            seen=set(); cur=lid
            while cur in self.leases:
                if cur in seen:
                    self.add("error","E11.LEASE.CYCLE","lease predecessor cycle detected",f"lease:{lid}"); break
                seen.add(cur); pred=self.leases[cur].get("predecessor")
                if not pred: break
                cur=pred

    def lease_depth(self,lease:dict[str,Any],loc:str)->int|None:
        depth=0; seen=set(); cur=lease
        while cur.get("predecessor"):
            pid=cur["predecessor"]
            if pid in seen: self.add("error","E11.LEASE.CYCLE","lease predecessor cycle detected",loc); return None
            seen.add(pid); pred=self.leases.get(pid)
            if pred is None: self.add("error","E11.LEASE.PREDECESSOR_REF","unresolved lease predecessor",loc); return None
            depth+=1; cur=pred
        return depth

    def expected_state(self,d,policy,obs,lease,replay,loc):
        src=self.sources.get(obs.get("source")) if obs else None
        if obs is None or src is None or src.get("status")!="active": return "unavailable"
        if src.get("domain")!=policy.get("domain"): self.add("error","E11.DECISION.DOMAIN","observation source domain differs from policy domain",loc); return "unavailable"
        if obs.get("uncertainty",0)>policy.get("max_observation_uncertainty",0): return "indeterminate"
        if policy.get("require_e10_authorized"):
            st=self.e10_states.get(d.get("subject"))
            if st is None: self.add("error","E11.DECISION.E10_REF","subject E10 decision does not resolve",loc); return "unavailable"
            if st!="authorized": return "unavailable"
        if policy.get("require_lease") and lease is None: return "unavailable"
        if lease is not None:
            if lease.get("subject_kind")!="e10-decision" or lease.get("subject")!=d.get("subject"):
                self.add("error","E11.DECISION.LEASE_SUBJECT","lease not bound to exact E10 decision",loc); return "unavailable"
            if lease.get("domain")!=policy.get("domain"):
                self.add("error","E11.DECISION.LEASE_DOMAIN","lease domain differs from policy domain",loc); return "unavailable"
            if lease.get("status")!="active": return "unavailable"
            depth=self.lease_depth(lease,loc)
            if depth is None or depth>policy.get("max_renewal_depth",0): return "unavailable"
        if policy.get("require_replay_guard") and replay is None: return "unavailable"
        if replay is not None:
            if replay.get("subject")!=d.get("subject"):
                self.add("error","E11.DECISION.REPLAY_SUBJECT","replay assertion not bound to exact E10 decision",loc); return "unavailable"
            if replay.get("state") in {"consumed","replayed"}: return "replay-rejected"
            if replay.get("state")!="available": return "unavailable"
        if lease is None: return "valid"
        tick=obs.get("tick"); u=obs.get("uncertainty"); lo=tick-u; hi=tick+u
        vf=lease.get("valid_from"); vu=lease.get("valid_until")
        ma=policy.get("max_lease_age_ticks")
        if ma is not None:
            threshold=lease.get("issued_tick")+ma
            if lo>threshold: return "stale"
            if lo<=threshold<hi: return "indeterminate"
        if hi<vf: return "not-yet-valid"
        if lo<vf<=hi: return "indeterminate"
        if lo<vu and hi<vu: return "valid"
        if lo<vu<=hi: return "indeterminate"
        grace_end=vu+policy.get("grace_ticks",0)
        if policy.get("allow_grace") and lo>=vu and hi<grace_end: return "grace-valid"
        if policy.get("allow_grace") and lo<grace_end<=hi: return "indeterminate"
        return "expired"

    def check_decisions(self):
        self.decisions=self.map_items("temporal_decisions","E11.DECISION")
        for did,d in self.decisions.items():
            loc=f"decision:{did}"; state=d.get("state")
            if state not in TEMPORAL_STATES: self.add("error","E11.DECISION.STATE","invalid temporal decision state",loc); continue
            policy=self.policies.get(d.get("policy")); obs=self.observations.get(d.get("observation"))
            if policy is None or obs is None: self.add("error","E11.DECISION.REF","unresolved policy or observation",loc); continue
            if not isinstance(d.get("subject"),str) or not d.get("subject"): self.add("error","E11.DECISION.SUBJECT","subject required",loc); continue
            lease=self.leases.get(d.get("lease")) if d.get("lease") else None
            replay=self.replays.get(d.get("replay_assertion")) if d.get("replay_assertion") else None
            if d.get("lease") and lease is None: self.add("error","E11.DECISION.LEASE_REF","unresolved lease",loc)
            if d.get("replay_assertion") and replay is None: self.add("error","E11.DECISION.REPLAY_REF","unresolved replay assertion",loc)
            expected=self.expected_state(d,policy,obs,lease,replay,loc)
            if state!=expected: self.add("error","E11.DECISION.MISMATCH",f"declared {state} but mechanically expected {expected}",loc)
            if not self.has_error(loc):
                self.time_verified+=1
                if lease is not None: self.lease_verified+=1
                if replay is not None and replay.get("state")=="available": self.replay_verified+=1
                if state=="valid": self.temporal_valid+=1
                elif state=="grace-valid": self.temporal_grace+=1

    def result(self):
        errs=any(f.severity=="error" for f in self.findings)
        def cap(n): return "not-evaluated" if errs or n==0 else "verified"
        temporal="not-evaluated" if errs or (self.temporal_valid+self.temporal_grace)==0 else ("grace" if self.temporal_valid==0 and self.temporal_grace>0 else "verified")
        return {
            "tool":"eigiib_temporal_check.py","tool_version":TOOL_VERSION,"standard":STANDARD,"revision":self.obj.get("revision"),
            "structural_result":"non-conformant" if errs else "conformant",
            "time_observation_result":cap(self.time_verified),"lease_result":cap(self.lease_verified),"renewal_result":cap(self.renewal_verified),
            "replay_result":cap(self.replay_verified),"temporal_validity_result":temporal,
            "findings":[asdict(f) for f in sorted(self.findings)]
        }
    def run(self):
        if self.load(): self.check_base(); self.check_decisions()
        return self.result()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",nargs="?",default="."); ap.add_argument("--registry",default="conformance/temporal.json"); ap.add_argument("--automation",default="conformance/automation.json"); ap.add_argument("--json",action="store_true")
    a=ap.parse_args(); r=Checker(Path(a.root),Path(a.registry),Path(a.automation)).run(); print(json.dumps(r,indent=2,sort_keys=True)); return 1 if r["structural_result"]=="non-conformant" else 0
if __name__=="__main__": raise SystemExit(main())
