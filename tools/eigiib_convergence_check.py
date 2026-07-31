#!/usr/bin/env python3
"""EIGIIB-E8 relying-party convergence and migration-safety checker.

Static by design: no network access, no relying-party mutation, no command
execution, and no lower-layer cryptographic verification. E7 decisions are
consumed only as typed external facts when explicitly supplied.
"""
from __future__ import annotations
import argparse, json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0"
MAX_OBJECTS = 100_000

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

class Checker:
    def __init__(self, root: Path, registry: Path, recovery: Path | None = None):
        self.root=root.resolve()
        self.registry_path=registry
        self.recovery_path=recovery
        self.findings=[]
        self.obj={}
        self.parties={}
        self.migrations={}
        self.observations={}
        self.policies={}
        self.exceptions={}
        self.windows={}
        self.adoption_decisions={}
        self.e7_continuity=set()
        self.e7_transitions=set()
        self.invalid_observations=set()
        self.verified_adoption_ids=set()
        self.adoption_verified=0
        self.legacy_rejection_verified=0
        self.legacy_rejection_with_exceptions=0
        self.cutover_verified=0
        self.cutover_with_exceptions=0

    def add(self,severity,code,message,path=""):
        self.findings.append(Finding(severity,code,path,message))

    def safe_path(self, raw: str) -> Path | None:
        if not isinstance(raw,str) or not raw:
            self.add("error","E8.PATH.INVALID","path must be non-empty",str(raw)); return None
        p=Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error","E8.PATH.ESCAPE","path escapes repository",raw); return None
        c=(self.root/p).resolve(strict=False)
        try: c.relative_to(self.root)
        except ValueError:
            self.add("error","E8.PATH.ESCAPE","resolved path escapes repository",raw); return None
        if not c.exists() or not c.is_file():
            self.add("error","E8.PATH.MISSING","file does not exist",raw); return None
        try: c.resolve(strict=True).relative_to(self.root)
        except (OSError,ValueError):
            self.add("error","E8.PATH.SYMLINK","unsafe resolved path",raw); return None
        return c

    def load_json(self, rel: Path, code: str, required=True):
        p=(self.root/rel).resolve(strict=False)
        if not p.exists() and not required: return None
        safe=self.safe_path(str(rel))
        if safe is None: return None
        try: data=json.loads(safe.read_text(encoding="utf-8"))
        except (OSError,UnicodeError,json.JSONDecodeError) as exc:
            self.add("error",f"{code}.PARSE",f"cannot parse JSON: {exc}",str(rel)); return None
        if not isinstance(data,dict):
            self.add("error",f"{code}.TYPE","registry root must be object",str(rel)); return None
        return data

    def load(self):
        d=self.load_json(self.registry_path,"E8.REGISTRY")
        if d is None: return False
        self.obj=d
        if d.get("standard") != STANDARD:
            self.add("error","E8.STANDARD","unsupported E8 standard identifier",str(self.registry_path))
        if not isinstance(d.get("revision"),str) or not d.get("revision"):
            self.add("error","E8.REVISION","revision must be non-empty string",str(self.registry_path))
        arrays=["relying_parties","migrations","observations","compatibility_windows","policies","exceptions","adoption_decisions","cutover_decisions"]
        total=0
        for k in arrays:
            v=d.get(k)
            if not isinstance(v,list): self.add("error","E8.COLLECTION",f"{k} must be array",str(self.registry_path))
            else: total+=len(v)
        if total>MAX_OBJECTS: self.add("error","E8.RESOURCE","object count exceeds checker limit")
        self.load_recovery()
        return True

    def load_recovery(self):
        if not self.recovery_path: return
        d=self.load_json(self.recovery_path,"E8.E7",required=False)
        if not d: return
        for x in d.get("decisions",[]):
            if isinstance(x,dict) and x.get("state") in {"continuity-established","closed"} and isinstance(x.get("id"),str):
                self.e7_continuity.add(x["id"])
        for x in d.get("transitions",[]):
            if isinstance(x,dict) and x.get("status")=="verified" and isinstance(x.get("id"),str):
                self.e7_transitions.add(x["id"])

    def map_items(self,key,code):
        out={}
        for i,item in enumerate(self.obj.get(key,[])):
            loc=f"{self.registry_path}#/{key}/{i}"
            if not isinstance(item,dict):
                self.add("error",f"{code}.TYPE","item must be object",loc); continue
            iid=item.get("id")
            if not isinstance(iid,str) or not iid:
                self.add("error",f"{code}.ID","item requires non-empty id",loc); continue
            if iid in out: self.add("error",f"{code}.DUPLICATE",f"duplicate id: {iid}",loc)
            out[iid]=item
        return out

    def check_base(self):
        self.parties=self.map_items("relying_parties","E8.PARTY")
        self.migrations=self.map_items("migrations","E8.MIGRATION")
        self.observations=self.map_items("observations","E8.OBS")
        self.windows=self.map_items("compatibility_windows","E8.WINDOW")
        self.policies=self.map_items("policies","E8.POLICY")
        self.exceptions=self.map_items("exceptions","E8.EXCEPTION")
        for pid,p in self.parties.items():
            if p.get("status") not in {"active","retired","unknown"}:
                self.add("error","E8.PARTY.STATUS","invalid party status",f"party:{pid}")
            if not isinstance(p.get("required"),bool):
                self.add("error","E8.PARTY.REQUIRED","required must be boolean",f"party:{pid}")
            for k in ("domain","class"):
                if not isinstance(p.get(k),str) or not p.get(k):
                    self.add("error","E8.PARTY.GROUP",f"{k} must be non-empty string",f"party:{pid}")
        for mid,m in self.migrations.items():
            a,b=m.get("from_epoch"),m.get("to_epoch")
            if not isinstance(a,int) or not isinstance(b,int) or a<0 or b<=a:
                self.add("error","E8.MIGRATION.EPOCH","migration must advance epoch",f"migration:{mid}")
            if m.get("status") not in {"planned","in-progress","cutover","closed","aborted"}:
                self.add("error","E8.MIGRATION.STATUS","invalid migration status",f"migration:{mid}")
            if m.get("e7_transition") is not None and m.get("e7_transition") not in self.e7_transitions:
                self.add("error","E8.MIGRATION.E7_TRANSITION","declared E7 transition is absent or not verified",f"migration:{mid}")
        for oid,o in self.observations.items():
            loc=f"observation:{oid}"
            if o.get("migration") not in self.migrations: self.add("error","E8.OBS.MIGRATION","unresolved migration",loc)
            if o.get("party") not in self.parties: self.add("error","E8.OBS.PARTY","unresolved relying party",loc)
            if o.get("phase") not in {"pre-cutover","cutover","post-cutover"}: self.add("error","E8.OBS.PHASE","invalid phase",loc)
            for k in ("new_state","old_state"):
                if o.get(k) not in {"accepted","rejected","unknown","unavailable","not-applicable"}:
                    self.add("error","E8.OBS.STATE",f"invalid {k}",loc)
            ev=o.get("evidence",[])
            if not isinstance(ev,list): self.add("error","E8.OBS.EVIDENCE","evidence must be array",loc)
            for e in ev if isinstance(ev,list) else []:
                if isinstance(e,dict) and "path" in e:
                    if self.safe_path(e["path"]) is None:
                        self.invalid_observations.add(oid)
                elif not isinstance(e,(str,dict)):
                    self.add("error","E8.OBS.EVIDENCE","invalid evidence item",loc)
                    self.invalid_observations.add(oid)
        for wid,w in self.windows.items():
            loc=f"window:{wid}"
            if w.get("migration") not in self.migrations: self.add("error","E8.WINDOW.MIGRATION","unresolved migration",loc)
            if w.get("state") not in {"planned","open","closed","expired"}: self.add("error","E8.WINDOW.STATE","invalid window state",loc)
            if not isinstance(w.get("allow_old"),bool): self.add("error","E8.WINDOW.ALLOW_OLD","allow_old must be boolean",loc)
            if w.get("state")=="closed" and w.get("allow_old") is True:
                self.add("error","E8.WINDOW.CLOSED_ALLOWS_OLD","closed window cannot allow old state",loc)
        for pid,p in self.policies.items():
            loc=f"policy:{pid}"
            if not isinstance(p.get("minimum"),int) or p.get("minimum")<0: self.add("error","E8.POLICY.MINIMUM","minimum must be non-negative integer",loc)
            if p.get("distinct_by") not in {"party","domain","class"}: self.add("error","E8.POLICY.DISTINCT","invalid distinct_by",loc)
            for k in ("require_old_rejected","require_all_required_parties","allow_exceptions"):
                if not isinstance(p.get(k),bool): self.add("error","E8.POLICY.BOOL",f"{k} must be boolean",loc)
        for xid,x in self.exceptions.items():
            loc=f"exception:{xid}"
            if x.get("migration") not in self.migrations: self.add("error","E8.EXCEPTION.MIGRATION","unresolved migration",loc)
            if x.get("party") not in self.parties: self.add("error","E8.EXCEPTION.PARTY","unresolved party",loc)
            if x.get("disposition") not in {"temporary","permanent","not-applicable"}: self.add("error","E8.EXCEPTION.DISPOSITION","invalid disposition",loc)
            if not isinstance(x.get("reason"),str) or not x.get("reason"): self.add("error","E8.EXCEPTION.REASON","reason required",loc)

    def satisfying_observation(self,o,policy):
        ev=o.get("evidence")
        if o.get("id") in self.invalid_observations:
            return False
        if o.get("new_state")!="accepted" or not isinstance(ev,list) or not ev:
            return False
        if policy.get("require_old_rejected") and o.get("old_state")!="rejected":
            return False
        return True

    def check_adoption(self):
        self.adoption_decisions=self.map_items("adoption_decisions","E8.ADOPTION")
        for did,d in self.adoption_decisions.items():
            loc=f"adoption:{did}"
            m=self.migrations.get(d.get("migration")); p=self.policies.get(d.get("policy"))
            if m is None or p is None:
                self.add("error","E8.ADOPTION.REF","unresolved migration or policy",loc); continue
            state=d.get("state")
            if state not in {"converged","converged-with-exceptions","partial","stalled","unavailable"}:
                self.add("error","E8.ADOPTION.STATE","invalid adoption decision state",loc); continue
            refs=d.get("observations",[])
            if not isinstance(refs,list):
                self.add("error","E8.ADOPTION.OBS","observations must be array",loc); continue
            selected=[]
            for r in refs:
                o=self.observations.get(r)
                if o is None or o.get("migration")!=d.get("migration"):
                    self.add("error","E8.ADOPTION.OBS","invalid observation reference",loc); continue
                selected.append(o)
            if state not in {"converged","converged-with-exceptions"}: continue
            if p.get("minimum",0) < 1:
                self.add("error","E8.ADOPTION.ZERO_MINIMUM","positive convergence requires minimum >= 1",loc)
            good=[o for o in selected if self.satisfying_observation(o,p)]
            distinct_by=p.get("distinct_by")
            values=set()
            for o in good:
                party=self.parties.get(o.get("party"),{})
                values.add(o.get("party") if distinct_by=="party" else party.get(distinct_by))
            if len(values) < p.get("minimum",0):
                self.add("error","E8.ADOPTION.QUORUM",f"adoption quorum not met: {len(values)} < {p.get('minimum')}",loc)
            domains={self.parties.get(o.get("party"),{}).get("domain") for o in good}
            classes={self.parties.get(o.get("party"),{}).get("class") for o in good}
            reqd=p.get("required_domains",[])
            reqc=p.get("required_classes",[])
            if not isinstance(reqd,list) or any(x not in domains for x in reqd): self.add("error","E8.ADOPTION.DOMAINS","required domains not covered",loc)
            if not isinstance(reqc,list) or any(x not in classes for x in reqc): self.add("error","E8.ADOPTION.CLASSES","required classes not covered",loc)
            exception_refs=d.get("exceptions",[])
            if not isinstance(exception_refs,list):
                self.add("error","E8.ADOPTION.EXCEPTIONS","exceptions must be array",loc); exception_refs=[]
            ex_parties=set()
            for r in exception_refs:
                x=self.exceptions.get(r)
                if x is None or x.get("migration")!=d.get("migration"):
                    self.add("error","E8.ADOPTION.EXCEPTION_REF","invalid exception reference",loc); continue
                ex_parties.add(x.get("party"))
            required={pid for pid,x in self.parties.items() if x.get("required") and x.get("status")=="active"}
            observed_good={o.get("party") for o in good}
            missing=required-observed_good
            if p.get("require_all_required_parties"):
                uncovered=missing-ex_parties
                if uncovered: self.add("error","E8.ADOPTION.REQUIRED_PARTIES",f"required parties not covered: {sorted(uncovered)}",loc)
            if state=="converged":
                if exception_refs: self.add("error","E8.ADOPTION.EXPLICIT_EXCEPTION_STATE","converged cannot rely on exceptions",loc)
                if p.get("require_all_required_parties") and missing:
                    self.add("error","E8.ADOPTION.EXPLICIT_EXCEPTION_STATE","converged requires all required parties directly observed",loc)
            else:
                if not p.get("allow_exceptions"):
                    self.add("error","E8.ADOPTION.EXCEPTIONS_NOT_ALLOWED","policy does not allow exceptions",loc)
                if not exception_refs:
                    self.add("error","E8.ADOPTION.EXCEPTIONS_REQUIRED","converged-with-exceptions requires explicit exceptions",loc)
                if p.get("require_all_required_parties") and missing != ex_parties & required:
                    self.add("error","E8.ADOPTION.EXCEPTION_COVERAGE","exceptions must exactly expose uncovered required parties",loc)
            if not any(f.severity=="error" and f.path==loc for f in self.findings):
                self.adoption_verified += 1
                self.verified_adoption_ids.add(did)
                if p.get("require_old_rejected"):
                    if state=="converged":
                        self.legacy_rejection_verified += 1
                    else:
                        self.legacy_rejection_with_exceptions += 1

    def check_cutover(self):
        cuts=self.map_items("cutover_decisions","E8.CUTOVER")
        for cid,c in cuts.items():
            loc=f"cutover:{cid}"
            if c.get("state")!="verified":
                self.add("error","E8.CUTOVER.STATE","reference cutover state must be verified",loc); continue
            m=self.migrations.get(c.get("migration"))
            a=self.adoption_decisions.get(c.get("adoption_decision"))
            w=self.windows.get(c.get("compatibility_window"))
            if m is None or a is None or w is None:
                self.add("error","E8.CUTOVER.REF","unresolved migration/adoption/window",loc); continue
            if a.get("migration")!=c.get("migration") or w.get("migration")!=c.get("migration"):
                self.add("error","E8.CUTOVER.MIGRATION","cutover references cross-migration object",loc)
            if m.get("status") not in {"cutover","closed"}:
                self.add("error","E8.CUTOVER.MIGRATION_STATE","migration must be cutover or closed",loc)
            if a.get("state") not in {"converged","converged-with-exceptions"}:
                self.add("error","E8.CUTOVER.ADOPTION","cutover requires converged adoption decision",loc)
            if c.get("adoption_decision") not in self.verified_adoption_ids:
                self.add("error","E8.CUTOVER.ADOPTION_UNVERIFIED","cutover requires mechanically verified adoption decision",loc)
            if w.get("state")!="closed" or w.get("allow_old") is not False:
                self.add("error","E8.CUTOVER.WINDOW","cutover requires closed window with old state disabled",loc)
            if c.get("require_e7_continuity"):
                if c.get("e7_decision") not in self.e7_continuity:
                    self.add("error","E8.CUTOVER.E7","required E7 continuity decision absent",loc)
            if not any(f.severity=="error" and f.path==loc for f in self.findings):
                if a.get("state")=="converged":
                    self.cutover_verified += 1
                else:
                    self.cutover_with_exceptions += 1

    def run(self):
        if self.load():
            self.check_base()
            self.check_adoption()
            self.check_cutover()
        findings=sorted(self.findings,key=lambda f:(f.severity,f.code,f.path,f.message))
        errors=sum(f.severity=="error" for f in findings)
        stale=sum(1 for o in self.observations.values() if o.get("phase")=="post-cutover" and o.get("old_state")=="accepted")
        return {
            "tool":"eigiib-convergence-check",
            "tool_version":TOOL_VERSION,
            "standard":STANDARD,
            "revision":self.obj.get("revision","unknown"),
            "structural_result":"non-conformant" if errors else "conformant",
            "adoption_result":"verified" if self.adoption_verified else "not-evaluated",
            "legacy_rejection_result":"verified" if self.legacy_rejection_verified else ("verified-with-exceptions" if self.legacy_rejection_with_exceptions else "not-evaluated"),
            "cutover_result":"verified" if self.cutover_verified else ("verified-with-exceptions" if self.cutover_with_exceptions else "not-evaluated"),
            "stale_acceptance_observations":stale,
            "findings":[asdict(f) for f in findings],
        }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("root",nargs="?",default=".")
    ap.add_argument("--registry",default="conformance/convergence.json")
    ap.add_argument("--recovery",default="conformance/recovery.json")
    ap.add_argument("--json",action="store_true")
    args=ap.parse_args()
    r=Checker(Path(args.root),Path(args.registry),Path(args.recovery)).run()
    print(json.dumps(r,indent=2,sort_keys=True) if args.json else r["structural_result"])
    return 1 if r["structural_result"]=="non-conformant" else 0

if __name__=="__main__":
    raise SystemExit(main())
