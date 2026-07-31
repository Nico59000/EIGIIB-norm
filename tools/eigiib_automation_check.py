#!/usr/bin/env python3
"""EIGIIB-E10 policy-safe automation, delegated execution, and accountability checker.

Static by design: no network access, command execution, approval creation, or
trust/configuration mutation. E9 decisions are consumed only as typed external
facts when explicitly supplied.
"""
from __future__ import annotations
import argparse, json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

TOOL_VERSION = "0.1.0"
STANDARD = "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0+E4-1.0+E5-1.0+E6-1.0+E7-1.0+E8-1.0+E9-1.0+E10-1.0"
MAX_OBJECTS = 100_000

@dataclass(order=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str

class Checker:
    def __init__(self, root: Path, registry: Path, degraded: Path | None = None):
        self.root = root.resolve()
        self.registry_path = registry
        self.degraded_path = degraded
        self.findings: list[Finding] = []
        self.obj: dict[str,Any] = {}
        self.principals={}; self.delegations={}; self.contexts={}; self.policies={}
        self.proposals={}; self.approvals={}; self.decisions={}; self.executions={}
        self.effects={}; self.traces={}
        self.e9_states: dict[str,str] = {}
        self.valid_authorizations: set[str] = set()
        self.valid_executions: set[str] = set()
        self.valid_effects: set[str] = set()
        self.delegation_verified = 0
        self.authorization_verified = 0
        self.execution_verified = 0
        self.effect_verified = 0
        self.accountability_verified = 0

    def add(self,severity,code,message,path=""):
        self.findings.append(Finding(severity,code,path,message))

    def has_error(self, loc: str) -> bool:
        return any(f.severity=="error" and f.path==loc for f in self.findings)

    def safe_path(self, raw: str) -> Path | None:
        if not isinstance(raw,str) or not raw:
            self.add("error","E10.PATH.INVALID","path must be non-empty",str(raw)); return None
        p=Path(raw)
        if p.is_absolute() or ".." in p.parts:
            self.add("error","E10.PATH.ESCAPE","path escapes repository",raw); return None
        c=(self.root/p).resolve(strict=False)
        try: c.relative_to(self.root)
        except ValueError:
            self.add("error","E10.PATH.ESCAPE","resolved path escapes repository",raw); return None
        if not c.exists() or not c.is_file():
            self.add("error","E10.PATH.MISSING","file does not exist",raw); return None
        try: c.resolve(strict=True).relative_to(self.root)
        except (OSError,ValueError):
            self.add("error","E10.PATH.SYMLINK","unsafe resolved path",raw); return None
        return c

    def evidence_valid(self, ev: Any, loc: str) -> bool:
        if not isinstance(ev,list) or not ev:
            self.add("error","E10.EVIDENCE.EMPTY","evidence must be non-empty array",loc); return False
        ok=True
        for item in ev:
            if isinstance(item,str):
                if not item:
                    self.add("error","E10.EVIDENCE.ITEM","evidence id must be non-empty",loc); ok=False
            elif isinstance(item,dict):
                if set(item) != {"path"} or not isinstance(item.get("path"),str) or not item["path"]:
                    self.add("error","E10.EVIDENCE.ITEM","evidence object must contain only non-empty path",loc); ok=False
                elif self.safe_path(item["path"]) is None:
                    ok=False
            else:
                self.add("error","E10.EVIDENCE.ITEM","invalid evidence item",loc); ok=False
        return ok

    def load_json(self, rel: Path, code: str, required=True):
        p=(self.root/rel).resolve(strict=False)
        if not p.exists() and not required: return None
        s=self.safe_path(str(rel))
        if s is None: return None
        try: d=json.loads(s.read_text(encoding="utf-8"))
        except (OSError,UnicodeError,json.JSONDecodeError) as exc:
            self.add("error",f"{code}.PARSE",f"cannot parse JSON: {exc}",str(rel)); return None
        if not isinstance(d,dict):
            self.add("error",f"{code}.TYPE","registry root must be object",str(rel)); return None
        return d

    def load(self):
        d=self.load_json(self.registry_path,"E10.REGISTRY")
        if d is None: return False
        self.obj=d
        if d.get("standard") != STANDARD:
            self.add("error","E10.STANDARD","unsupported E10 standard identifier",str(self.registry_path))
        if not isinstance(d.get("revision"),str) or not d.get("revision"):
            self.add("error","E10.REVISION","revision must be non-empty string",str(self.registry_path))
        arrays=["principals","delegations","contexts","policies","proposals","approvals","decisions","executions","effects","accountability_traces"]
        total=0
        for k in arrays:
            v=d.get(k)
            if not isinstance(v,list):
                self.add("error","E10.COLLECTION",f"{k} must be array",str(self.registry_path))
            else:
                total += len(v)
        if total>MAX_OBJECTS:
            self.add("error","E10.RESOURCE","object count exceeds checker limit")
        self.load_e9()
        return True

    def load_e9(self):
        if not self.degraded_path: return
        d=self.load_json(self.degraded_path,"E10.E9",required=False)
        if not d: return
        for x in d.get("decisions",[]):
            if isinstance(x,dict) and isinstance(x.get("id"),str) and isinstance(x.get("state"),str):
                self.e9_states[x["id"]] = x["state"]

    def map_items(self,key,code):
        out={}
        for i,item in enumerate(self.obj.get(key,[])):
            loc=f"{self.registry_path}#/{key}/{i}"
            if not isinstance(item,dict):
                self.add("error",f"{code}.TYPE","item must be object",loc); continue
            iid=item.get("id")
            if not isinstance(iid,str) or not iid:
                self.add("error",f"{code}.ID","item requires non-empty id",loc); continue
            if iid in out:
                self.add("error",f"{code}.DUPLICATE",f"duplicate id: {iid}",loc)
            out[iid]=item
        return out

    def check_base(self):
        self.principals=self.map_items("principals","E10.PRINCIPAL")
        self.delegations=self.map_items("delegations","E10.DELEGATION")
        self.contexts=self.map_items("contexts","E10.CONTEXT")
        self.policies=self.map_items("policies","E10.POLICY")
        self.proposals=self.map_items("proposals","E10.PROPOSAL")
        self.approvals=self.map_items("approvals","E10.APPROVAL")
        for pid,p in self.principals.items():
            loc=f"principal:{pid}"
            if p.get("kind") not in {"human","service","automation","team","external","unknown"}:
                self.add("error","E10.PRINCIPAL.KIND","invalid principal kind",loc)
            if p.get("status") not in {"active","suspended","retired","unknown"}:
                self.add("error","E10.PRINCIPAL.STATUS","invalid principal status",loc)
            scopes=p.get("direct_scopes")
            if not isinstance(scopes,list) or any(not isinstance(x,str) or not x for x in scopes):
                self.add("error","E10.PRINCIPAL.SCOPES","direct_scopes must be non-empty-string array",loc)
        for did,d in self.delegations.items():
            loc=f"delegation:{did}"
            if d.get("delegator") not in self.principals or d.get("delegate") not in self.principals:
                self.add("error","E10.DELEGATION.PRINCIPAL_REF","unresolved delegation principal",loc)
            if d.get("delegator")==d.get("delegate"):
                self.add("error","E10.DELEGATION.SELF","self-delegation is not valid authority derivation",loc)
            if d.get("status") not in {"active","suspended","revoked","retired","unknown"}:
                self.add("error","E10.DELEGATION.STATUS","invalid delegation status",loc)
            scopes=d.get("scopes")
            if not isinstance(scopes,list) or not scopes or any(not isinstance(x,str) or not x for x in scopes):
                self.add("error","E10.DELEGATION.SCOPES","scopes must be non-empty-string array",loc)
            if "evidence" in d and d["evidence"]:
                self.evidence_valid(d["evidence"],loc)
        for cid,c in self.contexts.items():
            loc=f"context:{cid}"
            if not isinstance(c.get("revision"),str) or not c.get("revision"):
                self.add("error","E10.CONTEXT.REVISION","context revision required",loc)
            if "e9_decision" in c and (not isinstance(c["e9_decision"],str) or not c["e9_decision"]):
                self.add("error","E10.CONTEXT.E9","e9_decision must be non-empty string",loc)
        for pid,p in self.policies.items():
            loc=f"policy:{pid}"
            for k in ("revision","action_scope","approval_scope"):
                if not isinstance(p.get(k),str) or not p.get(k):
                    self.add("error","E10.POLICY.FIELD",f"{k} must be non-empty string",loc)
            if not isinstance(p.get("required_approvals"),int) or p.get("required_approvals")<0:
                self.add("error","E10.POLICY.APPROVALS","required_approvals must be non-negative integer",loc)
            for k in ("allow_self_approval","allow_automation_actor","allow_automation_executor","require_e9_context"):
                if not isinstance(p.get(k),bool):
                    self.add("error","E10.POLICY.BOOL",f"{k} must be boolean",loc)
            if not isinstance(p.get("max_delegation_depth"),int) or p.get("max_delegation_depth")<0:
                self.add("error","E10.POLICY.DEPTH","max_delegation_depth must be non-negative integer",loc)
            states=p.get("allowed_e9_states",[])
            if not isinstance(states,list) or any(x not in {"degraded-safe","fallback-verified","partial-trust-available","nominal-restored","unsafe","unavailable"} for x in states):
                self.add("error","E10.POLICY.E9_STATES","invalid allowed_e9_states",loc)
            elif p.get("require_e9_context") and not states:
                self.add("error","E10.POLICY.E9_STATES","required E9 context needs at least one allowed E9 state",loc)
        for qid,q in self.proposals.items():
            loc=f"proposal:{qid}"
            for k in ("revision","action","scope","target"):
                if not isinstance(q.get(k),str) or not q.get(k):
                    self.add("error","E10.PROPOSAL.FIELD",f"{k} must be non-empty string",loc)
            if q.get("actor") not in self.principals or q.get("requested_executor") not in self.principals:
                self.add("error","E10.PROPOSAL.PRINCIPAL_REF","unresolved actor or requested_executor",loc)
            if q.get("policy") not in self.policies or q.get("context") not in self.contexts:
                self.add("error","E10.PROPOSAL.BOUNDARY_REF","unresolved policy or context",loc)
        for aid,a in self.approvals.items():
            loc=f"approval:{aid}"
            if a.get("proposal") not in self.proposals or a.get("approver") not in self.principals:
                self.add("error","E10.APPROVAL.REF","unresolved proposal or approver",loc)
            if a.get("state") not in {"approved","rejected","abstained","withdrawn","unavailable"}:
                self.add("error","E10.APPROVAL.STATE","invalid approval state",loc)
            path=a.get("authority_path",[])
            if not isinstance(path,list):
                self.add("error","E10.APPROVAL.PATH","authority_path must be array",loc)
            if a.get("state")=="approved":
                self.evidence_valid(a.get("evidence",[]),loc)

    def verify_authority_path(self, principal_id: str, scope: str, path_refs: Any, max_depth: int, loc: str) -> bool:
        p=self.principals.get(principal_id)
        if p is None:
            self.add("error","E10.AUTH.PRINCIPAL","unresolved authority principal",loc); return False
        if p.get("status")!="active":
            self.add("error","E10.AUTH.STATUS","authority principal must be active",loc); return False
        if not isinstance(path_refs,list):
            self.add("error","E10.AUTH.PATH","authority_path must be array",loc); return False
        if len(path_refs)>max_depth:
            self.add("error","E10.AUTH.DEPTH","delegation path exceeds policy max depth",loc); return False
        if not path_refs:
            if scope not in p.get("direct_scopes",[]):
                self.add("error","E10.AUTH.DIRECT","principal lacks direct scope authority",loc); return False
            return True
        ds=[]
        for ref in path_refs:
            d=self.delegations.get(ref)
            if d is None:
                self.add("error","E10.AUTH.DELEGATION_REF",f"unresolved delegation: {ref}",loc); return False
            ds.append(d)
        first=ds[0]
        root=self.principals.get(first.get("delegator"))
        if root is None or root.get("status")!="active" or scope not in root.get("direct_scopes",[]):
            self.add("error","E10.AUTH.ROOT","delegation path lacks active direct authority root",loc); return False
        principals=[first.get("delegator")]
        prev=None
        for d in ds:
            if d.get("status")!="active":
                self.add("error","E10.AUTH.DELEGATION_STATUS","selected delegation must be active",loc); return False
            delegator=self.principals.get(d.get("delegator")); delegate=self.principals.get(d.get("delegate"))
            if delegator is None or delegate is None or delegator.get("status")!="active" or delegate.get("status")!="active":
                self.add("error","E10.AUTH.PATH_STATUS","all principals on selected delegation path must be active",loc); return False
            if scope not in d.get("scopes",[]):
                self.add("error","E10.AUTH.SCOPE","selected delegation does not include scope",loc); return False
            if prev is not None and d.get("delegator")!=prev:
                self.add("error","E10.AUTH.CHAIN","delegation path is not contiguous",loc); return False
            principals.append(d.get("delegate"))
            prev=d.get("delegate")
        if prev != principal_id:
            self.add("error","E10.AUTH.TARGET","delegation path does not terminate at target principal",loc); return False
        if len(set(principals)) != len(principals):
            self.add("error","E10.AUTH.CYCLE","delegation path repeats a principal",loc); return False
        self.delegation_verified += 1
        return True

    def approval_valid(self, approval: dict[str,Any], proposal: dict[str,Any], policy: dict[str,Any], context: dict[str,Any], loc: str) -> bool:
        if approval.get("state")!="approved": return False
        if approval.get("proposal_revision") != proposal.get("revision"):
            self.add("error","E10.APPROVAL.PROPOSAL_REV","stale proposal revision",loc); return False
        if approval.get("policy_revision") != policy.get("revision"):
            self.add("error","E10.APPROVAL.POLICY_REV","stale policy revision",loc); return False
        if approval.get("context_revision") != context.get("revision"):
            self.add("error","E10.APPROVAL.CONTEXT_REV","stale context revision",loc); return False
        if not self.evidence_valid(approval.get("evidence",[]),loc): return False
        if approval.get("approver") in {proposal.get("actor"), proposal.get("requested_executor")} and not policy.get("allow_self_approval"):
            self.add("error","E10.APPROVAL.SELF","actor/executor self approval forbidden by policy",loc); return False
        return self.verify_authority_path(
            approval.get("approver"), policy.get("approval_scope"),
            approval.get("authority_path",[]), policy.get("max_delegation_depth"), loc
        )

    def check_decisions(self):
        self.decisions=self.map_items("decisions","E10.DECISION")
        for did,d in self.decisions.items():
            loc=f"decision:{did}"
            state=d.get("state")
            if state not in {"authorized","denied","held","unavailable"}:
                self.add("error","E10.DECISION.STATE","invalid decision state",loc); continue
            proposal=self.proposals.get(d.get("proposal")); policy=self.policies.get(d.get("policy")); context=self.contexts.get(d.get("context"))
            if proposal is None or policy is None or context is None:
                self.add("error","E10.DECISION.REF","unresolved proposal/policy/context",loc); continue
            for key in ("proposal_revision","policy_revision","context_revision"):
                if not isinstance(d.get(key),str) or not d.get(key):
                    self.add("error","E10.DECISION.REVISION",f"{key} must be non-empty string",loc)
            if state!="authorized": continue
            if proposal.get("policy")!=d.get("policy") or proposal.get("context")!=d.get("context"):
                self.add("error","E10.DECISION.BOUNDARY","decision does not use proposal policy/context boundary",loc)
            if d.get("proposal_revision")!=proposal.get("revision"):
                self.add("error","E10.DECISION.PROPOSAL_REV","proposal revision mismatch",loc)
            if d.get("policy_revision")!=policy.get("revision"):
                self.add("error","E10.DECISION.POLICY_REV","policy revision mismatch",loc)
            if d.get("context_revision")!=context.get("revision"):
                self.add("error","E10.DECISION.CONTEXT_REV","context revision mismatch",loc)
            if proposal.get("scope")!=policy.get("action_scope"):
                self.add("error","E10.DECISION.SCOPE","proposal scope does not match policy action_scope",loc)
            actor=self.principals.get(proposal.get("actor"))
            if actor and actor.get("kind")=="automation" and not policy.get("allow_automation_actor"):
                self.add("error","E10.DECISION.AUTOMATION_ACTOR","automation actor forbidden by policy",loc)
            self.verify_authority_path(proposal.get("actor"),proposal.get("scope"),d.get("actor_authority_path",[]),policy.get("max_delegation_depth"),loc)
            ref=context.get("e9_decision")
            if policy.get("require_e9_context") and not ref:
                self.add("error","E10.DECISION.E9_MISSING","required E9 context decision is absent",loc)
            if ref:
                if ref not in self.e9_states:
                    self.add("error","E10.DECISION.E9_REF","explicit E9 context decision does not resolve",loc)
                elif policy.get("allowed_e9_states") and self.e9_states[ref] not in policy.get("allowed_e9_states",[]):
                    self.add("error","E10.DECISION.E9_STATE","E9 context state not allowed by policy",loc)
            refs=d.get("approvals",[])
            if not isinstance(refs,list):
                self.add("error","E10.DECISION.APPROVALS","approvals must be array",loc); refs=[]
            valid=[]
            seen=set()
            for ref in refs:
                a=self.approvals.get(ref)
                if a is None or a.get("proposal")!=proposal.get("id"):
                    self.add("error","E10.DECISION.APPROVAL_REF",f"invalid approval reference: {ref}",loc); continue
                approver=a.get("approver")
                if approver in seen:
                    self.add("error","E10.DECISION.APPROVER_DUP","duplicate approver in decision",loc); continue
                seen.add(approver)
                if self.approval_valid(a,proposal,policy,context,loc):
                    valid.append(ref)
            if len(valid) < policy.get("required_approvals",0):
                self.add("error","E10.DECISION.QUORUM",f"approval quorum not met: {len(valid)} < {policy.get('required_approvals')}",loc)
            if not self.has_error(loc):
                self.valid_authorizations.add(did); self.authorization_verified += 1

    def check_executions_effects(self):
        self.executions=self.map_items("executions","E10.EXECUTION")
        self.effects=self.map_items("effects","E10.EFFECT")
        for xid,x in self.executions.items():
            loc=f"execution:{xid}"
            if x.get("state") not in {"attempted","succeeded","failed","aborted","unavailable"}:
                self.add("error","E10.EXECUTION.STATE","invalid execution state",loc); continue
            d=self.decisions.get(x.get("decision"))
            if d is None or x.get("decision") not in self.valid_authorizations:
                self.add("error","E10.EXECUTION.AUTHORIZATION","execution requires mechanically valid authorized decision",loc); continue
            proposal=self.proposals.get(d.get("proposal")); policy=self.policies.get(d.get("policy"))
            executor=self.principals.get(x.get("executor"))
            if executor is None:
                self.add("error","E10.EXECUTION.EXECUTOR","unresolved executor",loc); continue
            if proposal.get("requested_executor") != x.get("executor"):
                self.add("error","E10.EXECUTION.REQUESTED","executor differs from proposal requested_executor",loc)
            if executor.get("kind")=="automation" and not policy.get("allow_automation_executor"):
                self.add("error","E10.EXECUTION.AUTOMATION","automation executor forbidden by policy",loc)
            self.verify_authority_path(x.get("executor"),proposal.get("scope"),x.get("authority_path",[]),policy.get("max_delegation_depth"),loc)
            if x.get("state")=="succeeded":
                self.evidence_valid(x.get("evidence",[]),loc)
            if not self.has_error(loc):
                self.valid_executions.add(xid); self.execution_verified += 1
        for eid,e in self.effects.items():
            loc=f"effect:{eid}"
            if e.get("state") not in {"observed","partially-observed","not-observed","unavailable"}:
                self.add("error","E10.EFFECT.STATE","invalid effect state",loc); continue
            x=self.executions.get(e.get("execution"))
            if x is None or e.get("execution") not in self.valid_executions:
                self.add("error","E10.EFFECT.EXECUTION","effect requires valid execution record",loc); continue
            if e.get("state") in {"observed","partially-observed"}:
                self.evidence_valid(e.get("evidence",[]),loc)
            if not self.has_error(loc):
                self.valid_effects.add(eid)
                if e.get("state")=="observed": self.effect_verified += 1

    def check_traces(self):
        self.traces=self.map_items("accountability_traces","E10.TRACE")
        for tid,t in self.traces.items():
            loc=f"trace:{tid}"
            if t.get("state") not in {"trace-complete","trace-partial","disputed","unavailable"}:
                self.add("error","E10.TRACE.STATE","invalid trace state",loc); continue
            if t.get("state")!="trace-complete": continue
            did=t.get("decision"); xid=t.get("execution"); eid=t.get("effect")
            if did not in self.valid_authorizations or xid not in self.valid_executions or eid not in self.valid_effects:
                self.add("error","E10.TRACE.CHAIN","complete trace requires valid authorization, execution and effect",loc); continue
            x=self.executions[xid]; e=self.effects[eid]
            if x.get("decision")!=did or e.get("execution")!=xid:
                self.add("error","E10.TRACE.COHERENCE","trace references are not coherent",loc); continue
            d=self.decisions[did]; q=self.proposals[d["proposal"]]
            participants=t.get("participants")
            if not isinstance(participants,list) or any(p not in self.principals for p in participants):
                self.add("error","E10.TRACE.PARTICIPANTS","participants must resolve to principals",loc); continue
            required={q.get("actor"),x.get("executor")}
            for ref in d.get("approvals",[]):
                a=self.approvals.get(ref)
                if a and a.get("state")=="approved":
                    required.add(a.get("approver"))
            missing=required-set(participants)
            if missing:
                self.add("error","E10.TRACE.PARTICIPANTS",f"trace omits participants: {sorted(missing)}",loc); continue
            if "evidence" in t and t["evidence"]:
                self.evidence_valid(t["evidence"],loc)
            if not self.has_error(loc): self.accountability_verified += 1

    def run(self):
        if self.load():
            self.check_base()
            self.check_decisions()
            self.check_executions_effects()
            self.check_traces()
        findings=sorted(self.findings,key=lambda x:(x.severity,x.code,x.path,x.message))
        errors=sum(f.severity=="error" for f in findings)
        positive_ok = errors == 0
        return {
            "tool":"eigiib-automation-check",
            "tool_version":TOOL_VERSION,
            "standard":STANDARD,
            "revision":self.obj.get("revision","unknown"),
            "structural_result":"non-conformant" if errors else "conformant",
            "delegation_result":"verified" if positive_ok and self.delegation_verified else "not-evaluated",
            "authorization_result":"verified" if positive_ok and self.authorization_verified else "not-evaluated",
            "execution_result":"verified" if positive_ok and self.execution_verified else "not-evaluated",
            "effect_result":"observed" if positive_ok and self.effect_verified else "not-evaluated",
            "accountability_result":"verified" if positive_ok and self.accountability_verified else "not-evaluated",
            "findings":[asdict(f) for f in findings],
        }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("root",nargs="?",default=".")
    ap.add_argument("--registry",default="conformance/automation.json")
    ap.add_argument("--degraded",default="conformance/degraded.json")
    ap.add_argument("--json",action="store_true")
    a=ap.parse_args()
    r=Checker(Path(a.root),Path(a.registry),Path(a.degraded)).run()
    if a.json: print(json.dumps(r,indent=2,sort_keys=True))
    else:
        print(r["structural_result"])
        for f in r["findings"]: print(f"{f['severity']}: {f['code']}: {f['message']}")
    return 1 if r["structural_result"]=="non-conformant" else 0

if __name__=="__main__":
    raise SystemExit(main())
