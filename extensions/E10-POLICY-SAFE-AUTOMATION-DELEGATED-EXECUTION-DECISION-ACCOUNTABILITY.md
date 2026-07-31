# EIGIIB-E10 — Policy-Safe Automation, Delegated Execution and Decision Accountability

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0 and EIGIIB-E1 through EIGIIB-E9 1.0  
**Reference checker:** `tools/eigiib_automation_check.py`

## 1. Purpose

EIGIIB-E10 defines how a project may authorize and account for automated or delegated actions without collapsing technical capability, authority, approval, decision, execution, observed effect, or responsibility into one Boolean.

The following implications are invalid unless an explicit policy supplies the missing premise:

```text
action technically possible       != action authorized
principal authenticated           != principal authorized
delegation present                != delegation applicable
approval recorded                 != approval current
authorization issued              != action executed
execution reported successful     != intended effect observed
automated actor                   != autonomous authority
quorum reached                    != approver independence
trace complete                    != action correct
trace complete                    != culpability
policy satisfied                  != global safety
```

The reference checker is static. It MUST NOT execute actions, create approvals, mutate trust/configuration, or manufacture human consent.

## 2. Core separation

For an action proposal `P`, E10 distinguishes:

```text
Capability(P)
Authority(P)
Delegation(P)
Approval(P)
Authorization(P)
Execution(P)
ObservedEffect(P)
AccountabilityTrace(P)
```

These are orthogonal. A proposal may be executable but unauthorized; an authorized proposal may never execute; a successful execution may have no observed effect; a complete trace may document an erroneous decision without proving fault or intent.

## 3. Principals and scopes

A principal SHOULD record:

```text
id
kind
status
direct_scopes
```

Canonical kinds are `human`, `service`, `automation`, `team`, `external`, `unknown`. Canonical statuses are `active`, `suspended`, `retired`, `unknown`.

`direct_scopes` are repository-declared authorization roots for E10 mechanical checking. Their presence does not establish real-world identity or legitimacy; E4 remains authoritative for authentication and trust.

Action scopes are opaque exact identifiers such as `observe`, `read`, `publish`, `mutate`, `rotate`, `revoke`, `fallback`, `cutover`, `remediate`, `admin`. The reference profile infers no wildcard, prefix, inheritance, or ambient privilege.

Automation is a principal kind, not an authority source.

## 4. Delegation

A delegation SHOULD record `id`, `delegator`, `delegate`, `scopes`, `status`, and optional evidence. Canonical statuses are `active`, `suspended`, `revoked`, `retired`, `unknown`.

For action scope `s`, selected path `D1...Dn` is valid only when:

1. every delegation is active;
2. every principal on the path is active;
3. every delegation explicitly contains `s`;
4. the first delegator has direct authority for `s`;
5. adjacent delegations are contiguous;
6. the final delegate equals the target principal;
7. no principal repeats;
8. path length is within policy `max_delegation_depth`.

An empty path is valid only when the target principal has direct authority for the scope.

A delegation MUST NOT create authority ex nihilo.

## 5. Context binding

A context SHOULD record `id`, `revision`, optional `e9_decision`, and optional bounded facts.

Context revision is a logical identity marker, not trusted time. When an E9 decision is supplied, E10 consumes it only as a typed external fact and does not re-prove E9.

An explicit E9 reference MUST resolve. A policy that requires E9 context MUST list at least one admissible E9 state.

## 6. Policies

An E10 policy SHOULD record:

```text
id
revision
action_scope
approval_scope
required_approvals
allow_self_approval
allow_automation_actor
allow_automation_executor
max_delegation_depth
require_e9_context
allowed_e9_states
```

`required_approvals` counts mechanically valid approved records, not semantic correctness or human independence. Distinct identifiers are not proof of real-world independence.

Automation permission does not grant authority; it only permits a principal kind after ordinary authority checks pass.

## 7. Proposals

A proposal SHOULD record `id`, `revision`, `actor`, `requested_executor`, `action`, `scope`, `target`, `policy`, and `context`.

A proposal identifies what is being considered. It is not an authorization. Policy and context are part of the proposal authorization boundary.

## 8. Approval binding

An approval SHOULD record:

```text
id
proposal
approver
state
proposal_revision
policy_revision
context_revision
authority_path
evidence
```

Canonical states are `approved`, `rejected`, `abstained`, `withdrawn`, `unavailable`.

An approved record is mechanically usable only when:

- proposal, policy and context revisions match exactly;
- approver authority for policy `approval_scope` is established;
- selected authority path is valid;
- evidence is non-empty;
- self-approval policy is satisfied.

When self-approval is forbidden, neither the proposal actor nor its requested executor may supply the qualifying approval.

Changing proposal, policy, or context revision invalidates approval reuse in the reference profile.

## 9. Authorization decisions

A decision SHOULD record:

```text
id
proposal
policy
context
state
proposal_revision
policy_revision
context_revision
actor_authority_path
approvals
```

Canonical states are `authorized`, `denied`, `held`, `unavailable`.

Even negative decisions remain traceable to resolvable proposal, policy, and context boundaries.

A reference `authorized` decision additionally requires:

1. exact revision bindings;
2. proposal scope equals policy action scope;
3. actor authority for the action scope;
4. automation actor use is permitted when applicable;
5. approval quorum is satisfied;
6. required E9 context constraints are satisfied.

A record labelled `authorized` is input data, not proof. It contributes to a positive authorization result only after the checks pass.

## 10. Delegated execution

An execution record SHOULD include `id`, `decision`, `executor`, `state`, `authority_path`, and evidence when required.

Canonical states are `attempted`, `succeeded`, `failed`, `aborted`, `unavailable`.

Execution requires a mechanically valid authorized decision. The actual executor must match the proposal's requested executor and must independently have authority for the proposal scope.

An automation executor additionally requires policy permission.

A `succeeded` execution requires evidence.

```text
authorization != execution
execution.succeeded != intended effect observed
```

## 11. Observed effects

An effect record SHOULD include `id`, `execution`, `state`, and evidence when required.

Canonical states are `observed`, `partially-observed`, `not-observed`, `unavailable`.

`observed` and `partially-observed` require evidence. E10 retains execution/effect separation even when the same system reports both records.

## 12. Accountability traces

An accountability trace SHOULD record:

```text
id
decision
execution
effect
participants
state
evidence?
```

Canonical states are `trace-complete`, `trace-partial`, `disputed`, `unavailable`.

A `trace-complete` record requires:

- mechanically valid authorization;
- coherent execution linked to that decision;
- effect linked to that execution;
- participants covering actor, executor, and all approved approvers used by the decision.

A complete trace proves only that the declared chain is mechanically connected in the evaluated registry. It MUST NOT be promoted to real-world identity, malicious intent, culpability, legal responsibility, semantic correctness, or global safety.

## 13. Lower-layer authority

E10 may consume E9 typed decisions as bounded context but does not replace prior layers:

```text
E4 authentication
E5 transparent history
E6 gossip/fork accountability evidence
E7 recovery continuity
E8 relying-party convergence
E9 degraded-operation state
```

A degraded-safe E9 state does not automatically authorize any E10 mutation.

## 14. Capability results

E10 defines independent results:

```text
structural
delegation-verified
authorization-verified
execution-trace-verified
effect-observed
accountability-trace-verified
```

No scalar maturity order is defined. If the registry is structurally non-conformant, the reference checker MUST NOT emit positive E10 capability results.

A structurally conforming repository may contain no production proposal, authorization, execution, or accountability trace.

## 15. Mechanical checks

A generic checker SHOULD verify supported revision, path confinement, unique ids, principal state/scopes, selected delegation paths, bounded revision binding, actor authority, approval authority/quorum, self-approval policy, automation policy, E9 context constraints, executor authority, execution evidence, observed-effect evidence, and accountability trace coherence.

A generic checker MUST NOT execute proposals, invoke deployment/remediation tools, create approvals, infer consent from activity, infer identity from ids, infer malicious intent or legal responsibility, or infer global safety.

## 16. Invariants

E10-I1. Technical capability is not authority.  
E10-I2. Authentication is not authorization.  
E10-I3. Delegation derives from an explicit authority root.  
E10-I4. Approval is revision-bound.  
E10-I5. Authorization is not execution.  
E10-I6. Execution success is not observed effect.  
E10-I7. Automation has no ambient authority.  
E10-I8. Delegated execution requires executor authority independently.  
E10-I9. Accountability trace is not culpability.  
E10-I10. Lower-layer semantics remain authoritative.

## 17. Non-goals

E10-1.0 does not standardize human identity proofing, legal signatures, employment authority, IAM/OAuth/OIDC formats, secret management, approval UX, scheduling, autonomous-agent execution, trusted wall-clock time, or legal/disciplinary attribution.

## 18. Repository adoption

A repository adopting E10 SHOULD declare `conformance/automation.json` as its E10 authority.

A structurally empty registry is valid when no production authorization or execution claim is made. A repository MUST NOT invent approvals, actions, execution success, or accountability traces merely to demonstrate conformance.
