# EIGIIB-E13 — Policy Composition, Conflict Resolution and Obligations

Status: draft normative extension 1.0 introduced after E12.

## 1. Purpose

E10 establishes whether one proposal is authorized under one policy boundary. E13 addresses a different problem: one operation can be subject to several independently authoritative policies whose outcomes may disagree or carry different obligations.

E13 keeps these distinctions explicit:

```text
valid individual decision != valid composed decision
policy membership != policy precedence
permit + deny != implicit winner
composition algorithm != policy authority
conflict observed != conflict malicious
obligation declared != obligation satisfied
waivable != waived
waiver authorized != original policy erased
composed permit != execution
composed permit != E12 commit safety
```

E13 consumes E10 decisions. It does not recreate E10 delegation, approvals or authorization proof. It does not execute E12 commits and it does not make a policy engine authoritative merely because it can evaluate rules.

## 2. Functional position

E13 is introduced after E12 in the version sequence but is a sibling functional branch from E10:

```text
                         -> E11 -> E12   time / commit
E10 authorization ----<
                         -> E13          multi-policy composition
```

Version order is not a claim that E13 semantically depends on E12.

## 3. Registry objects

E13 defines:

- **composition profile** — explicit composition algorithm and E10 policy membership;
- **composition request** — one exact operation subject evaluated by several E10 decisions;
- **obligation definition** — bounded requirement contributed by one member policy;
- **obligation evaluation** — state of one obligation for one request;
- **exception** — E10-authorized waiver of one explicitly waivable obligation;
- **composed decision** — mechanically derived result for one composition request.

The repository registry is `conformance/policy-composition.json`.

## 4. Composition profiles

A profile contains at least two distinct E10 policies and at least one required member.

Supported algorithms are exactly:

```text
all-authorized
deny-overrides
permit-overrides
priority-order
```

No algorithm is the global EIGIIB default.

Therefore:

```text
deny-overrides is not implicit
permit-overrides is not implicit
member array order is not precedence
repository file order is not precedence
```

`priority-order` requires a unique integer priority for every member. Lower numeric value has higher priority. A priority field is invalid for the other algorithms, preventing accidental hidden ordering.

Required membership controls completeness. If a required policy has no selected E10 decision, the composition is `held`; absence is not silently converted to permit or deny.

## 5. Exact common subject

Every selected E10 decision must resolve through its E10 proposal and policy.

All selected proposals must match the E13 request exactly on:

```text
action
scope
target
actor
requested_executor
context
```

The request also carries the exact E10 context revision.

The referenced E10 decision must retain the exact proposal, policy and context revisions from its own E10 boundary.

This prevents composing decisions for superficially similar but actually different operations.

## 6. One decision per policy

One composition request selects at most one E10 decision for one member policy.

A profile member policy may not appear twice.

A decision from an E10 policy outside the selected profile is invalid.

E13 therefore does not perform hidden voting by duplicate policy evaluation.

## 7. Outcome algorithms

Let `S` be the states of selected E10 member decisions after required-member completeness is checked.

E10 member states remain:

```text
authorized
denied
held
unavailable
```

E13 composed states are:

```text
permitted
denied
held
unavailable
```

### 7.1 all-authorized

- any `denied` -> `denied`;
- any `held` or mixed `unavailable` -> `held`;
- every selected member `authorized` and all required members present -> `permitted`;
- all selected members `unavailable` -> `unavailable`.

### 7.2 deny-overrides

- any `denied` -> `denied`;
- otherwise any `held` or mixed `unavailable` -> `held`;
- otherwise at least one `authorized` with required completeness -> `permitted`;
- all `unavailable` -> `unavailable`.

### 7.3 permit-overrides

- any `authorized` -> `permitted`;
- otherwise any `denied` -> `denied`;
- otherwise `held` if at least one member is held;
- all `unavailable` -> `unavailable`.

The fact that `permit-overrides` is supported is not a recommendation to use it. Its use must be explicit in the authoritative composition profile.

### 7.4 priority-order

All members carry unique integer priorities.

After required-member completeness, the selected member with smallest priority determines the result:

```text
authorized  -> permitted
denied      -> denied
held        -> held
unavailable -> unavailable
```

A lower-priority result cannot silently replace a higher-priority held or unavailable result.

## 8. Conflict observation

A selected request has a direct policy conflict when at least one member result is `authorized` and at least one member result is `denied`.

Conflict is derived by the checker. It is not a second stored authority.

A direct conflict can be resolved by the profile algorithm, but:

```text
mechanically resolved conflict != policies semantically agree
resolved conflict != one policy was wrong
resolved conflict != malicious policy behavior
```

## 9. Obligations

Obligation definitions belong to one composition profile and one source member policy.

Each definition declares:

```text
phase
trigger
mandatory
waivable
```

Phases:

```text
pre-decision
pre-commit
post-commit
audit
```

Triggers:

```text
authorized
denied
always
```

An obligation is active only when its source policy is selected and its trigger matches that E10 member state (`always` matches any selected state).

## 10. Obligation evaluations

Evaluation states are:

```text
satisfied
pending
failed
waived
unavailable
```

`satisfied` and `failed` require material evidence.

There is at most one evaluation for one `(request, obligation)` pair.

For a positive composed result, an active mandatory `pre-decision` obligation must be either:

```text
satisfied
waived by a valid E13 exception
```

Otherwise an algorithmic `permitted` result is reduced to `held`.

This blocking rule does not convert a derived `denied` result into `held`.

## 11. Residual obligations

Mandatory active obligations in phases:

```text
pre-commit
post-commit
audit
```

may remain pending after an E13 `permitted` decision.

They are residual obligations, not evidence that they have been fulfilled.

Thus:

```text
E13 permitted + residual pre-commit obligation
!= E12 commit-safe
```

A later layer may consume such obligations, but E13 does not execute or discharge them.

## 12. Obligation waivers

E13 baseline defines one exception kind:

```text
obligation-waiver
```

An active waiver is valid only when:

1. the composition profile allows obligation waivers;
2. the obligation is explicitly `waivable`;
3. the exception binds the exact request and obligation;
4. it references an E10 decision whose state is `authorized`;
5. the E10 proposal action is exactly `eigiib:e13:waive-obligation`;
6. that proposal targets the exact obligation id;
7. the exception carries material evidence.

One `(request, obligation)` may have at most one active waiver.

E13 does not define permit/deny break-glass overrides in baseline 1.0. This avoids turning a waiver mechanism into an ambient authority to rewrite policy outcomes.

## 13. Composed decisions

There is at most one E13 composed decision for one request.

Its declared state must equal the checker-derived state from:

1. exact E10 request binding;
2. explicit profile membership;
3. selected algorithm;
4. required-member completeness;
5. active mandatory pre-decision obligations;
6. valid waivers when used.

A state label does not establish itself.

## 14. Structural failure

Any structural error suppresses positive E13 capability results.

A registry with no production composition facts may remain conformant with all positive result capabilities `not-evaluated`.

## 15. Non-goals and proof boundary

The E13 checker is static and offline.

It does not:

- run OPA, Cedar or another policy engine;
- discover applicable policies from a live environment;
- execute an E10 proposal;
- create approvals or waivers;
- execute an E12 commit;
- prove semantic consistency among policies;
- prove that a declared organizational hierarchy is legitimate;
- infer human intent, maliciousness, culpability or legal responsibility;
- infer that `permit-overrides` is safe for a particular domain;
- prove residual obligations were later discharged.

Therefore:

```text
composed permit != global safety
composed permit != execution
composed permit != commit safety
conflict resolution != semantic agreement
waiver != policy deletion
```

## 16. Reference checker

The reference checker is:

```text
tools/eigiib_policy_composition_check.py
```

It uses only repository-local JSON input and the Python standard library.

The repository conformance registry is intentionally structural-only and asserts no production multi-policy composition.
