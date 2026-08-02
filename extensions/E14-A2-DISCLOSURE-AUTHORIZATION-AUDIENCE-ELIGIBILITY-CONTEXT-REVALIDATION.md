# EIGIIB-E14-A2 — Disclosure Authorization, Audience Eligibility and Context Revalidation

Status: normative companion slice 1.0 for E14, introduced after E14-A1.

## 1. Purpose

E14-A1 proves that one disclosure projection is bound to one exact confidential evidence record and cannot strengthen its source claims. E14-A2 answers the next distinct question: **may this sealed projection be disclosed to this audience under this policy and this evaluation context?**

The slice keeps these distinctions explicit:

```text
valid projection != authorized disclosure
named audience != eligible audience
audience eligibility != audience authentication
policy identifier != policy permit
context identifier != current context
source authorization != disclosure authorization
disclosure permit != release or transmission
```

## 2. Functional position

```text
E14-A1 sealed projection
        + audience authority
        + disclosure policy
        + evaluation context
        -> E14-A2 disclosure decision
```

E14-A2 consumes E14-A1 identities and commitments. It does not recreate the confidential record, re-project claims or release content.

## 3. Machine authority

The registry is:

```text
conformance/disclosure-authorization.json
```

It defines:

- **audience authority** — versioned eligibility boundary for subjects, classifications and purposes;
- **disclosure policy** — versioned constraints on audiences, purposes, claims, assurance, claim count and correlation controls;
- **evaluation context** — versioned purpose, action, operation and subject boundary;
- **authorization request** — exact crossing request bound to one sealed E14-A1 projection;
- **disclosure decision** — declared result that must equal the checker-derived result.

The repository registry is structural-only and contains no production disclosure authorization.

## 4. Decision vocabulary

Decisions are exactly:

```text
permit
deny
held
unavailable
```

The checker derives four component results:

```text
projection: admissible | denied | held | unavailable
audience:   eligible   | ineligible | held | unavailable
policy:     permit     | deny       | held | unavailable
context:    admissible | inadmissible | held | unavailable
```

Final precedence is:

1. any authoritative negative -> `deny`;
2. otherwise any unavailable required input -> `unavailable`;
3. otherwise any held input -> `held`;
4. only four positive component results -> `permit`.

A state label does not establish itself.

## 5. Exact request binding

One request binds the exact:

```text
projection id, revision and commitment
source record id, revision and commitment
audience id and revision
policy id and revision
context id and revision
purpose
action
operation
```

The projection's embedded audience, policy and context identities must match the request. Any policy or context revision change requires a new request and decision.

## 6. Audience eligibility

An active audience is eligible only when all of the following are explicitly permitted:

```text
source record subject
source classification
request purpose
```

Audience states have these meanings:

```text
active      -> evaluate eligibility
retired     -> ineligible
contested   -> held
unavailable -> unavailable
```

`required_authentication` is a bound external control identifier. E14-A2 checks its presence, not its effective execution.

## 7. Disclosure policy evaluation

An active policy evaluates the exact projection against:

```text
allowed audience ids
allowed classifications
allowed purposes
allowed claim types
allowed predicates
maximum projected assurance
maximum projected claim count
required correlation controls
empty-projection permission
```

Any active-policy constraint violation derives `deny`. A revoked policy derives `deny`; a contested policy derives `held`; an unavailable policy derives `unavailable`.

No wildcard or repository order is interpreted as authority.

## 8. Context revalidation

An active context must match the request exactly on:

```text
purpose
action
operation
source record subject
```

A closed context or a mismatch derives `inadmissible`. A contested context derives `held`; an unavailable context derives `unavailable`.

Thus:

```text
old permit + changed context != current permit
old permit + changed policy revision != current permit
```

## 9. Sealed projection gate

Only an E14-A1 projection in state `sealed` is positively admissible.

```text
prepared -> held
sealed + active source -> admissible
revoked or withdrawn source -> denied
unavailable source -> unavailable
```

This slice still defines no `released` projection state.

## 10. Decision evidence

`permit` and `deny` decisions require material evidence identifiers. `held` and `unavailable` decisions require explicit reasons but may lack material evidence.

There is at most one decision per authorization request.

## 11. Structural failure

Unresolved references, stale revisions, stale commitments, duplicate ids, duplicate decisions or malformed state suppress positive conformance.

A structural-only registry with no requests or decisions remains conformant with authorization results `not-evaluated`.

## 12. Non-goals

E14-A2 does not:

- authenticate a real audience;
- run an external policy engine;
- prove organizational authority;
- prove correlation controls are effective;
- establish trusted time or freshness beyond exact revisions;
- release, transmit or publish a projection;
- prove confidentiality, anonymity, unlinkability or zero knowledge;
- replace E10 authorization, E11 temporal validity or E12 commit safety.

Therefore:

```text
E14-A2 permit != disclosure occurred
E14-A2 permit != audience authenticated
E14-A2 permit != storage confidential
E14-A2 permit != correlation controls enforced
```

## 13. Reference checker

```text
tools/eigiib_disclosure_authorization_check.py
```

The checker uses repository-local JSON and the Python standard library only.
