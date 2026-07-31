# EIGIIB-E11 — Temporal Validity, Freshness, Leases and Replay Resistance

Status: draft 1.0 extension above E10.

## 1. Purpose

E10 answers whether an action is mechanically authorized under an explicit policy boundary. E11 answers a different question: whether that authorization or another bounded subject is temporally admissible at an explicitly observed evaluation point.

E11 does not read the host clock and does not define a universal trusted time service. It operates on declared time domains, explicit observations, bounded uncertainty, lease records, renewal lineage, and replay assertions.

## 2. Non-equivalences

The following implications are invalid unless separately established:

```text
clock value                 != trusted time
issued                      != currently valid
not expired                 != fresh
fresh                       != authorized
authorized                  != temporally valid
lease active                != context unchanged
renewal approved            != old lease mutated
newer lease                 != valid renewal
same timestamp              != same event
nonce present               != nonce unused
replay detected             != malicious intent
grace accepted              != full validity
source kind = witnessed     != globally trusted time
host clock readable         != admissible E11 observation
```

E11 therefore never collapses time observation, freshness, lease validity, replay status, or E10 authorization into one scalar `valid` bit.

## 3. Explicit evaluation time

E11 has no implicit `now`.

Every temporal conclusion is evaluated against an observation

\[
O=(S,t,u,E)
\]

where `S` is a declared time source, `t` is an integer tick, `u >= 0` is symmetric declared uncertainty, and `E` is material observation evidence.

The mechanically admissible interval is

\[
I(O)=[t-u,t+u].
\]

No comparison is permitted across distinct time domains.

A source being labelled `wall`, `monotonic`, `external`, `witnessed`, `logical`, or `unknown` does not by itself establish authenticity or correctness. Source kind is descriptive; observation admissibility is policy-bound.

## 4. Time domains and sources

A time domain is

\[
D=(id,unit,ordering,status).
\]

The E11 reference profile requires total ordering within a domain. Cross-domain conversion is outside E11 1.0 unless an explicit adapter is introduced by a future extension.

A source is

\[
S=(id,domain,kind,status).
\]

Only an `active` source can support a positive reference-profile decision.

## 5. Temporal policy

A policy binds the exact time domain; whether a referenced E10 decision must be `authorized`; whether a lease and replay guard are required; maximum admitted observation uncertainty; optional maximum lease age; grace-period permission and duration; and maximum renewal depth.

`allow_grace = false` requires `grace_ticks = 0` in the reference profile.

A policy tolerance never changes a lease's own interval, a replay assertion's state, or the upstream E10 authorization result.

## 6. Lease semantics

A lease is

\[
L=(id,subject,domain,g,i,v_f,v_u,status,pred,E)
\]

with validity interval

\[
[v_f,v_u),\qquad v_f<v_u.
\]

The interval is half-open. At exactly `valid_until`, ordinary validity has ended.

An active lease requires material issuance evidence. A syntactically coherent lease without issuance evidence cannot establish temporal validity.

For an E10 authorization subject, the reference profile requires `subject_kind = e10-decision` and exact subject identity.

## 7. Conservative interval evaluation

For an active lease and observation interval `I(O)=[l,h]`:

- `valid` requires the whole interval inside `[valid_from, valid_until)`;
- `not-yet-valid` requires the whole interval before `valid_from`;
- `expired` requires the interval beyond ordinary validity and outside any admitted grace interval;
- if uncertainty crosses `valid_from`, `valid_until`, a freshness threshold, or a grace boundary, the result is `indeterminate`.

Thus:

\[
\text{boundary crossed by uncertainty} \Rightarrow \texttt{indeterminate}.
\]

## 8. Freshness

Optional `max_lease_age_ticks = A` defines

\[
T_f=issued\_tick+A.
\]

If the complete observation interval is beyond `T_f`, the result is `stale`. If uncertainty crosses `T_f`, the result is `indeterminate`.

Freshness is distinct from lease validity. A lease may be unexpired but stale under policy.

## 9. Grace periods

Grace is an explicit degraded temporal state. If enabled, its interval is

\[
[valid\_until, valid\_until+grace\_ticks).
\]

`grace-valid` MUST NOT be reported as ordinary `valid` and MUST NOT be interpreted as renewal, extension, or upstream reauthorization.

## 10. Renewal lineage

Renewal creates a new lease identity. It never mutates historical lease identity.

For an approved renewal from `L_n` to `L_{n+1}`, the reference profile requires exact predecessor linkage; same subject kind, subject, and time domain; generation increment by exactly one; strictly later validity end; and material renewal evidence.

Lease predecessor graphs must be acyclic. Policy bounds the maximum predecessor depth admissible for a temporal decision.

## 11. Replay resistance

A replay assertion is

\[
R=(id,namespace,token,subject,state,E).
\]

Reference states are `available`, `consumed`, `replayed`, and `unknown`.

Within one registry, `(namespace, token)` must be unique. A positive decision requiring replay protection needs an exact-subject assertion in state `available`.

`consumed` or `replayed` yields `replay-rejected`. `unknown` yields `unavailable` rather than optimistic acceptance.

A static E11 check never consumes a token. Actual atomic token consumption belongs to an execution system and remains outside this checker.

Replay detection does not establish intent, actor identity, compromise, or culpability.

## 12. E10 binding

E11 may consume E10 decision state as an upstream typed fact. It does not reimplement E10 delegation, approval, authorization, execution, or accountability logic.

When `require_e10_authorized = true`, the exact E10 decision identifier must resolve to upstream state `authorized`.

In repository CI, the E10 checker remains authoritative for whether the E10 registry is itself mechanically conformant.

## 13. Temporal decision states

Reference states are:

```text
valid
grace-valid
expired
not-yet-valid
stale
replay-rejected
indeterminate
unavailable
```

These states are not a total maturity order. In particular:

```text
grace-valid != valid
indeterminate != invalid
unavailable != expired
replay-rejected != unauthorized
stale != expired
```

## 14. Structural-only adoption

A repository may adopt E11 structurally with an empty `conformance/temporal.json` registry. This does not assert a production clock, production lease, fresh production authorization, consumed nonce, replay event, or successful renewal.

## 15. Reference checker boundary

The E11 reference checker is static and dependency-free. It performs no network access; never reads the host clock; changes no lease or token state; executes no E10 action; signs nothing; performs no cross-domain time conversion; and does not establish trusted time, human identity, malicious intent, legal responsibility, or global safety.

## 16. Core invariants

```text
E11-I1  No implicit current time.
E11-I2  No cross-domain temporal comparison.
E11-I3  Positive observations require material evidence.
E11-I4  Active leases require issuance evidence.
E11-I5  Ordinary lease validity is half-open [from, until).
E11-I6  Boundary-crossing uncertainty yields indeterminate.
E11-I7  Freshness is independent from expiration.
E11-I8  Grace validity is never ordinary validity.
E11-I9  Renewal creates a new identity with exact lineage.
E11-I10 Renewal lineage is acyclic and policy-depth bounded.
E11-I11 Replay namespace/token pairs are unique per registry.
E11-I12 Consumed or replayed tokens cannot establish positive validity.
E11-I13 E10 authorization remains an upstream premise, not an E11 inference.
E11-I14 Structural errors suppress positive capability reporting.
E11-I15 Replay evidence never implies intent or culpability.
```