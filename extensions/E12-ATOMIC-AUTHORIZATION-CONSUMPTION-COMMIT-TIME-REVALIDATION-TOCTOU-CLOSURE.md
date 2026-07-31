# EIGIIB-E12 — Atomic Authorization Consumption, Commit-Time Revalidation and TOCTOU Closure

Status: draft normative extension 1.0 above E11.

## 1. Purpose

E10 establishes whether an operation is authorized. E11 establishes whether an authorization-related subject is temporally admissible at an explicit observation. Neither fact alone establishes that the same operation is still admissible when an irreversible commit is performed.

E12 formalizes the boundary between **check** and **use**.

Its goal is not to implement transactions. Its goal is to make the following distinctions mechanically explicit:

```text
authorized at check != authorized at commit
valid at check != revalidated at commit
operation proposed != exact operation committed
one-shot token available != token atomically consumed
retry identifier present != retry bound to the same operation
execution started != commit completed
commit completed != effect observed
commit compensated != commit never happened
```

E12 consumes E10 and E11 facts. It does not re-prove E10 authority or E11 temporal validity.

## 2. Core model

E12 uses these object classes:

- **atomic store** — declared storage/serialization authority used for one-shot consumption or idempotency binding;
- **commit policy** — local rule selecting allowed E11 states and whether consumption/idempotency are required;
- **operation intent** — exact action/target/request identity bound to one E10 authorization and one E11 check decision;
- **attempt** — one concrete use attempt tied to an E10 execution and a separate E11 commit-time decision;
- **consumption record** — one-shot token state for one operation/attempt;
- **idempotency record** — unique retry key bound to one operation and, after commit, one canonical commit;
- **commit record** — durable declared commit outcome;
- **E12 decision** — bounded conclusion for one attempt.

The dependency direction is:

```text
E10 authorization
   +
E11 check-time temporal decision
   ↓
operation intent
   +
E10 execution
   +
E11 commit-time temporal decision
   ↓
attempt
   + optional atomic consumption
   + optional idempotency binding
   ↓
commit record
   ↓
E12 decision
```

## 3. Exact operation binding

A positive E12 operation must bind to one E10 decision whose state is `authorized`.

The E10 decision resolves its E10 proposal. E12 requires exact equality of:

```text
proposal.action == operation.action
proposal.scope  == operation.scope
proposal.target == operation.target
```

The E10 proposal and E12 operation also carry the same `operation_identity`:

```text
algorithm = sha256
digest    = 64 lowercase hexadecimal characters
bytes     = positive integer
```

`operation_identity` is a byte-identity binding for the request payload selected by the proposal. It does not establish semantic correctness, authenticity, confidentiality or benign intent.

A proposal that does not carry an operation identity cannot support positive E12 commit safety.

The operation also repeats the E10 decision revision tuple:

```text
proposal_revision
policy_revision
context_revision
```

and it must equal the referenced E10 decision tuple.

This prevents a target, action, payload or policy/context revision checked earlier from being silently substituted at commit.

## 4. Check-time and commit-time temporal decisions

Each operation references an E11 **check-time** temporal decision.

Each attempt references a distinct E11 **commit-time** temporal decision.

Both temporal decisions must:

- name the same E10 decision as `subject`;
- carry the same exact E10 revision boundary;
- have states allowed by the selected E12 policy.

E12 requires the two E11 observations to belong to the same E11 time domain.

Let the check observation be:

\[
I_c=[t_c-u_c,t_c+u_c]
\]

and the commit observation be:

\[
I_u=[t_u-u_u,t_u+u_u].
\]

For a positive commit-time revalidation E12 requires the conservative order:

\[
\boxed{t_u-u_u \ge t_c+u_c.}
\]

Thus the entire commit-time uncertainty interval is no earlier than the entire check-time interval.

If the intervals overlap, the checker does not guess an order. A positive E12 decision is unavailable until a sufficiently ordered observation exists.

E12 does not read the host clock and performs no cross-domain time conversion.

## 5. Attempts and E10 execution

Each attempt references one E10 execution record.

For positive E12 use:

- the E10 execution must reference the operation's E10 decision;
- its state must be `attempted` or `succeeded`;
- the attempt's E11 commit-time decision must satisfy §4.

E12 does not turn `attempted` into `succeeded` and does not infer an E10 effect.

Attempt states are:

```text
prepared
committed
reused
aborted
failed
unavailable
```

`reused` is reserved for an idempotent retry that returns a previously committed canonical result without creating a new commit.

## 6. Atomic stores

An atomic store declaration has a mode:

```text
atomic-compare-and-set
transactional-unique-key
external-serialized
unknown
```

and a status:

```text
active
suspended
unavailable
unknown
```

A positive consumption/idempotency decision requires an `active` store whose mode is not `unknown` and whose declaration carries material evidence.

This establishes only that the registry has a bounded evidence-backed atomicity premise. The E12 checker does not execute the store, prove linearizability, inspect a database, or establish that the external system actually honored the declared mode.

Therefore:

```text
declared atomic store != globally proven atomic execution
```

## 7. One-shot consumption

When policy `require_consumption = true`, a `commit-safe` decision requires one consumption record in state `consumed`.

A consumption record binds:

```text
(store, namespace, token)
```

uniquely to one operation and one attempt.

The tuple `(store, namespace, token)` MUST occur at most once in the E12 registry. A second record is a structural conflict even if its state differs.

A consumed record requires material evidence.

A commit cannot use a consumption record for another operation or another attempt.

States are:

```text
reserved
consumed
released
contested
unavailable
```

`released` does not mean `consumed`, and `contested` does not support commit safety.

## 8. Idempotency binding

When policy `require_idempotency = true`, the operation/attempt must use an idempotency record identified by:

```text
(store, namespace, key)
```

The tuple is globally unique in the E12 registry and binds to exactly one operation.

States are:

```text
open
committed
retired
contested
unavailable
```

A `committed` idempotency record names one `canonical_commit` and carries material evidence.

The canonical commit must belong to the same operation.

This establishes:

```text
same idempotency key -> same E12 operation identity
```

within the declared store/key namespace. It does not establish application-level semantic idempotence beyond that boundary.

## 9. Commit records

Commit states are:

```text
committed
compensated
disputed
unavailable
```

A `committed` record requires material evidence.

A commit binds exactly one operation and the attempt that performed the commit.

For positive `commit-safe`:

- attempt state is `committed`;
- commit state is `committed`;
- commit and attempt reference the same operation;
- if consumption is required, the commit uses the attempt's unique consumed record;
- if idempotency is required, the commit uses the attempt's committed idempotency record and is that record's canonical commit.

At most one commit record in state `committed` or `compensated` may exist for one operation. Compensation preserves historical commit identity:

```text
compensated != never committed
```

E7 remains authoritative for recovery/remediation semantics.

## 10. Idempotent replay

An E12 decision may be `idempotent-replay` instead of `commit-safe`.

For that state:

- policy requires idempotency;
- current attempt state is `reused`;
- commit-time E11 revalidation still passes;
- the attempt references a committed idempotency record for the same operation;
- the E12 decision references that record's existing canonical commit;
- the canonical commit's original attempt is different from the current reused attempt;
- the reused attempt carries no new consumption record.

Thus a retry can recover the canonical commit result without creating a second one-shot effect.

E12 does not infer that a remote service actually returned byte-identical application output; that belongs to operation-specific evidence.

## 11. E12 decision states

Decision states are:

```text
commit-safe
idempotent-replay
held
rejected
indeterminate
unavailable
```

Positive states are only `commit-safe` and `idempotent-replay`.

Negative/non-positive decisions must still resolve their operation, attempt and policy references. Historical traceability is not waived merely because commit safety was not established.

## 12. Positive-result suppression

Any structural E12 error suppresses all positive aggregate capability results.

The checker reports orthogonal bounded capabilities:

```text
operation_binding_result
commit_revalidation_result
consumption_binding_result
idempotency_binding_result
commit_safety_result
idempotent_replay_result
```

A capability with no qualifying record is `not-evaluated`.

No result means:

- E10 authorization was independently re-proved;
- E11 time was globally trusted;
- a storage engine is actually linearizable;
- an external side effect occurred exactly once;
- a remote system is application-level idempotent;
- a commit cannot later be compensated or disputed;
- malicious intent, culpability or legal responsibility was established.

## 13. Lower-layer authority

E12 consumes but does not re-prove:

- E3 artifact/request byte identity concepts;
- E7 recovery and compensation semantics;
- E10 authority, approval, execution and effects;
- E11 temporal validity, freshness, lease and replay semantics.

E12 adds only the check/use relation, exact-operation commit binding, one-shot consumption relation, idempotency relation and bounded commit conclusion.

## 14. Reference checker boundary

The reference checker is static and offline.

It:

- reads E10, E11 and E12 registries;
- resolves declared cross-layer references;
- checks exact revision/action/scope/target/request identity binding;
- checks conservative E11 observation ordering;
- checks atomic-store premises and unique consumption/idempotency keys;
- checks commit and retry coherence;
- emits bounded results.

It performs no network request, lock acquisition, compare-and-set, transaction, commit, rollback, token consumption, retry, deployment action or external command.
