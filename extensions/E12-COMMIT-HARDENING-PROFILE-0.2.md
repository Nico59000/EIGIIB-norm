# EIGIIB-E12 Commit Hardening Profile 0.2

Status: additive hardening above E12 draft 1.0.

This profile closes two mechanically decidable false-positive boundaries discovered after the first green E1→E12 repository replay. It does not execute a transaction, acquire a lock, consume a token, perform a commit, read the host clock, or prove external linearizability.

## H1. Fresh commit-time observation

A positive E12 decision already requires distinct E11 check-time and commit-time decision ids. H0.2 additionally requires those decisions to reference distinct E11 observation ids.

```text
check_temporal_decision.observation != commit_temporal_decision.observation
```

A second E11 decision object that merely reuses the exact check-time observation is therefore not accepted as commit-time revalidation.

The baseline conservative interval order remains in force:

\[
 t_u-u_u \ge t_c+u_c.
\]

H0.2 does not require a wall-clock source and does not strengthen E11 source trust.

## H2. Atomic commit-domain binding

Every positive `commit-safe` conclusion requires the referenced committed E12 commit to declare an `atomic_store`.

The store must already satisfy the baseline E12 active evidence-backed atomic-store premise.

When the selected E12 policy requires one-shot consumption, the consumed record must use the same store:

```text
commit.atomic_store == consumption.store
```

When the policy requires idempotency, the committed idempotency record must use the same store:

```text
commit.atomic_store == idempotency_record.store
```

Thus, when both are required:

```text
commit.atomic_store == consumption.store == idempotency_record.store
```

This is a declared atomicity-domain relation. It is not a proof that an external database, remote service, or distributed system actually provides linearizable exactly-once effects.

## H3. Idempotent replay store continuity

For `idempotent-replay`, the idempotency record's store must equal the canonical commit's `atomic_store`.

A retry key from one atomic domain cannot therefore be used to justify reuse of a canonical commit declared in another domain.

## Boundary

H0.2 strengthens only E12 positive conclusions. Historical negative/held/unavailable records remain traceable. A conformant H0.2 record still does not establish semantic idempotence, exactly-once external side effects, trusted time, benign intent, culpability, or legal responsibility.
