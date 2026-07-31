# EIGIIB-E11 Temporal Hardening Profile 0.2

Status: additive hardening above E11 draft 1.0.

This profile closes mechanically decidable replay and lineage gaps discovered after the first green E1→E11 repository replay. It does not introduce trusted time, execute renewals, consume tokens, or create authority.

## H1. Exact E10 boundary binding

When temporal policy requires an authorized E10 subject, the temporal decision, its selected E10 lease, and its selected replay assertion carry the exact E10 boundary:

```text
proposal_revision
policy_revision
context_revision
```

The tuple must equal the referenced E10 decision tuple. A previously valid E10 decision cannot therefore be replayed under a changed proposal, policy, or context revision while retaining temporal validity.

## H2. Replay observation binding

A replay assertion used by a temporal decision names the same observation as the decision. A nonce status observed at an older or different evaluation point cannot silently support the current evaluation.

## H3. Active time domain and origin

A temporal decision requires its policy domain to be active. The reference hardening profile also rejects an uncertainty interval extending below the declared non-negative domain origin:

\[
uncertainty \le tick.
\]

## H4. Lease predecessor integrity

Every explicit predecessor edge preserves subject kind, subject and domain; increments generation by exactly one; is not backdated relative to predecessor issuance; and strictly extends `valid_until`.

## H5. Used renewal edges require approval evidence

A selected successor lease is admissible only when every predecessor edge in its selected chain has exactly one approved renewal record. Merely naming a predecessor does not establish renewal authorization.

## H6. Renewal fork guard

One predecessor cannot have multiple approved renewal successors in the same registry. This profile therefore treats approved renewal lineage as a linear history for one predecessor edge rather than an implicit branch set.

## Boundary

The profile remains static. It does not prove wall-clock authenticity, atomic token consumption, semantic correctness of E10 context, malicious replay intent, or legal responsibility.
