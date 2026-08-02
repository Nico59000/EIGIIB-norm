# E14-A3 human mastery guide

## Read the result correctly

A committed consumption means the supplied static authorities support one bounded use under the supplied ordering. It does not prove that a production system executed an atomic disclosure.

A rejected consumption means the checker derived a known negative result. It is not evidence of malicious intent.

`held` and `unavailable` remain distinct non-positive outcomes.

## Review order

1. Verify the E14-A2 decision and request bindings.
2. Verify the exact projection and source commitments.
3. Inspect the control profile state and required identifiers.
4. Inspect the budget scope and maximum use count.
5. Confirm the operation nonce and linkability domain.
6. Replay consumptions in budget sequence order.
7. Count only prior committed consumptions.
8. Check the mode-specific cross-projection rule.

## Mode intuition

```text
isolated        -> one domain must not join different projections
pairwise        -> one domain stays within source + audience + purpose
declared-shared -> sharing is explicit and independently bounded
```

A domain name is not a secret and is not an anonymity proof.

## Common failure interpretations

- `operation-nonce-replay` — a prior committed use already consumed the nonce;
- `projection-budget-exhausted` — the projection reached its profile limit;
- `source-record-budget-exhausted` — committed uses across projections reached the source limit;
- `budget-exhausted` — the selected scoped budget reached its maximum;
- `linkability-domain-conflict` — sharing violates the selected mode.

## Human boundary

Reviewers must not infer production atomicity, audience authentication, unlinkability, erasure, confidential transport or revocation freshness from an E14-A3 `committed` result.
