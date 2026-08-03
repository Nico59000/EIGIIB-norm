# E16-A3 — Retention Windows, Bounded Preservation Observations, Independent Readback and Restore Verification

Status: adopted as the third principal slice of E16.

## 1. Scope

E16-A3 governs repository interpretation of declared retention windows, observations made at bounded window positions, declared-role-separated readback, restore execution and restore verification after a positive E16-A2 placement decision.

The slice owns six record families:

1. retention windows;
2. bounded preservation observations;
3. independent readbacks;
4. restore attempts;
5. restore verifications;
6. preservation-verification decisions.

Every record is revisioned and commitment-bound. References resolve by identifier, revision and commitment.

## 2. Historical entry

Current-tree E16-A3 evaluation begins only after byte-exact materialization and replay of the E16-A2 source commit:

`1bd5929a5a4415df8758b220765925ac80a797bc`.

The replay validates the exact E16-A2 report, its exact historical E16-A1 replay and the targeted E16-A2 tests in an isolated source tree. E16-A3 does not rewrite the E16-A2 registry, transition, authority freeze, claims or nonclaims.

## 3. Retention window

A retention window binds:

- one exact positive E16-A2 placement decision;
- its exact placement request;
- the content SHA-256 and byte count;
- one declared UTC opening boundary;
- one declared UTC closing boundary;
- one versioned clock-basis declaration;
- mandatory opening and closing observations;
- an idempotency key.

The boundaries are represented claims. Conformance does not establish globally trusted time, continuous observation, future retention or provider honesty.

## 4. Bounded preservation observation

A preservation observation binds the exact retention window and exact E16-A2 placement observation. It records an observer, method, represented UTC instant, boundary role, observed content identity, state and evidence references.

Boundary roles are:

- `opening`;
- `intermediate`;
- `closing`.

An opening observation binds the exact declared opening boundary. A closing observation binds the exact declared closing boundary.

Two positive boundary observations establish only two positive represented observation events. They do not prove uninterrupted preservation between them.

## 5. Independent readback

An independent readback binds the exact window and closing observation. It records:

- a reader identity and declared control domain;
- a custodian identity and declared control domain;
- a readback method;
- returned content identity;
- one of `positive`, `negative`, `inconclusive` or `unavailable`;
- evidence references.

A positive readback requires distinct declared reader and custodian identities and distinct declared control domains. Different declarations do not prove actual organizational, administrative, physical or cryptographic independence.

## 6. Restore attempt

A restore attempt binds the exact positive readback and retention window. It records an executor, declared ephemeral target environment, restore method, restored content identity, state and evidence references.

Attempt states are:

- `completed`;
- `failed`;
- `held`;
- `unavailable`.

A completed attempt is bounded to that represented execution. It does not prove future restorability.

## 7. Restore verification

A restore verification binds the exact restore attempt. It records a verifier and executor, their declared control domains, verification method, verified content identity, state and evidence references.

A positive verification requires distinct declared verifier and executor identities and distinct declared control domains. Different declarations do not prove actual independence.

## 8. Decision derivation

The checker derives seven gates:

- E16-A2 placement;
- retention-window integrity;
- opening observation;
- closing observation;
- independent readback;
- restore attempt;
- restore verification.

Gate precedence is:

1. any `deny` produces `rejected`;
2. otherwise any `unavailable` produces `unavailable`;
3. otherwise any `held` produces `held`;
4. otherwise the decision is `bounded-preservation-and-restore-verified`.

A stored decision must reproduce the derived gates and state exactly.

## 9. Negative evidence

Known negative evidence includes, at minimum:

- source placement substitution or a non-positive source placement decision;
- window or commitment substitution;
- invalid or reversed boundaries;
- boundary-role or boundary-time mismatch;
- content digest or byte-count mismatch;
- a negative preservation observation;
- same declared identity or control domain where role separation is required;
- a negative readback;
- a failed restore attempt;
- a negative restore verification.

Known negative evidence is not weakened to `held` or `unavailable`.

## 10. Authority boundary

The slice-local authority manifest is:

`conformance/e16-a3-authority-manifest.json`.

It binds the contract, registry, schemas, checker, historical replay, transition, freeze, tests, workflow and review guidance. The descendant freeze excludes itself from its frozen member set.

## 11. Nonclaims

Conformance does not establish:

- continuous preservation between observations;
- globally trusted time;
- future retention or durability;
- actual reader, custodian, executor or verifier independence;
- physical or administrative separation;
- resistance to correlated failure;
- future readback or future restorability;
- legal custody or ownership;
- administrative deletion prevention;
- external-service honesty;
- universal availability or interoperability.
