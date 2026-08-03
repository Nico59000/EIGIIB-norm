# E15-A4 Manual Review — Withdrawal, Tombstones and Post-Delivery Governance

Status: complete.

## Reviewed boundary

The review confirms that E15-A4 consumes only an exact E15-A3 publication record and an exact E15-A3 lifecycle decision whose state already establishes a bounded publication observation. It does not reinterpret the underlying delivery or publication evidence.

The following object families remain distinct:

- withdrawal authority profiles;
- distribution operator profiles;
- distribution target profiles;
- withdrawal policies and requests;
- registry tombstones;
- distribution-stop records;
- bounded post-withdrawal observations;
- withdrawal lifecycle decisions.

## Safety properties reviewed

- withdrawal requests bind the exact publication, exact E15-A3 decision and exact payload identity;
- one authority cannot substitute for a distribution operator;
- one target cannot substitute for another target;
- tombstone and stop histories are commitment-chained and evaluated at their latest referenced heads;
- a later removal or resumption defeats a stale installed/stopped record;
- positive post-withdrawal observations are bounded by target, locator, observer and time;
- `not-found` at one registered target is not global erasure;
- `unreachable` is not interpreted as absence;
- a withdrawal request does not prove execution;
- a tombstone does not prove deletion;
- a distribution stop does not recall previously obtained bytes.

## Historical continuity

The exact E15-A3 head `f403e93dd6d1dcb058474d67f2cc7e73b8ad13bd` is materialized and replayed in an isolated tree before A4 interpretation. E15-A3 authorities are not rewritten. The current descendant test profile is isolated from the historical A3 profile and frozen separately.

## Reserved scope

E15-A4 does not own the independent external-evidence verifier matrix, differential external replay or final E15 authority freeze. Those remain reserved for E15-A5.

It also does not establish global erasure, recipient-side deletion, legal recall, universal propagation, unregistered-mirror closure, future retention behavior or external-service honesty.
