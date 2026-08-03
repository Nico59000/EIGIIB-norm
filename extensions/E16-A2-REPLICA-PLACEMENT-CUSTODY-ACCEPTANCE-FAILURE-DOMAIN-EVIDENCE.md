# E16-A2 — Replica Placement, Custody Acceptance, Failure-Domain Declaration and Placement Evidence

Status: adopted as the second principal slice of E16.

## 1. Scope

E16-A2 governs repository interpretation of bounded placement evidence after an E16-A1 preservation decision has admitted a logical replica binding.

The slice owns five record families:

1. placement requests;
2. custody acceptances;
3. failure-domain declarations;
4. placement observations;
5. placement decisions.

Every record is revisioned and commitment-bound. References resolve by identifier, revision and commitment, not by identifier alone.

## 2. Historical entry

Current-tree E16-A2 evaluation begins only after byte-exact materialization and replay of the E16-A1 source commit:

`7fd50a2009c6a437c7fe0b680407cf337b55cf4f`.

The historical replay validates the E16-A1 preservation-intent report and its targeted tests in an isolated source tree. E16-A2 does not rewrite the E16-A1 registry, transition, authority freeze, claims or nonclaims.

## 3. Placement request

A placement request binds:

- one exact E16-A1 replica binding;
- the source preservation intent;
- the custodian and replica revisions;
- the content SHA-256 and byte count;
- the requested failure-domain dimensions;
- a purpose, action, evaluation context and idempotency key.

A request authorizes repository evaluation. It does not prove execution, acceptance, placement, retention or availability.

## 4. Custody acceptance

A custody acceptance binds the exact placement request and repeats its custodian, replica and content identity. Its state is one of:

- `accepted`;
- `rejected`;
- `held`;
- `unavailable`.

`accepted` means only that the represented custodian record accepted the represented scope for the represented request. It is not a legal ownership transfer, a retention promise or proof that bytes exist at a physical location.

## 5. Failure-domain declaration

A failure-domain declaration records versioned labels for operational dimensions such as provider, account, region, facility, administrative control, control plane, storage implementation, network, power and encryption-key domain.

The declaration state is `active`, `retired`, `contested` or `unavailable`.

These labels are declarations. Matching labels may indicate possible common control; differing labels do not prove independence or physical separation.

## 6. Placement observation

A placement observation binds exact request, acceptance and failure-domain declaration commitments. It records:

- observer identity and revision;
- an observation method;
- observed content identity;
- one of `positive`, `negative`, `inconclusive` or `unavailable`;
- evidence references.

A positive observation is bounded to that observation event. It does not prove future persistence, independent readback, retention-window satisfaction or restorability.

## 7. Decision derivation

The checker derives six gates:

- E16-A1 binding;
- request integrity;
- custody acceptance;
- content identity;
- failure-domain declaration;
- placement observation.

Gate precedence is:

1. any `deny` produces `rejected`;
2. otherwise any `unavailable` produces `unavailable`;
3. otherwise any `held` produces `held`;
4. otherwise the decision is `placement-observed`.

A stored placement decision must reproduce the derived gates and state exactly.

## 8. Negative evidence

Known negative evidence includes, at minimum:

- an inadmissible or substituted E16-A1 binding;
- request, acceptance, declaration or observation reference substitution;
- content digest or byte-count mismatch;
- explicit custody rejection;
- a retired failure-domain declaration;
- a negative placement observation;
- a commitment mismatch.

Known negative evidence is not weakened to `held` or `unavailable`.

## 9. Authority boundary

The slice-local authority manifest is:

`conformance/e16-a2-authority-manifest.json`.

It binds the contract, registry, schemas, checker, historical replay, transition, freeze, tests, workflow and review guidance. The descendant authority freeze is byte-exact and excludes itself from its frozen member set.

## 10. Nonclaims

Conformance does not establish:

- legal custody or ownership;
- physical separation;
- provider or administrative independence;
- resistance to correlated failure;
- future retention or durability;
- independent readback;
- restore success or future restorability;
- administrative deletion prevention;
- external-service honesty;
- globally trusted time;
- universal availability or interoperability.
