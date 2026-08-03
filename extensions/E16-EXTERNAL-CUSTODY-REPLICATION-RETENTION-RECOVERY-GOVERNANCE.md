# E16 — External Custody, Replication, Retention and Recovery Governance

Status: adopted through `E16-A2`; later slices remain unimplemented.

## Purpose

E16 governs the transition from a closed E15 external-object record to bounded preservation governance. It separates preservation intent, logical replica binding, observed placement, custody acceptance, retention evidence, readback, restoration, loss, migration and succession.

## E16-A1 boundary

E16-A1 owns:

- exact historical E15 and M0-A7 authority continuity;
- versioned custodian profiles;
- versioned replica profiles;
- versioned preservation policies;
- preservation intents bound to an exact positive E15 publication and lifecycle decision;
- logical replica bindings;
- repository decisions with negative precedence.

A logical replica binding is not proof that bytes were placed, accepted by an external custodian, retained, independently stored or restorable.

## E16-A2 boundary

E16-A2 adds:

- placement requests bound to an exact admissible E16-A1 replica binding;
- custody-acceptance records bound to the same custodian, replica and content identity;
- versioned failure-domain declarations;
- placement observations bound to exact request, acceptance and declaration commitments;
- placement decisions derived from typed gates with known-negative precedence.

A placement observation is bounded evidence for the referenced observation event. A custody acceptance is an operational record, not a transfer of legal ownership. Failure-domain labels are declarations and do not prove physical separation, provider independence or resistance to correlated failure.

## State separation

Gate values are `permit`, `deny`, `held`, and `unavailable`.

E16-A1 decisions are `admissible`, `rejected`, `held`, and `unavailable`.

E16-A2 placement decisions are `placement-observed`, `rejected`, `held`, and `unavailable`.

These vocabularies are not aliases for external truth. Known negative evidence takes precedence over held and unavailable conditions. Equal identifiers, locators or provider labels do not establish physical identity or independence; different labels do not establish physical separation.

## Planned continuation

- E16-A3: retention windows, bounded observations, independent readback and restore verification;
- E16-A4: custodian succession, migration, loss, quarantine and anti-rollback recovery;
- E16-A5: independent verifier matrix, differential restore replay and final freeze.

## Nonclaims

E16-A2 does not establish legal custody or ownership, provider independence, failure-domain separation, future retention, future restorability, indefinite durability, universal availability, administrative deletion prevention, external-service honesty, globally trusted time, collusion resistance or universal interoperability.
