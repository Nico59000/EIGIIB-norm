# E16 — External Custody, Replication, Retention and Recovery Governance

Status: adopted at `E16-A1`; later slices remain unimplemented.

## Purpose

E16 governs the transition from a closed E15 external-object record to bounded preservation governance. It separates preservation intent, logical replica binding, observed placement, custody acceptance, retention evidence, readback, restoration, loss, migration and succession.

## E16-A1 boundary

E16-A1 owns only:

- exact historical E15 and M0-A7 authority continuity;
- versioned custodian profiles;
- versioned replica profiles;
- versioned preservation policies;
- preservation intents bound to an exact positive E15 publication and lifecycle decision;
- logical replica bindings;
- repository decisions with negative precedence.

A logical replica binding is not proof that bytes were placed, accepted by an external custodian, retained, independently stored or restorable.

## State separation

Gate values are `permit`, `deny`, `held`, and `unavailable`. Derived A1 decisions are `admissible`, `rejected`, `held`, and `unavailable`. These vocabularies are not aliases for external evidence.

Known negative evidence takes precedence over held and unavailable conditions. Equal identifiers, locators or provider labels do not establish physical identity or independence.

## Planned continuation

- E16-A2: placement requests, custody acceptance, failure-domain declarations and observations;
- E16-A3: retention windows, bounded observations, independent readback and restore verification;
- E16-A4: custodian succession, migration, loss, quarantine and anti-rollback recovery;
- E16-A5: independent verifier matrix, differential restore replay and final freeze.

## Nonclaims

E16-A1 does not establish physical placement, custody acceptance, legal custody or ownership, provider independence, failure-domain separation, future retention, future restorability, indefinite durability, universal availability, administrative deletion prevention, external-service honesty, globally trusted time, collusion resistance or universal interoperability.
