# EIGIIB-E7 — Recovery hardening profile 0.2

**Status:** supplementary hardening profile for EIGIIB-E7 draft 1.0  
**Requires:** EIGIIB-E7 draft 1.0  
**Reference checker:** `tools/eigiib_recovery_hardening_check.py`

This profile does not create a new extension layer. It closes mechanically decidable gaps inside E7 while preserving the E7 claim boundary.

## Additional mechanical invariants

1. A transition carries an explicit incident identity; its actions do not cross incident boundaries implicitly.
2. A transition labelled `verified` is counted as mechanically verified only when its hardening checks have no error.
3. Declared E4/E5/E6 bindings of a verified transition must resolve before that transition is counted.
4. A recovery plan cannot silently include actions owned by another incident.
5. A rollback record preserves a non-empty reason and incident-bounded compensating actions.
6. When a rollback names a replacement transition, that transition belongs to the same incident and ends at an epoch later than the superseded destination.
7. A `reopened` decision corresponds to an incident currently marked `reopened`.
8. A reopen record should preserve the prior closure and the new contradicting evidence. Omission is a warning rather than a hard failure because E7 draft 1.0 states this provenance preservation as `SHOULD`.
9. Optional E7 evidence bindings to E4, E5, or E6 are checked when supplied; they are not promoted into stronger semantics.
10. Hardening remains static: no remediation command, trust-store mutation, cryptographic verification, Merkle verification, network collection, intent inference, or root-cause inference is performed.

## Capability discipline

A label such as `verified` is data, not proof. The hardening checker reports a verified transition count only for objects that satisfy the hardening invariants. A contradictory object may remain present for evidence preservation, but it does not contribute to a positive capability result.

## Relationship to the baseline checker

`tools/eigiib_recovery_check.py` remains the E7 draft 1.0 baseline checker. The hardening checker is an additive gate. Repository CI should require both until these invariants are folded into a later E7 revision.
