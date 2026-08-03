# E16 — External Custody, Replication, Retention and Recovery Governance

Status: closed at `E16-A5`; stable profile `EIGIIB-E16-1.0`.

## Purpose

E16 governs the transition from a closed E15 external-object record to bounded preservation governance. It separates preservation intent, logical replica binding, placement, custody acceptance, declared failure domains, retention windows, bounded observations, independent readback, restore verification, custodian succession, migration, loss, quarantine and anti-rollback recovery.

## Principal slices

- E16-A1 preserves exact E15 and M0-A7 continuity and introduces preservation intent, custodian profiles and logical replica binding.
- E16-A2 introduces placement requests, custody acceptance, declared failure domains and bounded placement observations.
- E16-A3 introduces retention windows, boundary observations, declared-independent readback and bounded restore verification.
- E16-A4 introduces custodian succession, migration, loss, quarantine and anti-rollback recovery.
- E16-A5 closes the lineage through an independent verifier matrix, differential restore replay and a final authority freeze.

## Final closure boundary

Earlier slices remain authoritative at their exact historical heads and are replayed in isolated trees. The stable profile is admitted only when the E16-A4 replay, the frozen 20-vector matrix, the two separate-process verifier routes, canonical report agreement, the final manual gate and the 95-authority freeze are conformant.

## State separation

Gate values are `permit`, `deny`, `held`, and `unavailable`. Final matrix states are `e16-preservation-closure-verified`, `rejected`, `held`, and `unavailable`. Known negative evidence takes precedence over unavailable and held evidence.

## Nonclaims

E16 does not establish physical or legal custody transfer, real verifier or failure-domain independence, continuous retention, indefinite durability, globally trusted time, complete loss detection, complete quarantine enforcement, future restore success, external-service honesty, collusion resistance, universal verifier correctness, universal availability, universal interoperability, or external durability of the final freeze.
