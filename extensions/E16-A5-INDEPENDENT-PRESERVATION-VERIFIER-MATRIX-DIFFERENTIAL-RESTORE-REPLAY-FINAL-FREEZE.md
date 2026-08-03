# E16-A5 — Independent Preservation Verifier Matrix, Differential Restore Replay and Final Freeze

Status: final E16 closure profile.

## Purpose

E16-A5 closes the E16 lineage by replaying the exact E16-A4 authority, evaluating a frozen preservation corpus through two separately implemented verifiers, comparing their canonical reports, promoting the E16 profile to `EIGIIB-E16-1.0`, and freezing the final authority surface.

## Historical boundary

E16-A1 through E16-A4 remain authoritative at their exact historical heads. Their checkers, registries, transitions, fixtures and freezes are replayed in isolated source trees. Stable-profile interpretation begins only after that replay succeeds. E16-A5 does not reinterpret an earlier positive observation as a stronger claim.

## Independent verifier matrix

The matrix contains frozen positive, negative, held and unavailable vectors. Each verifier is executed as a separate process and does not import or reference the other implementation. Declared implementation separation is mechanically checked; it is not proof of organizational or operational independence.

A positive vector requires at least three distinct route identifiers and three distinct declared verifier domains. Every route must bind the same content digest and accepted generation and must report a positive restore result. Known negative evidence has priority over held and unavailable conditions.

## Differential restore replay

The two canonical verifier reports must be byte-identical for every vector. The matrix rejects stale lineage, rejected A4 recovery, insufficient independence, incomplete coverage, rollback, target loss, target quarantine, non-conformant freeze, route mismatch, content mismatch, generation mismatch and duplicate route or domain declarations.

A positive matrix result establishes only agreement of the registered implementations over the frozen corpus. It does not prove universal verifier correctness or future restore success.

## Final closure

The final closure requires exact E16-A4 ancestry and replay, complete matrix agreement, the stable E16 profile, a conformant extension graph, the complete final manual gate and byte identity of all frozen authorities. Failure of any component leaves E16 open.

## Evidence priority

Gate values are `permit`, `deny`, `held`, and `unavailable`. Final vector states are `e16-preservation-closure-verified`, `rejected`, `held`, and `unavailable`. `deny` precedes `unavailable`, which precedes `held`.

## Nonclaims

E16-A5 does not establish physical or legal custody transfer, real verifier or failure-domain independence, continuous retention, indefinite durability, globally trusted time, complete loss detection, complete quarantine enforcement, future restore success, external-service honesty, collusion resistance, universal verifier correctness, universal availability, universal interoperability, or external durability of the final freeze.
