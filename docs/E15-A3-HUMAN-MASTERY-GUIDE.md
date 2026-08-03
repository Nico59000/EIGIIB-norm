# E15-A3 Human Mastery Guide

## Purpose

E15-A3 starts only after an exact E15-A2 decision has reached `externally-attested`. It records what an external publisher states, what bounded observations later report, and what an independently scoped readback obtains.

## Four separate objects

1. `external_publication_record` binds one exact A2 attempt and decision to a publisher, locator, mechanism, policy and payload commitment.
2. `bounded_persistence_observation` records a time-bounded presence, absence, mismatch or unavailability observation.
3. `independent_readback` records an actual read route and its declared independence dimensions.
4. `publication_lifecycle_decision` derives one bounded lifecycle result from the exact records it consumes.

None of these objects substitutes for another.

## Independence

Independence is evaluated by declared dimensions: principal, provider, implementation, process and network path. A different process is not automatically a different provider. The policy states which dimensions are mandatory.

## Persistence

A positive persistence result requires the configured number of positive observations and the configured minimum spacing. It proves only those observations at those times and locators. It does not prove future availability or indefinite retention.

## Readback

A positive readback requires exact locator and payload binding, matching digest, matching byte count and every required independence dimension. Digest equality establishes byte identity only; it does not establish semantic truth or publisher honesty.

## Lifecycle states

- `not-published`: no positive publication event is established;
- `publication-observed`: publication is positive but the bounded persistence policy is not yet satisfied;
- `persistence-observed`: bounded persistence is satisfied but no qualifying positive readback is established;
- `independently-read-back`: publication, bounded persistence and required independent readback all pass;
- `rejected`, `contested`, `unavailable` and `held`: bounded negative or incomplete outcomes.

## Historical continuity

The checker consumes a report from `tools/eigiib_historical_e15_a2_replay.py`. That tool materializes exact E15-A2 commit `25988d80571f0f8d3587d976810a2dd8e0ce2328` in an isolated tree, replays its historical chain and executes its unit tests before A3 is interpreted.

## Nonclaims

E15-A3 does not establish universal public access, provider independence beyond the declared dimensions, indefinite durability, global nonexistence, withdrawal, erasure, legal recall or universal interoperability.
