# EIGIIB-E9 — Degraded Operation Hardening Profile 0.2

**Status:** Additive hardening profile  
**Requires:** EIGIIB-E9 1.0  
**Reference checker:** `tools/eigiib_degraded_hardening_check.py`

This profile closes three mechanically decidable false-positive boundaries discovered after the first complete E1→E9 replay.

## H1. Evidence item materiality

An observation or fallback evidence item used by the E9 registry MUST be either:

- a non-empty typed evidence identifier; or
- a repository-confined object carrying a non-empty `path`.

An empty string, empty object, or unrelated object does not satisfy evidence presence merely because the evidence array is non-empty.

## H2. Guarantee partition coherence

For every E9 mode:

```text
preserved_guarantees ∩ suspended_guarantees = ∅
```

A guarantee MUST NOT be simultaneously claimed as preserved and suspended within the same mode.

## H3. Capability minimum survives fallback

Fallback substitution MUST NOT weaken a capability's own `minimum_availability`.

If capability `c` requires `available` and its direct dependency is replaced by a fallback, the selected substitute MUST itself be observed `available` in the decision closure. A merely `degraded` substitute cannot satisfy that capability even when degraded dependencies are otherwise policy-permitted.

This rule is separate from policy-level required dependencies: a policy may explicitly tolerate degraded infrastructure while an individual capability remains unavailable because its own minimum is stricter.

## Boundary

The hardening checker remains static. It does not probe dependencies, activate fallbacks, execute routing changes, assess semantic equivalence of substitutes, or infer global trust/availability.
