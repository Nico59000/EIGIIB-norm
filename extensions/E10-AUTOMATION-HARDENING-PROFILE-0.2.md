# EIGIIB-E10 — Automation Hardening Profile 0.2

**Status:** Additive hardening profile for EIGIIB-E10 draft 1.0  
**Reference checker:** `tools/eigiib_automation_hardening_check.py`

## Purpose

This profile closes one accountability boundary identified after the first successful E1→E10 replay: a negative or unavailable decision must remain bound to the exact proposal, policy and context revisions on which that decision was recorded.

The following implication is invalid:

```text
decision not authorized != revision binding unimportant
```

A `denied`, `held`, or `unavailable` decision can materially affect later reasoning, retries, escalation, audit, or remediation. It therefore MUST NOT silently point to a different policy/context boundary or stale revision merely because it did not authorize execution.

## Additional invariant

For every E10 decision `D` whose proposal `P`, policy `Q`, and context `C` resolve, the hardening profile requires:

```text
P.policy  = D.policy
P.context = D.context
D.proposal_revision = P.revision
D.policy_revision   = Q.revision
D.context_revision  = C.revision
```

This applies uniformly to:

```text
authorized
denied
held
unavailable
```

The baseline E10 checker remains authoritative for positive authorization, delegation, approvals, execution, effects and accountability traces. This profile adds no execution capability and does not convert a negative decision into a positive claim.

## Boundary

Exact revision binding is a repository identity relation. It is not trusted wall-clock freshness, proof that the policy was legitimate, proof that the decision was correct, or proof of real-world accountability.
