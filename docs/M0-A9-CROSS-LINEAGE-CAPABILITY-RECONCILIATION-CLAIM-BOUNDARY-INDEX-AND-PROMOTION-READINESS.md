# M0-A9 — Cross-Lineage Capability Reconciliation, Claim-Boundary Index and Promotion Readiness

## Purpose

M0-A9 reconciles the exact P1-A15 through P1-A20 capability authorities with the closed E15 and E16 boundaries after M0-A8 publication normalization.

It is a governance and interpretation slice. It does not repeat P1 proof content, mutate the `EIGIIB-E16-1.0` profile, modify the extension graph, publish a new external object or adopt E17.

## Exact source

- parent branch: `agent/m0-a8-authoritative-lineage-publication-default-branch-reconciliation-pr-topology-closure`;
- parent head: `232e8574f23fb2162a6fdf7fa24338e7aaf987d6`;
- stable E16 branch: `stable/eigiib-e16-1.0`;
- stable E16 head: `fc3f8402bfbe447227f5777bad92b620c7bcb350`;
- canonical P1 authority: `conformance/m0-a5-p1-lineage.json`.

Every reconciled capability is consumed by exact state path, exact standard, exact boundary and exact canonical head.

## Claim classes

M0-A9 keeps five classes separate:

1. **established-bounded** — established only in the exact source scope;
2. **declared-policy-only** — a policy exists without implying enforcement or future fulfillment;
3. **observed-current** — the represented external state was observed at capture or replay time;
4. **promotion-candidate** — the mechanism may be applied to a new artifact only through a new bounded operation;
5. **not-established** — the property cannot be inferred from the reconciled evidence.

No class conversion is automatic.

## Reconciled capabilities

- P1-A15: named GitHub Release, closed asset identity and authenticated/public readback;
- P1-A16: named OCI/GHCR publication, public readback and cross-registry digest identity;
- P1-A17: observed two-location replication, signed retention-policy declaration and restore from each named location;
- P1-A18: signed fixture governance, two-approval normal route and bounded reviewed emergency route;
- P1-A19: registered profile matrix, capability negotiation and downgrade rejection;
- P1-A19-F2: Draft 2020-12 closed-schema enforcement;
- P1-A20: signed fixture runner admission, toolchain succession and single-use rollback replay.

Each record repeats the source nonclaims that prevent scope broadening.

## Promotion readiness

`M0-A10 — Stable E16 Normative Bundle, Dual-Channel Publication and Exact External Readback` is classified as `ready-for-bounded-implementation`.

That decision means only that the required mechanisms already have validated precedents. M0-A10 must still perform a new operation against the exact stable E16 bundle and capture new evidence.

E17 remains `not-ready-for-adoption`. It requires new evidence for real external control-domain independence, correlated-failure modelling, long-horizon observation, multi-authority deletion or quarantine and an independent live-evidence matrix.

## Decision

The positive M0-A9 state is:

`cross-lineage-capability-boundaries-reconciled`

Unknown claim boundaries deny. Historical heads remain unchanged. P1 content owners remain the original slice documents and state files.
