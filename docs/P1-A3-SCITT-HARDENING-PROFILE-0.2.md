# EIGIIB P1-A3 Hardening Profile 0.2 — Upstream Authentication Revalidation

Status: additive interoperability hardening attached to P1-A3. It is not a numbered EIGIIB extension and does not replace the P1-A3 baseline.

## Purpose

The P1-A3 baseline binds exact P1-A2 bytes into a SCITT Signed Statement and Receipt. Its repository self-check already delegates to the P1-A2 checker, but the generic baseline `verify` entry point can evaluate a shape-correct P1-A2 source without independently re-running P1-A2 signature verification.

H0.2 closes that interface gap.

A positive hardened P1-A3 result requires the exact P1-A2 source to be revalidated by the P1-A2 checker using:

- the exact P1-A1 capsule;
- the P1-A2 Ed25519 public key;
- the same exact P1-A2 bytes later consumed by P1-A3.

Only then is the P1-A3 baseline verifier invoked.

## Required conjunction

```text
P1-A2 structural_result = conformant
AND
P1-A2 signature_result = valid
AND
P1-A3 structural_result = conformant
AND
P1-A3 registration_evidence_result = receipt-bound
```

is required for:

```text
hardening_result = conformant
```

This establishes an exact authenticated-carrier handoff between P1-A2 and P1-A3. It does not promote P1-A2 signer trust or P1-A3 Transparency Service trust.

## Core separations

```text
upstream P1-A2 signature valid != trusted P1-A2 signer
P1-A3 receipt valid != trusted Transparency Service
both signatures valid != EIGIIB claim truth
upstream revalidation != key authorization
receipt-bound inclusion != global append-only consistency
```

## Reference checker

`tools/eigiib_scitt_receipt_hardening_check.py` composes the existing P1-A2 and P1-A3 reference checkers. It intentionally contains no second implementation of DSSE, Ed25519, COSE, or RFC9162 verification.

The hardened `verify` command requires explicit paths for P1-A3 capsule, P1-A2 bundle, P1-A1 capsule, P1-A2 public key, P1-A3 Issuer public key and P1-A3 Transparency Service public key.

The repository `check` command uses the canonical fixture paths.

## Non-goals

H0.2 does not add:

- trust or authorization decisions;
- network key discovery;
- production key custody;
- SCITT service discovery;
- global consistency proofs;
- trusted time;
- semantic claim validation.
