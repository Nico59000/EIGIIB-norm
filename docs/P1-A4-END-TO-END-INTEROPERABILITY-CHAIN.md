# P1-A4 — End-to-End Interoperability Chain and Cross-Capsule Replay

Status: portable interoperability infrastructure. P1-A4 is not a numbered EIGIIB extension and introduces no new external-standard authority.

## Purpose

P1-A4 verifies that the checked-in P1 artifacts form one coherent chain rather than three independently valid capsules:

```text
M0-A2 aggregate report
  -> P1-A1 deterministic in-toto Statement
  -> P1-A2 signature-valid DSSE/Sigstore bundle
  -> P1-A3 hardened SCITT Signed Statement and Receipt
```

The P1-A4 result is a composition result. P1-A1, P1-A2 and P1-A3 retain authority for their own formats and verification rules.

## Exact chain descriptor

`tests/fixtures/p1-a4/chain.json` records an ordered descriptor containing:

- the exact M0-A2 report identity;
- the exact deterministic P1-A1 Statement identity;
- the exact P1-A2 bundle byte identity;
- the exact P1-A3 Signed Statement and Receipt identities;
- the three supplied public-key SPKI identities and their roles;
- the fixed replay order;
- the exact checker paths and tool versions;
- the fixed P1-A1 subject name;
- a SHA-256 identity over the canonical descriptor itself.

The chain identity binds the descriptor bytes only. It does not authenticate the source, establish trust, or prove production interoperability.

## Replay algorithm

`tools/eigiib_interop_chain.py` performs these stages.

### 1. Manifest binding

The checker validates the closed manifest shape, fixed component order, fixed paths, expected standards, key roles, checker versions, claim boundary and canonical chain identity.

Repository-relative paths are confined after resolution. A symlink that escapes the repository is rejected.

### 2. Independent cross-capsule bindings

Before invoking any upstream checker, P1-A4 verifies that:

```text
P1-A1.aggregateReport.identity == manifest.M0-A2.identity
P1-A2.binding.p1A1Statement == manifest.P1-A1-Statement.identity
P1-A2.binding.publicKeySpki == manifest.P1-A2-key.identity
P1-A3.binding.p1A2Bundle == manifest.P1-A2-bundle.identity
P1-A3.signedStatement.identity == manifest.Signed-Statement.identity
P1-A3.receipt.identity == manifest.Receipt.identity
```

The P1-A3 Issuer and Transparency Service key bindings must also match the manifest.

### 3. P1-A1 deterministic replay

P1-A4 invokes the fixed P1-A1 builder over the exact M0-A2 report and requires byte equality with the checked-in P1-A1 capsule. It then invokes the P1-A1 verifier with the exact source report.

### 4. P1-A2 authenticated replay

P1-A4 invokes the existing P1-A2 verifier with the exact P1-A1 capsule and supplied P1-A2 public key. A positive stage requires both:

```text
structural_result = conformant
signature_result = valid
```

### 5. P1-A3 hardened replay

P1-A4 invokes P1-A3-H0.2 with the exact P1-A1 capsule, P1-A2 bundle, P1-A2 key, SCITT Issuer key and Transparency Service key. A positive stage requires:

```text
hardening_result = conformant
upstream_p1a2_authentication_result = valid
p1a3_baseline_result = conformant
```

This preserves the P1-A3 Receipt and RFC9162 verification already implemented by the upstream checker.

## Fixed execution boundary

P1-A4 may execute only these repository-owned scripts:

```text
tools/eigiib_in_toto_capsule.py
tools/eigiib_sigstore_bundle.py
tools/eigib_scitt_receipt_hardening_check.py
```

Their paths, order and versions are constants in both the manifest and checker. P1-A4 does not execute a path supplied freely by a manifest and performs no network operation.

## Result carriers

The checker reports separately:

```text
manifest_binding_result
p1a1_replay_result
p1a2_replay_result
p1a3_replay_result
cross_capsule_binding_result
end_to_end_result
```

A positive end-to-end result requires every carrier to be conformant. Stage failures retain their own error codes and are not collapsed into an unsupported truth claim.

## Claim boundary

P1-A4 preserves these separations:

```text
end-to-end replay != EIGIIB claim truth
all capsules valid != production conformance
signature valid != trusted or authorized signer
receipt-bound registration != global append-only consistency
single-chain replay != E6 cross-view convergence
registration order != E11 trusted time
chain identity != source authenticity
fixture portability != live-service interoperability
composition != replacement of P1-A1/P1-A2/P1-A3 authorities
```

P1-A4 does not create signatures, private keys, network submissions, trust decisions, timestamps, consistency proofs, witness quorums or production evidence.

## Structural repository state

`conformance/p1-a4-chain.json` is structural-only. Its empty `production_replays` array makes no claim that a live in-toto, Sigstore or SCITT deployment has executed this chain.
