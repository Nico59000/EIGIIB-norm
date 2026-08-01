# P1-A10 — Delegated Release Authorization, Threshold Approval and Revocation Replay

## Purpose

P1-A10 adds a bounded authorization layer above the authenticated P1-A9 release. A supplied Ed25519 trust root signs an exact delegation policy. The policy binds the P1-A9 release signer key and the exact P1-A8 release descriptor, delegates the `release-approver` role to three public keys, and requires two distinct approvals.

The claim `trusted release signer` means trusted relative to the supplied root and signed policy. The claim `authorized release signer` means authorized for the exact release descriptor and release id. Neither result establishes a real-world identity, organizational control or production deployment.

## Fixed release scope

```text
release id:
eigiib-p1-a7-authority-1.0

release descriptor SHA-256:
1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec

P1-A9 release-signer SPKI SHA-256:
c5310a741895b555fb1185b85502aa58ad4e8399809a244143e158216a6c5cbd
```

## Policy and threshold

The root-signed policy has:

- policy id `eigiib-p1-a10-release-policy-1`;
- policy sequence 1;
- role `release-approver`;
- delegates `delegate-a`, `delegate-b`, `delegate-c`;
- threshold 2 of 3;
- exact release-descriptor and release-signer bindings;
- the trust root itself as revocation authority.

All policy, approval and revocation signatures are deterministic COSE_Sign1 Ed25519 objects with canonical CBOR, protected algorithm, content type and SPKI-derived key id.

## Replay

1. At authorization sequence 10, approvals from A and B meet the threshold.
2. At revocation sequence 11, the root revokes B for evaluations at or after sequence 11.
3. At evaluation sequence 12, replaying the cryptographically valid A+B authorization leaves only A active and is rejected.
4. A fresh sequence-12 authorization approved by A and C restores the 2-of-3 threshold and becomes the current authorized state.

Sequences are logical ordering coordinates. They do not establish trusted wall-clock time.

## Three routes

- `reference-python-openssl`: dependency-free canonical CBOR and OpenSSL Ed25519 verification;
- `independent-go-stdlib`: independent strict JSON, canonical CBOR and `crypto/ed25519` implementation;
- `external-go-cose`: separate strict route using `fxamacker/cbor v2.5.0` and `go-cose v1.3.0`.

Portable equality covers release scope, trust root, policy envelope, threshold, delegates, revocation sequence, approval sets, acceptance and final boundary. External-library diagnostic text is excluded.

## Final boundary

```text
recovered-threshold-authorization
```

## Explicit non-claims

P1-A10 does not establish real-world signer identity, organizational possession of the root key, trusted time, content revocation, distribution withdrawal, vulnerability remediation, live publication, production governance or universal interoperability.
