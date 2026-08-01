# P1-A9 — Authenticated Release Envelope, Transparency Registration and Supersession Replay

## Purpose

P1-A9 adds authentication and fixture transparency evidence to the exact P1-A8 release authority. It does not create a second content release. The predecessor is the detached A8 digest authority; the successor is an authenticated envelope over the same release descriptor.

## Source authority

The DSSE payload is byte-for-byte `tests/fixtures/p1-a8/expected-release.json` from P1-A8. Its SHA-256 is `1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec` and its release id is `eigiib-p1-a7-authority-1.0`.

## Authenticated release envelope

The fixed profile uses:

- payload type `application/vnd.eigiib.release+json`;
- exactly one Ed25519 DSSE signature;
- key id `p1-a9-ed25519-spki-sha256:<SPKI SHA-256>`;
- one explicitly supplied Ed25519 SubjectPublicKeyInfo.

The envelope SHA-256 is `ce1286285115917ddce92b8746087f97820029ff417ede1886390ce09c2ba718`.

Signature validity proves only consistency relative to the supplied public key. It does not establish maintainer identity, trust, authorization or signing time.

## Transparency registration

P1-A9 creates two deterministic COSE_Sign1 Signed Statements:

1. one binding the authenticated release envelope;
2. one binding the authenticated supersession envelope.

They are the two leaves of one RFC9162 SHA-256 tree. Each has a detached-payload COSE Receipt with a one-sibling inclusion proof and an Ed25519 signature under a supplied transparency-service key.

The common root is `12bb270bb723153bebb17c56d293780c2866e325e87182d958250e05a8a4f066`.

The HTTP `POST /entries`, `201` and `Location` carriers are offline fixture transcripts only. They are not live network observations or durability evidence.

## Supersession semantics

The relation is exactly `authority-carrier-upgrade`:

```text
detached A8 release-digest authority, sequence 0
    -> authenticated release envelope, sequence 1
```

The relation requires:

- the same release id on both nodes;
- byte-identical release descriptor identity in predecessor and preservation carrier;
- exact successor-envelope identity;
- strict sequence increase from zero to one;
- one edge, no cycle and one current authority.

It does not revoke the A8 bytes, withdraw a distribution, fix a vulnerability or establish an effective legal time.

## Three routes

- `reference-python-openssl`: strict JSON, deterministic CBOR and OpenSSL Ed25519 verification;
- `independent-go-stdlib`: independent strict JSON, CBOR, DSSE, Ed25519 and RFC9162 implementation;
- `external-go-cose`: separate Go route using `fxamacker/cbor v2.5.0` and `go-cose v1.3.0` for COSE processing.

Portable equality covers release id, release descriptor identity, both envelope identities, transparency root, entry count, acceptance and final boundary. Library-specific diagnostics are not portable evidence.

## Explicit non-claims

P1-A9 does not establish a trusted or authorized signer, a trusted transparency service, global append-only consistency, trusted time, content revocation, security remediation, external publication, external durability, production release policy correctness or universal interoperability.

## Inherited A7.7 runner-policy revision

The original P1-A7.7 toolchain policy and semantic authority root remain byte-exact and unchanged. During P1-A9 validation, the hosted `windows-2025` pool was observed in two exact distribution states:

- image `20260714.173.1` with Git `2.55.0.windows.2`;
- image `20260728.188.1` with Git `2.55.0.windows.3`.

Python `3.13.14`, Go `go1.26.5`, OpenSSL `3.5.7`, the action pins, all forty A7 tests and every A7.1–A7.6 replay remained unchanged and conformant in both states.

P1-A9 therefore retains the original A7.7 policy for the first pair and registers `tests/fixtures/p1-a9/a7.7-toolchain-policy-revision.json` for the second. The inherited workflow selects a policy only after matching the observed Windows image/Git pair against this closed two-entry allowlist. Any third pair is rejected before authority registration.

This descendant distribution compatibility layer does not alter the thirteen-file A7 semantic inventory, the A7 authority root `e338247156165c48b7b1ce88a69f24123defc0162b1f3f6a58c4ecd510e105be`, or the canonical A7 report. It does not generalize compatibility to future runner revisions.

## A8 offline-publication replay compatibility

The P1-A8 archive, release descriptor, manifest and registered digests remain byte-exact. On a P1-A9 descendant checkout, the inherited A8 workflow selects `tools/eigiib_p1_a9_a8_compat_replay.py`. The wrapper first invokes the unchanged A8 publication verifier with offline replay disabled, requiring publisher byte equality, USTAR closure and all registered A8 digests. It then independently extracts the same archive and executes A7.1 through A7.7 outside Git.

For the final A7.7 authority call, the wrapper applies the same closed Windows image/Git selector as the inherited A7 workflow. The original policy is used for `20260714.173.1 / Git 2.55.0.windows.2`; the additive revision is used for `20260728.188.1 / Git 2.55.0.windows.3`; every other pair is rejected. The revision is supplied from the descendant checkout and is not inserted into, or substituted for, any archive entry. Consequently the A8 bundle SHA-256, source-tree root and release authority remain unchanged.
