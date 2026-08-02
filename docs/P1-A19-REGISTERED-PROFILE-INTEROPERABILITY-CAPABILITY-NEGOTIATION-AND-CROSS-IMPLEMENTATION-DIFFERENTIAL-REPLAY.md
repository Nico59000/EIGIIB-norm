# P1-A19 — Registered Profile Interoperability, Capability Negotiation and Cross-Implementation Differential Replay

## 1. Scope

P1-A19 extends exact P1-A18 commit `be2eda2c9a86c703c6d486599d1062143c228ca9`. It binds the P1-A18 governance result to a signed registry of explicitly named and versioned interoperability profiles, a deterministic capability-negotiation transcript and differential replay by independent Python and Go implementations.

The slice closes only the declared active profile matrix. It does not claim universal interoperability, compatibility with future unregistered profiles or runners, semantic equivalence of all carrier formats, or automatic acceptance of unknown extensions.

## 2. Registered matrix

The active registry contains six profiles:

- `eigiib.native@1.1`;
- `in-toto.statement@1.0`;
- `sigstore.bundle@0.3`;
- `scitt.receipt@1.0`;
- `oci.distribution@1.1`;
- `github.release-carrier@1.0`.

Two historical entries remain registered but deprecated: `eigiib.native@1.0` and `sigstore.bundle@0.2`. Their presence permits explicit downgrade replay; their registration does not make them admissible when an active version is required.

Each entry freezes required capabilities, optional capabilities, a claim vocabulary and critical extensions. The canonical registry is signed with Ed25519 by `p1-a19-profile-registrar-v1`.

## 3. Capability negotiation

For an active source and target profile, the selected capability set is the sorted exact intersection of both supported sets. Every required capability of either side must be present in that intersection. The transcript is not allowed to omit a mutually supported capability, inject an unsupported capability or reorder the canonical set.

The transcript binds:

- exact P1-A18 commit and report digest;
- exact registry digest;
- fixture environment `p1-a18-fixture-production`;
- source and target profile identifiers and active versions;
- selected and dropped capabilities;
- portable claims;
- all critical extensions;
- route identifier and final decision.

## 4. Claim-boundary preservation

A target profile may preserve a subset of source claims. It may not introduce a semantic claim absent from the source route. Both source and target claims must belong to their registered vocabularies. Format-specific carrier fields are capabilities, not automatic semantic claims.

This distinction prevents a transport conversion from upgrading provenance, governance, transparency or distribution assertions merely because the destination format has a field capable of carrying such data.

## 5. Positive route matrix

Six routes are closed:

1. EIGIIB native to in-toto statement;
2. EIGIIB native to Sigstore bundle;
3. EIGIIB native to SCITT receipt;
4. EIGIIB native to OCI distribution;
5. OCI distribution to GitHub Release carrier;
6. Sigstore bundle to SCITT receipt.

The matrix demonstrates registered route interoperability only. It does not assert that in-toto, Sigstore, SCITT, OCI and GitHub Release have identical trust or governance semantics.

## 6. Negative replay

Twenty-five mutations cover unknown profiles, active-version rollback, registry alteration, unknown mandatory capability, required-capability failure, capability stripping and injection, noncanonical ordering, artifact and environment substitution, registry substitution, profile substitution, claim expansion, vocabulary violation, unknown or stripped critical extensions, duplicate route identifiers and registry-signature alteration.

Every mutation must be rejected rather than negotiated down implicitly.

## 7. Differential implementations

The Python reference implementation and independent Go implementation parse the same frozen bundle, verify the Ed25519 registry signature, recompute all six transcripts and emit byte-identical canonical reports. A separate OpenSSL route verifies the registry signature without using either implementation's cryptographic verifier.

## 8. Exact authorities

- P1-A18 commit: `be2eda2c9a86c703c6d486599d1062143c228ca9`
- P1-A18 report SHA-256: `02ed5d44db18acb676714a27273c4df75d6a5a132cfe1fc8e7102e8bdc774ee6`
- profile registry SHA-256: `feca5612d7b57069819b3603ee72c9558db60ed7eb7a32b0688d53f048186f3b`
- interoperability bundle SHA-256: `2e281ed72f05a47f32965d6585131ee51bd1265a3a1c86ca3b77ad9d0679319f`
- expected report SHA-256: `8008f0eb90328a4ff01f1bd4a594f1f7417ecbd3f5c68efdcf07bf801be62c2a`
- registrar public-key file SHA-256: `92ab839043a328ea39009a86c419d706bbbbdc44b460386eae7cc5fbdf57921c`

## 9. Decision boundary

Boundary: `registered-active-profile-matrix-canonical-capability-negotiation-claim-boundary-preserving-differential-replay-closure`.

Conformant inside the boundary:

- signed registration of the declared profile matrix;
- active-version selection and downgrade rejection;
- deterministic capability negotiation;
- explicit rejection of unsupported mandatory capabilities;
- claim-boundary preservation;
- exact transcript binding;
- six-route Python and Go differential replay;
- external registry-signature verification.

Outside the boundary:

- universal interoperability;
- future unregistered profile compatibility;
- future unregistered runner compatibility;
- semantic equivalence of all carrier formats;
- automatic compatibility with unknown critical extensions.
