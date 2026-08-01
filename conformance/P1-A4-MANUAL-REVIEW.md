# P1-A4 end-to-end chain boundary review

Revisions reviewed: `EIGIIB-P1-A4-1.0` and additive `EIGIIB-P1-A4-hardening-0.2`.

- `p1-end-to-end-chain-boundary-review`: complete.
- P1-A4 composes the existing P1-A1, P1-A2 and P1-A3-H0.2 checkers; it does not duplicate their format or cryptographic implementations.
- The checked-in baseline manifest binds the ordered component identities, public-key SPKI identities, checker paths, checker versions and P1-A1 subject name through one canonical chain identity.
- Only fixed repository-owned checker paths are executable. Manifest values cannot select an arbitrary executable, shell command or network endpoint.
- P1-A4-H0.2 additionally binds the exact SHA-256 digest and byte length of the full eight-file executable closure, including the P1-A4 hardening checker itself, before invoking the unchanged baseline replay.
- The H0.2 closure covers the P1-A1, P1-A2, P1-A3 baseline, P1-A3 hardening and P1-A4 implementation files. It deliberately does not claim a trusted Python interpreter, trusted OpenSSL provider, hermetic runner or production-environment equivalence.
- P1-A1 remains authoritative for the deterministic in-toto Statement and transported M0-A2 report.
- P1-A2 remains authoritative for DSSE/Sigstore signature validity relative to the supplied public key.
- P1-A3 remains authoritative for SCITT Signed Statement, COSE Receipt and RFC9162 inclusion verification; H0.2 remains authoritative for upstream P1-A2 authentication before a positive receipt result.
- E4 remains authoritative for trust, authorization, delegation and revocation. P1-A4 does not promote supplied public keys into trusted identities.
- E5 and E6 remain authoritative for append-only, witnessing, cross-view and fork-accountability semantics. One replayed Receipt is not a global consistency or convergence proof.
- E11 remains authoritative for trusted temporal semantics. Replay order is not converted into trusted time.
- `conformance/p1-a4-chain.json` remains structural-only and asserts no production replay, live service interoperability, network registration or production conformance.
- No private key is introduced and no network operation is performed.

No deviation is accepted by this attestation.
