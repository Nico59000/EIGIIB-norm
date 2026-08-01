# P1-A3 SCITT receipt boundary review

Revision reviewed: `EIGIIB-P1-A3-1.0` plus additive `P1-A3-H0.2`.

- `scitt-receipt-boundary-review`: complete.
- P1-A3 owns only exact P1-A2 identity binding into one SCITT Signed Statement, verification of that Signed Statement against one supplied Issuer Ed25519 public key, verification of one RFC9162_SHA256 inclusion proof, and verification of one COSE Receipt against one supplied Transparency Service Ed25519 public key.
- P1-A3-H0.2 requires the exact P1-A2 source to be revalidated by the existing P1-A2 checker with the exact P1-A1 capsule and P1-A2 public key before a hardened positive P1-A3 conclusion is admitted. It does not duplicate DSSE verification logic.
- P1-A2 remains authoritative for the authenticated DSSE/Sigstore carrier. P1-A3 does not reinterpret the in-toto predicate or M0-A2 aggregate result.
- E4 remains authoritative for trust, identity, authorization, delegation and revocation. P1-A3 treats all fixture public keys as supplied cryptographic inputs only.
- E5 remains authoritative for transparency semantics. One valid inclusion Receipt proves only the bounded inclusion relation represented by the Receipt; it does not prove global append-only consistency.
- E6 remains authoritative for cross-view comparison, gossip and fork accountability. One Receipt does not establish observer convergence or global fork absence.
- E11 remains authoritative for trusted temporal semantics. P1-A3 does not convert HTTP response timing, registration order, Receipt presence or any local clock into trusted time.
- RFC 9943 and RFC 9942 are the stable SCITT object/Receipt references. `draft-ietf-scitt-scrapi-11` is used only for the fixture registration transcript shape and remains a draft external reference.
- The SCRAPI-style `201` status and `Location` value are transcript metadata. Registration evidence is derived from the verified Receipt and inclusion proof, not from HTTP status alone.
- The P1-A3 fixture stores only public keys. No private signing key is retained in the repository and no SCITT network service is contacted.
- The deterministic CBOR subset is a repository-local transport profile; it does not redefine generic CBOR, COSE, RFC 9942 or RFC 9943.
- `conformance/p1-a3-scitt.json` remains structural-only and asserts no production Issuer, Transparency Service, trusted key, trusted time, network registration, Registration Policy correctness, global append-only state or cross-view convergence.

No deviation is accepted by this attestation.
