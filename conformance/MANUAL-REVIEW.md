# EIGIIB E1/E2/E3/E4 manual gates

Revision reviewed: `EIGIIB-E4-draft-1.0`.

- `semantic-authority-review`: complete. The EIGIIB core remains authoritative for the general rule; E1 owns typed evidence/claim semantics; E2 owns static repository checking semantics; E3 owns artifact identity, production provenance, replay and reproducibility semantics; E4 owns authenticated attestations, trust roots, delegation, revocation and provenance-integrity semantics.
- `claim-boundary-review`: complete. The E2 reference checker limits its claim to mechanically decidable repository properties and does not claim semantic validation of manual attestations.
- `provenance-boundary-review`: complete. The E3 model keeps byte identity, provenance and reproducibility distinct from authenticity. The selected E3 closure now covers only stable E3 normative/schema/checker/test artifacts; the mutable cross-extension E1 evidence registry is intentionally not part of that immutable E3 artifact closure.
- `authentication-boundary-review`: complete. E4 separates cryptographic signature validity, trust-root acceptance, authorization, temporal/revocation policy and semantic truth. The repository's `conformance/trust.json` is structural-only and asserts no production trust root or authenticated production decision. The Ed25519 key under `tests/fixtures/e4/` is test-only and cannot satisfy a production policy.

The E4 reference checker may use a fixed OpenSSL Ed25519 verification adapter. It does not execute repository-provided commands, does not infer real-world identity, and does not claim full delegated-path or global revocation completeness in version 0.1.

No deviation is accepted by this attestation.
