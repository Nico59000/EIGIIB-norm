# EIGIIB E1/E2/E3/E4/E5 manual gates

Revision reviewed: `EIGIIB-E5-draft-1.0`.

- `semantic-authority-review`: complete. The EIGIIB core remains authoritative for the general rule; E1 owns typed evidence/claim semantics; E2 owns static repository checking semantics; E3 owns artifact identity, production provenance, replay and reproducibility semantics; E4 owns authenticated attestations, trust roots, delegation, revocation and provenance-integrity semantics; E5 owns transparency logs, append-only checkpoint relations, witnessing and transparent trust-history semantics.
- `claim-boundary-review`: complete. The E2 reference checker limits its claim to mechanically decidable repository properties and does not claim semantic validation of manual attestations.
- `provenance-boundary-review`: complete. The E3 model keeps byte identity, provenance and reproducibility distinct from authenticity. The selected E3 closure covers only stable E3 normative/schema/checker/test artifacts; mutable cross-extension evidence is not part of that immutable closure.
- `authentication-boundary-review`: complete. E4 separates cryptographic signature validity, trust-root acceptance, authorization, temporal/revocation policy and semantic truth. The repository's `conformance/trust.json` remains structural-only and asserts no production trust root or authenticated production decision.
- `transparency-boundary-review`: complete. E5 separates log inclusion, append-only consistency, witness coverage, E4 authentication and semantic truth. The repository's `conformance/transparency.json` is structural-only: it asserts no production transparency log, production checkpoint, production witness, witness independence, fork-free global view, or complete transparent trust history.

The E5 reference checker uses a domain-separated SHA-256 Merkle reference profile and a deliberately simple `prefix-recompute-v1` consistency profile. It may consume E4 authenticated decision ids but does not perform E4 cryptographic verification itself. `fork_state = none-observed` means only that the evaluated registry contains no detected conflicting checkpoint; it is never a proof that no external split view exists.

No deviation is accepted by this attestation.
