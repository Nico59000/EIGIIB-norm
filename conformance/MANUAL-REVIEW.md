# EIGIIB E1/E2/E3 manual gates

Revision reviewed: `EIGIIB-E3-draft-1.0`.

- `semantic-authority-review`: complete. The EIGIIB core remains authoritative for the general rule; E1 owns typed evidence/claim semantics; E2 owns static repository checking semantics; E3 owns artifact identity, production provenance, replay and reproducibility semantics.
- `claim-boundary-review`: complete. The E2 reference checker limits its claim to mechanically decidable repository properties and does not claim semantic validation of manual attestations.
- `provenance-boundary-review`: complete. The E3 model keeps byte identity, provenance, reproducibility and authenticity separate; its static checker hashes local artifacts and validates graph/reference invariants but does not execute procedures, authenticate producers, infer semantic equivalence, or infer replay independence.

The selected E3 provenance closure covers the normative E3 document, E3 schema, reference checker, its unit-test suite, and the E1 evidence registry used to bind the checker validation. It does not claim a complete supply-chain closure for GitHub, CPython, the operating system, or external infrastructure.

No deviation is accepted by this attestation.
