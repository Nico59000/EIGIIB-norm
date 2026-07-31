# P1-A1 in-toto capsule boundary review

Revision reviewed: `EIGIIB-P1-A1-1.0` with additive transport hardening 0.2.

- `in-toto-capsule-boundary-review`: complete.
- P1-A1 owns only deterministic transport of one exact M0-A2 aggregate report into one in-toto `Statement/v1` capsule plus the preserved negative implication boundary.
- M0-A2 remains authoritative for the aggregate result and component classifications; P1-A1 does not reinterpret them.
- E3 remains authoritative for provenance semantics beyond the local SHA-256/byte identity recomputed by the capsule adapter.
- E4 remains authoritative for authentication. `authentication_state = not-provided-p1-a1` is mandatory and P1-A1 creates no envelope, signature, certificate or authenticated principal.
- E5/E6 remain authoritative for transparency and cross-view accountability; P1-A1 creates no log inclusion or receipt.
- E11 remains authoritative for trusted temporal semantics; P1-A1 adds no host-clock or external timestamp.
- The in-toto Statement subject is the exact aggregate report bytes. It is not an implicit assertion about a build artifact, repository tree or production deployment.
- The EIGIIB predicate transports the aggregate result without promoting it to an in-toto Simple Verification Result or another stronger verifier assertion.
- Transport hardening 0.2 rejects duplicate JSON member names in transported material and requires canonical RFC 4648 base64 by strict decode plus byte-identical re-encode.
- These ambiguity guards provide cross-parser/cross-runtime stability only; they do not authenticate the source or create a canonical signed-envelope format.
- M0-A3 state `implemented` means the adapter and replay evidence exist. It is not `validated` interoperability and does not claim an independent in-toto implementation accepted or authenticated the capsule.

`conformance/p1-a1-in-toto.json` remains structural-only and asserts no production capsule, signer, certificate, timestamp, transparency receipt or authenticated origin.

No deviation is accepted by this attestation.
