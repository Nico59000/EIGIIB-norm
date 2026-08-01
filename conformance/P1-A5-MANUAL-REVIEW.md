# P1-A5 independent verifier matrix boundary review

Revision reviewed: `EIGIIB-P1-A5-1.0`.

- `p1-independent-verifier-matrix-boundary-review`: complete.
- The reference route remains P1-A4-H0.2 and retains its Python/OpenSSL executable closure.
- The independent Go route does not invoke the Python reference checkers or OpenSSL.
- It independently parses strict JSON, deterministic CBOR, DSSE, COSE Sign1, Ed25519 and the bounded RFC9162 inclusion fixture.
- The differential projection requires exact agreement on every P1-A4 result carrier and chain identity.
- Required runners are closed to Ubuntu, macOS and Windows labels.
- An unavailable or divergent route is non-conformant.
- Cross-platform agreement is not promoted into production equivalence, trusted toolchains, independent trust roots or semantic truth.
- E4 remains authoritative for trust and authorization; E5/E6 for transparency and cross-view semantics; E11 for trusted time.
- No private key, network operation or production replay is introduced.

No deviation is accepted by this attestation.
