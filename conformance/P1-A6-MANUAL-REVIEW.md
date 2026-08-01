# P1-A6 external native verifier bridge boundary review

Revision reviewed: `EIGIIB-P1-A6-1.0`.

- `p1-external-native-verifier-boundary-review`: complete.
- P1-A5-H0.2 remains byte-exact and is consumed without modification.
- The external route uses `github.com/veraison/go-cose@v1.3.0` to parse and verify the P1-A3 Signed Statement and Receipt `COSE_Sign1` objects.
- The route independently verifies Ed25519 signatures relative to the supplied fixture public keys and independently parses the COSE headers and detached Receipt payload.
- The external observation is deliberately partial: it does not claim a third complete implementation of P1-A1 through P1-A4.
- The result is projected onto the unchanged seven-field P1-A5 differential carrier.
- External-library acceptance does not imply EIGIIB claim truth, trusted Issuer, trusted Transparency Service, production interoperability or trusted dependency binaries.
- Runtime fixture verification performs no network operation. Dependency download during CI is build-time transport only.
- P1-A6 does not replace P1-A1 through P1-A5 or any numbered `E*` authority.

No deviation is accepted by this attestation.
