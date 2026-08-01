# P1-A2 Sigstore bundle boundary review

Revision reviewed: `EIGIIB-P1-A2-1.0`, including post-green binding hardening 0.2.

- `sigstore-bundle-boundary-review`: complete.
- P1-A2 owns only DSSE/Sigstore carrier construction from one exact P1-A1 Statement and cryptographic verification against one explicitly supplied out-of-band Ed25519 public key.
- P1-A1 remains authoritative for the Statement and transported M0-A2 result. P1-A2 delegates source validation to the P1-A1 checker and does not reinterpret the predicate or aggregate result.
- A conformant P1-A2 verification requires the exact P1-A1 capsule as upstream input; a signed `Statement/v1` alone is not sufficient to establish P1-A2 carrier binding.
- The DSSE payload must be byte-identical to the deterministic P1-A2 serialization of that conformant P1-A1 Statement. Signature verification over one representation cannot authorize later substitution of another representation.
- E4 remains authoritative for trust, identity, authorization and revocation. P1-A2 establishes only signature validity for the supplied key.
- `publicKeyIdentifier.hint` and DSSE `keyid` are lookup/binding hints and are never accepted as security decisions by themselves.
- P1-A2 deliberately excludes Fulcio/OIDC identity, Rekor transparency entries and RFC3161 timestamps.
- E5/E6 remain authoritative for transparency and cross-view accountability; P1-A2 asserts no log inclusion or fork absence.
- E11 remains authoritative for trusted temporal semantics; P1-A2 asserts no signing time or certificate-validity interval.
- P1-A3 remains responsible for transparency registration/receipt semantics.
- The test fixture contains no private signing key. Its fixed public key/signature prove only reference-verifier interoperability for that fixture.
- M0-A3 `implemented` does not mean `validated`; the observed Sigstore documentation reference is moving and is not treated as a byte-immutable external specification snapshot.

`conformance/p1-a2-sigstore.json` remains structural-only and asserts no production signer, trust root, certificate, transparency entry, timestamp, signed production bundle or authenticated production origin.

No deviation is accepted by this attestation.
