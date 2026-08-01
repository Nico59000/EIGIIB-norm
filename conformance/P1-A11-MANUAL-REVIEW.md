# P1-A11 manual review

- The A10 report and recovered authorization identities are exact and are not replaced by release-id matching.
- The time trust root and timestamp authority are separate Ed25519 keys with exact 44-byte SPKI identities.
- The root-signed policy contains the closed inclusive window and the TSA identity.
- Four signed observations are present in fixed order with strictly increasing observation sequences.
- The pre-window observation is rejected.
- The in-window observation is accepted and becomes the last accepted time.
- The later-sequence but earlier-time observation is rejected as clock rollback.
- The post-window observation is rejected as expired.
- Rejected observations do not advance the accepted clock.
- Python/OpenSSL, independent Go and external go-cose routes must converge on the same portable result.
- No private key is admitted in the P1-A11 repository scope.
- The trusted-time conclusion is contextual to the supplied time root, delegated TSA, signed observations and fixed window.
