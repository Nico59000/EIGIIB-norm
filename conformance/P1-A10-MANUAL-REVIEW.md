# P1-A10 manual claim-boundary review

- [x] The policy binds the exact P1-A8 release descriptor and P1-A9 release-signer SPKI.
- [x] Trust is relative to one explicitly supplied root public key.
- [x] The delegate set is closed, ordered and contains three distinct SPKIs.
- [x] The threshold is exactly two distinct approvals.
- [x] Policy, approval and revocation objects use canonical COSE_Sign1 carriers.
- [x] The initial A+B authorization is valid before revocation.
- [x] B is revoked by the root at sequence 11.
- [x] The stale A+B replay is rejected at sequence 12 despite valid historical signatures.
- [x] The fresh A+C authorization is accepted at sequence 12.
- [x] Logical sequence is not reported as trusted time.
- [x] Delegate revocation is not reported as content revocation or distribution withdrawal.
- [x] No private key is committed.
- [x] The two absolute closure goals are retained as NF/F rather than silently absolutized.
