# P1-A9 manual claim-boundary review

- [x] The source is the exact detached A8 release descriptor, not a newly invented release artifact.
- [x] DSSE signature validity is reported separately from signer trust and authorization.
- [x] Both the release envelope and the supersession envelope have distinct COSE Signed Statements and Receipts.
- [x] The two receipts bind one RFC9162 tree of size two with explicit leaf coordinates.
- [x] `authority-carrier-upgrade` preserves the exact A8 release descriptor identity.
- [x] Sequence `0 -> 1`, one edge, one current authority and acyclicity are checked.
- [x] Supersession does not imply content revocation, security remediation or withdrawal from distribution.
- [x] Fixture HTTP transcripts perform no network registration and prove no external durability.
- [x] No private key is committed.
- [x] External-library error text is excluded from portable route equality.
- [x] The transitional Windows runner pool is restricted to the two explicitly registered image/Git pairs; the frozen A7 authority manifest and authority root remain unchanged.
- [x] The A8 offline replay preserves the frozen archive bytes and independently replays A7.1–A7.7 with the same closed Windows policy selector.
