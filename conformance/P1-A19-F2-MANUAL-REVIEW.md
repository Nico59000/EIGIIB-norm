# P1-A19-F2 manual review

- [x] Exact P1-A19 commit `d791f780bc97d70e8f97e5165d3c86dc4a90fddf` is the parent.
- [x] The P1-A19 schema, registry, bundle, expected report and six routes are unchanged.
- [x] The checker selects `Draft202012Validator` from the committed `$schema` URI.
- [x] The schema document is checked before instance validation.
- [x] The complete interoperability bundle is validated before semantic replay.
- [x] Local `#/$defs` references are exercised by nested negative mutations.
- [x] Extra properties are rejected at bundle, envelope, registry, profile, route and transcript boundaries.
- [x] Referenced canonical-set item type and minimum-length constraints are enforced.
- [x] Eight schema mutations are rejected independently of the existing 25 semantic mutations.
- [x] The exact P1-A19 report and six semantic routes remain unchanged.
- [x] Python and independent Go reports remain byte-exact.
- [x] External OpenSSL registry-signature verification remains required.
- [x] Arbitrary remote-reference resolution and network schema retrieval are not claimed.
- [x] Review closure requires a green exact-head matrix and resolution of the PR #99 P2 thread.
- [x] Boundary: `draft202012-committed-schema-local-ref-closed-instance-and-semantic-replay-closure`.
