# M0-A15-F2 manual review

- [ ] The branch is an additive first-parent successor of exact F1 head `b66ba8d5b11ce4e9d30d5fdb70fb982db3e26095` and exact tree `9c2ded5aedbf5c22d311461ad7ee42d8315f8763`.
- [ ] No M0-A15 or M0-A15-F1 frozen authority is modified.
- [ ] The package schema is closed before cryptographic and semantic verification.
- [ ] The embedded history is replayed by the exact F1 checker and exact historical A14 implementation.
- [ ] Publisher, activation authority, witnesses and observers are key-bound and profile-bound.
- [ ] At least two ingress readbacks, three of four activation witnesses and two activation readbacks are derived and verified.
- [ ] The evaluation instant is caller supplied and lies inside the bounded activation window.
- [ ] The verifier performs no network request and no host-clock read.
- [ ] Random private keys used for CI candidate issuance are ephemeral and never uploaded.
- [ ] External publication and byte-exact readback are recorded before any operational `T` claim.
- [ ] The claim boundary excludes legal identity, physical independence, provider honesty and future succession assurance.
