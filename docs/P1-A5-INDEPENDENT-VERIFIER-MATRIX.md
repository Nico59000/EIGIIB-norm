# P1-A5 — Independent Verifier Matrix and Cross-Platform Differential Replay

P1-A5 is an interoperability profile outside the numbered `E*` chain. It compares the exact P1-A4 fixture chain through two bounded routes:

1. the reference Python 3.13/OpenSSL P1-A4-H0.2 closure;
2. an independently implemented Go standard-library route with its own strict JSON, deterministic CBOR, DSSE, COSE, Ed25519 and RFC9162 fixture verification logic. The Go route does not invoke Python or OpenSSL.

The source chain is `tests/fixtures/p1-a4/chain.json`, identified by SHA-256 `8082fbe1c235ec3c5b5809eeb70d5593d20887f75a310abb8b4a9762be28a97d` and canonical descriptor length `2182` bytes.

The routes must agree on manifest binding, P1-A1 replay, P1-A2 replay, P1-A3 replay, cross-capsule binding, end-to-end result and canonical chain identity. Tool-specific metadata is excluded from this shared projection. The independent result is also checked byte-exactly against `tests/fixtures/p1-a5/expected-independent-result.json`.

The independent route is required on `ubuntu-24.04`, `macos-15` and `windows-2025`. The reference/differential gate uses Python 3.13, OpenSSL and Go 1.26.5 on Ubuntu; independent jobs use Go 1.26.5 and the Go standard library only.

A positive result requires a closed matrix manifest, exact source-chain identity, conformant P1-A4 and P1-A4-H0.2 results, conformant independent replay, exact expected-result equality, differential equivalence and successful required platform jobs. Unavailable or divergent routes are non-conformant.

P1-A5 does not imply EIGIIB claim truth, production-environment equivalence, independent trust roots, absence of a shared specification error, a trusted Go toolchain, independent GitHub runner operators or hardware, or replacement of upstream P1 and `E*` authorities. No private key, network operation or production replay is introduced.
