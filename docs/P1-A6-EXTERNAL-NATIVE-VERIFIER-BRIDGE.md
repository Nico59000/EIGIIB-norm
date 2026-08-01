# P1-A6 — External Native Verifier Bridge

P1-A6 is an additive interoperability profile outside the numbered `E*` chain. It consumes the exact P1-A5-H0.2 closure and adds one native observation implemented through a third-party COSE library.

## External observation

The bridge uses `github.com/veraison/go-cose@v1.3.0`. The library parses and verifies both tagged `COSE_Sign1` objects from the fixed P1-A3 fixture:

1. the attached-payload SCITT Signed Statement;
2. the detached-payload COSE Receipt.

The bridge supplies the checked-in Ed25519 public keys, verifies the exact protected-header profile, requires deterministic CBOR, validates the bounded one-entry RFC9162 inclusion proof, reconstructs the detached Receipt payload and invokes the external library for both signatures.

The observation is intentionally scoped to `p1-a3-cose-sign1-and-receipt`. P1-A1, P1-A2, manifest binding and end-to-end chain identity remain supplied by the unchanged P1-A5 independent route. P1-A6 therefore adds an external observation rather than claiming a third complete implementation.

## Closed projection

The bridge must reproduce the unchanged P1-A5 projection:

```text
manifest_binding_result
p1a1_replay_result
p1a2_replay_result
p1a3_replay_result
cross_capsule_binding_result
end_to_end_result
chain_identity
```

Tool-specific metadata is excluded from differential equality. The canonical P1-A6 result is additionally checked byte-for-byte through `tests/fixtures/p1-a6/expected-external-result.json`.

## Execution boundary

Runtime verification is fixture-only and performs no network operation. CI may download the declared Go module and its transitive dependencies. P1-A6 fixes the module version but does not yet identify downloaded module archives, Go binaries, runner images or reconstructed executables byte-for-byte; those limits belong to P1-A8.

## Positive condition

A conformant P1-A6 result requires:

- valid P1-A6 manifest and structural state;
- conformant P1-A5-H0.2 implementation closure and differential replay;
- successful external COSE observation;
- exact equality with the canonical external result;
- exact equality with the closed P1-A5 projection;
- successful required jobs on Ubuntu, macOS and Windows.

An unavailable external dependency, parse divergence, signature divergence, projection divergence or missing platform result is non-conformant.

## Claim boundary

P1-A6 does not imply EIGIIB claim truth, trusted Issuer or Transparency Service, independent trust roots, a third complete independent implementation, byte-exact dependency identity, production interoperability, live SCITT registration, global append-only consistency or replacement of upstream P1 and `E*` authorities.
