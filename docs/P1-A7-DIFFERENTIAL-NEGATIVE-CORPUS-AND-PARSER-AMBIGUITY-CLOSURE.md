# P1-A7 — Differential Negative Corpus and Parser-Ambiguity Closure

P1-A7 is an additive interoperability profile outside the numbered `E*` chain. It consumes the validated P1-A5 and P1-A6 routes and introduces a portable negative corpus shared by the Python reference route, the independent Go route and the external native observation.

## Target condition

Every closed vector must produce the same portable decision on every required route:

```text
same acceptance or rejection
+ same portable error class
+ same precedence when several defects coexist
```

Human-readable messages, stack traces and library-specific errors are not compared.

## Route set

The initial required route set is:

```text
reference-python-openssl
independent-go-stdlib
external-go-cose
```

A route that is unavailable, silently normalizes a forbidden encoding or returns an unmapped implementation error is non-conformant.

## Negative layers

The corpus is partitioned by the first authoritative boundary expected to reject the input:

| Layer | Initial mutation families |
| --- | --- |
| JSON | duplicate members, non-finite numbers, invalid UTF-8, trailing data |
| Base64 | non-canonical alphabet, invalid padding, truncated value |
| Path | absolute path, traversal, symlink, non-regular file |
| Manifest | duplicate member, permutation outside the declared canonical order, wrong length, wrong digest |
| DSSE | truncated signature, wrong payload type, wrong pre-authentication encoding |
| CBOR | non-deterministic integer or length encoding, duplicate map key, forbidden indefinite length |
| COSE | unknown critical header, unsupported algorithm, wrong tag, malformed protected header |
| Receipt | detached-payload mismatch, malformed proof, wrong tree coordinates, wrong root binding |
| Projection | missing field, extra field, wrong result carrier, chain-identity divergence |

## Portable error classes

The initial closed taxonomy is:

```text
syntax.invalid-json
syntax.invalid-utf8
encoding.noncanonical-base64
path.unsafe
manifest.invalid
identity.length-mismatch
identity.digest-mismatch
signature.malformed
signature.invalid
cbor.nondeterministic
cose.unsupported-header
cose.invalid-structure
receipt.invalid-proof
projection.invalid
route.unavailable
internal.unmapped
```

Each vector declares exactly one expected portable class. Multi-defect vectors additionally declare a precedence rule and may not rely on incidental parser order.

## Vector contract

Each vector must declare:

```text
id
layer
source fixture
mutation operation
expected acceptance
expected portable error class
required routes
required platforms
claim boundary
```

Mutated fixtures are generated deterministically from checked-in positive fixtures or are checked in with exact SHA-256 and byte length.

## Closure requirements

P1-A7 is complete only when:

- the positive corpus remains conformant on all routes;
- every negative vector is rejected by every required route;
- every rejection maps to the same portable error class;
- multi-defect precedence is explicit and equal across routes;
- Linux, macOS and Windows results agree;
- corpus identities and generation procedures are closed;
- no route silently repairs forbidden input;
- residual parser or library divergences are recorded rather than normalized away.

## Claim boundary

P1-A7 establishes portable parser and verifier behavior only for the closed fixtures, mutations, routes, versions and platforms. It does not imply universal parser equivalence, memory safety, production trust, complete fuzzing coverage, semantic truth of claims or closure of the reproducible toolchain obligations assigned to P1-A8.
