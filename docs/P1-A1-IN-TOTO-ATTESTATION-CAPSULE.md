# EIGIIB P1-A1 — in-toto Attestation Capsule and Claim-Boundary Preservation

Status: portable interoperability capsule profile. P1-A1 is not a numbered EIGIIB extension and does not add semantic authority above Core/E1–E13.

## Purpose

P1-A1 implements the M0-A3 profile `in-toto-aggregate-export-v1`.

It exports one exact M0-A2 aggregate conformance report into an in-toto
Attestation Framework v1 Statement while preserving the original EIGIIB claim
boundary.

P1-A1 deliberately stops at the Statement layer. Authentication, digital
signatures, certificate identity, trusted timestamps and transparency receipts
belong to later P1 stages.

## External reference

The implemented profile targets:

```text
in-toto Attestation Framework release: v1.2.0
Statement type: https://in-toto.io/Statement/v1
```

P1-A1 uses the Statement schema exposed by the tagged v1.2.0 release. It does
not vendor or restate the in-toto specification.

The in-toto Simple Verification Result predicate is intentionally not used as
the default carrier. SVR asserts properties verified by a verifier and carries
verifier/time semantics that M0-A2 does not itself establish. P1-A1 therefore
uses a narrow EIGIIB predicate type that transports the existing aggregate
result without strengthening it.

## Core separations

```text
M0-A2 aggregate report          != in-toto authenticated attestation
in-toto Statement validity      != EIGIIB claim truth
subject digest match            != artifact/source authenticity
predicate transport             != E4 authentication
capsule construction            != signature creation
capsule verification            != signature verification
aggregate conformant            != production conformance
Statement                       != Envelope
P1-A1 implemented               != M0-A3 validated interoperability
```

The last distinction is deliberate. M0-A3 reserves `validated` for profiles
with executable evidence bound to a byte-identified external specification
snapshot. P1-A1 advances the profile from `specified` to `implemented`; it does
not copy the external specification into this repository merely to manufacture
a validation state.

## Capsule structure

A P1-A1 capsule is a repository-defined wrapper containing exactly one in-toto
Statement.

The wrapper records:

```text
standard             = EIGIIB-P1-A1-1.0
profile              = in-toto-aggregate-export-v1
external_spec        = in-toto-attestation-1.2.0
transport_layer      = in-toto-statement-v1
authentication_state = not-provided-p1-a1
statement            = <in-toto Statement/v1 object>
```

`authentication_state = not-provided-p1-a1` is normative. A consumer MUST NOT
reinterpret a P1-A1 capsule as authenticated merely because its inner Statement
has valid in-toto syntax.

## Subject identity

P1-A1 treats the exact M0-A2 aggregate report bytes as the single Statement
subject.

For source bytes `B`:

```text
H = SHA256(B)
N = len(B)
```

The Statement subject is:

```json
{
  "name": "<producer-selected source name>",
  "digest": {"sha256": "<H>"}
}
```

The predicate repeats the exact identity as `(sha256, bytes)` and transports
the exact report bytes as strict base64. This makes whitespace and other byte
changes visible without claiming authenticity.

The subject digest and predicate source identity MUST match the transported
bytes.

## Predicate type

P1-A1 uses:

```text
https://eigiib.example/attestation/aggregate-conformance/v1
```

The predicate contains only:

- the M0-A3 profile id;
- the source standard id `EIGIIB-M0-A2-1.0`;
- the exact report bytes and local identity;
- the copied M0-A2 `overall_result` carrier/value;
- the fixed negative implication boundary.

The transported report remains authoritative for its own detailed content.
The copied result field is a convenience binding and MUST equal the transported
report's `overall_result`.

## Fixed negative implication boundary

Every capsule carries exactly:

```text
statement-format-validity-does-not-imply-eigiib-claim-truth
statement-presence-does-not-imply-e4-authentication
subject-digest-match-does-not-imply-source-authenticity
transported-aggregate-result-does-not-imply-production-conformance
p1-a1-capsule-does-not-imply-envelope-or-signature
```

Removing or replacing one of these boundaries makes the capsule
non-conformant.

The boundary is carried inside the predicate so that transport does not erase
the distinction between a result and the strength of claim that may be made
from that result.

## Source admissibility

The builder accepts only a JSON object whose:

```text
standard       = EIGIIB-M0-A2-1.0
overall_result ∈ {
  conformant,
  conformant-with-documented-deviations,
  incomplete,
  non-conformant
}
```

P1-A1 does not convert an incomplete or non-conformant aggregate into a
positive verification assertion. It transports the exact state unchanged.

## Determinism

For fixed source bytes and fixed subject name, the capsule object is
deterministic.

P1-A1 adds no host-clock timestamp, random identifier, signer identity or
network-derived value. This is intentional: those facts are not available from
M0-A2 and belong to later authenticated transport stages.

## Post-green transport hardening 0.2

The first complete repository replay of the P1-A1 baseline succeeded. A
deliberate post-green audit then identified two parser/encoding ambiguities that
would be undesirable before P1-A2 signs transported material:

1. duplicate JSON object member names can be interpreted differently by
different parsers or silently collapse under last-wins parsing;
2. syntactically decodable base64 can have a non-canonical spelling when unused
trailing bits are not constrained.

P1-A1 therefore applies these additive transport guards without changing the
capsule semantics:

```text
duplicate JSON member name -> reject
base64 decode failure       -> reject
base64 decode succeeds but re-encode differs -> reject as non-canonical
```

The builder uses the same duplicate-key-rejecting JSON loader for source
aggregate reports that the verifier uses for capsules. The self-check applies
that loader to checked-in capsule/profile material as well.

For transported base64 `s`, validation requires:

```text
B = strict_base64_decode(s)
base64_encode(B) = s
```

Thus byte identity and textual transport representation are both stable. This
is a portability guard, not a cryptographic authenticity claim.

## Reference implementation

`tools/eigiib_in_toto_capsule.py` provides three operations:

```text
build   exact aggregate bytes -> deterministic P1-A1 capsule
verify  validate capsule and optionally compare supplied source bytes
check   repository self-check of config, fixtures and M0-A3 implementation state
```

The tool:

- reads local files only;
- rejects duplicate JSON member names in transported material;
- computes SHA-256 locally;
- performs strict, canonical base64 validation;
- validates exact boundary constants;
- never contacts an external service;
- never signs;
- never verifies a signature;
- never reads the host clock;
- never executes an EIGIIB decision or commit.

## Structural repository state

`conformance/p1-a1-in-toto.json` is structural-only.

It asserts no production capsule, no production conformance result, no signer,
no certificate, no timestamp, no transparency inclusion and no authenticated
origin.

## M0-A3 lifecycle

P1-A1 changes `in-toto-aggregate-export-v1` from:

```text
specified -> implemented
```

and registers the adapter/test/fixture evidence paths, including the transport
ambiguity hardening tests.

This state means that a repository-local adapter implementing the documented
mapping exists and is replayed in CI. It does not mean that an independent
in-toto implementation has authenticated or accepted the capsule, and it does
not satisfy the M0-A3 byte-exact external-specification requirement for
`validated`.

## Non-goals

P1-A1 does not:

- create a DSSE envelope;
- create a Sigstore bundle;
- sign or authenticate a Statement;
- establish verifier identity;
- attach trusted time;
- submit to Rekor or SCITT;
- evaluate an external policy engine;
- replace E1/E3/E4 authority;
- strengthen M0-A2 results;
- prove production conformance.

Those concerns are reserved for P1-A2 and later interoperability stages.
