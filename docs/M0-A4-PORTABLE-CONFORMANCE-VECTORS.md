# EIGIIB M0-A4 — Portable Conformance Vectors

Status: repository infrastructure contract. M0-A4 is not a numbered EIGIIB extension and does not create a new semantic authority above Core→E11.

## Purpose

M0-A4 defines a portable, implementation-independent corpus for replaying selected EIGIIB checker contracts.

A vector captures:

1. the checker contract identifier;
2. an embedded JSON fixture;
3. the fixture's deterministic byte-independent digest under the M0-A4 canonical JSON profile;
4. the expected top-level result field/value;
5. the exact set of expected error codes.

The vector intentionally does not standardize human-readable diagnostic messages, implementation language, internal algorithms, file layout outside the fixture adapter, or command-line syntax.

## Core separations

```text
vector conformance != EIGIIB production conformance
reference implementation pass != proof every implementation is correct
same error code != same internal algorithm
fixture digest != fixture authenticity
portable expected behavior != requirement to use Python
vector runner != normative checker implementation
```

## Canonical fixture digest

Each fixture is a JSON object. M0-A4 computes its digest from UTF-8 bytes produced by this deliberately narrow serialization profile:

```text
object keys: ASCII strings only, sorted by ASCII byte value
separators: ',' and ':' with no surrounding whitespace
string values: valid UTF-8, not ASCII-escaped except as required by JSON syntax
integers: signed 64-bit only
floating-point values: forbidden
algorithm: SHA-256
```

Equivalent fixtures inside this restricted profile therefore have one M0-A4 digest regardless of source-file indentation or object-member order. Restricting keys and integer range avoids language-dependent Unicode collation and arbitrary-precision number behavior.

This is an EIGIIB vector identity profile, not a general-purpose JSON canonicalization standard such as RFC 8785.

## Expected result contract

A vector declares:

- `result_field`;
- `result`;
- `error_codes`.

`error_codes` is the exact sorted unique set of codes attached to findings whose severity is `error`.

Warnings and informational diagnostics are deliberately excluded from portable behavioral equality because an implementation may provide additional non-failing diagnostics without changing the contract result.

Human-readable finding messages are never compared.

## Contract adapters

M0-A4 does not require all checker contracts to accept the same fixture structure. Each supported contract defines a portable fixture adapter, and the vector catalog checker validates that adapter shape before replay.

The initial corpus covers:

### M0-A2

Fixture fields, exactly:

```text
graph             extension-graph object consumed by the aggregator
component_reports map from non-empty component id to checker report object
```

A replay implementation materializes these data into its own isolated workspace and evaluates the M0-A2 aggregate contract.

### M0-A3

Fixture fields, exactly:

```text
authorities       unique array of EIGIIB authority keys made available to the profile
registry          M0-A3 interoperability registry object
evidence_files    map from confined relative evidence path to textual fixture contents
```

A replay implementation evaluates the M0-A3 structural profile contract against those declared authorities and files.

Later contracts may add adapters through an explicit M0-A4 revision. A vector MUST NOT invent an undeclared contract id.

## Initial vector set

The first corpus deliberately starts small and covers both positive and rejection behavior without attempting exhaustive checker coverage.

M0-A2:

- complete conformant aggregation;
- missing required component report remains `incomplete`;
- positive primary carrier cannot hide a secondary `non-conformant` carrier.

M0-A3:

- specified profile with a versioned reference is structurally conformant;
- declared validated profile without byte-exact external identity is rejected;
- exact-semantic mapping before declared validated state is rejected.

Further vectors SHOULD be added additively. The initial corpus does not yet cover every error code, every M0 contract, or any Core/E1–E11 checker directly.

These vectors test the infrastructure contracts only. They do not assert external SLSA/in-toto/SPDX/SCITT interoperability.

## Repository checker

`tools/eigiib_vector_catalog_check.py` validates the vector corpus itself. It does not execute the contracts under test.

It verifies:

- vector ids are unique;
- contract ids are from the closed supported set;
- every supported contract has vector coverage;
- fixture shape matches the selected contract adapter;
- fixture values stay within the portable canonical JSON subset;
- canonical fixture SHA-256 matches the declared digest;
- expected result field matches the selected contract adapter;
- expected result is from the contract result vocabulary;
- expected error codes are sorted, unique, and non-empty strings;
- materialized M0-A3 evidence-file fixture paths cannot escape their fixture root.

## Reference replay

`tools/eigiib_vector_reference_replay.py` is a repository-local demonstration harness for the current Python reference implementations.

It:

- first requires the vector catalog itself to be structurally conformant;
- reads the same portable vector corpus;
- materializes each fixture in a temporary directory;
- invokes only the repository-owned M0-A2 or M0-A3 Python checker class;
- compares the declared result and exact error-code set;
- reports vector pass/fail.

This harness is not part of the portable interface. Another implementation may use another language and another harness while consuming the same vector catalog.

## Evolution rule

Changing an existing vector's fixture or expected behavior requires an explicit vector-catalog revision. New behavior SHOULD normally be represented by a new vector id rather than silently changing an old case.

The vector corpus does not replace the checker norm, schema, extension graph, or evidence registries. It is executable interoperability evidence for implementations of those contracts.
