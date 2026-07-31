# EIGIIB M0-A2 — Aggregate Conformance Report

Status: repository infrastructure contract. M0-A2 is not a numbered EIGIIB extension and does not add semantic authority above E1–E11.

## Purpose

M0-A2 provides one derived view over the mechanically emitted conformance reports already owned by the existing EIGIIB checkers.

The aggregate exists to answer a narrow operational question:

> Which required checker results were actually present for this replay, what top-level conformance result did each checker emit, and what is the bounded combined gate status?

It MUST NOT reinterpret lower-layer findings or promote a lower-layer result.

## Core separations

```text
aggregate report != new normative authority
aggregation != re-proof
all component gates passed != every EIGIIB claim is true
report SHA-256 binding != report authenticity
finding count != finding semantics
missing report != proven component failure
```

M0-A2 therefore copies only the component identifier, exact result-file identity, checker/tool identifiers, top-level result field/value and severity counts. Detailed findings remain in the component report that owns them.

## Expected component set

The expected set is derived from `conformance/extension-graph.json`:

1. the M0-A1 graph checker;
2. every canonical Core/E1–E11 node that declares a `checker`;
3. every attached hardening profile that declares a `checker`.

No second manually synchronized checker inventory is maintained.

For component id `X`, the default collection file is:

```text
.eigiib-results/components/<lowercase(X)>.json
```

Examples:

```text
M0-A1    -> m0-a1.json
E10      -> e10.json
E11-H0.2 -> e11-h0.2.json
```

## Result interpretation

M0-A2 recognizes only two top-level component result carriers:

- `overall_result`, used by E2;
- `structural_result`, used by current extension and hardening checkers.

The aggregate does not inspect operational sub-results to manufacture a stronger conclusion.

Classification is:

```text
conformant                              -> pass
conformant-with-documented-deviations   -> qualified
partially-evaluated / not-evaluated
/ unavailable                           -> incomplete
non-conformant                          -> fail
```

An unsupported result field/value is a collection-contract error.

A missing or unparsable required component report makes the aggregate `incomplete`; it does not claim the missing component itself is non-conformant. An actual component failure, stale/extra report pollution, graph-contract error, or unsupported report protocol makes the aggregate `non-conformant`.

## Exact-result binding

Each included component is bound by:

```text
SHA-256(report bytes)
byte length
```

These values establish exact local report identity only. They do not establish origin, authenticity, trusted time, transparency inclusion or semantic correctness; those remain E3–E6/E11 concerns where applicable.

## Execution boundary

`tools/eigiib_aggregate.py` is a pure collector.

It:

- reads the M0-A1 graph;
- reads already-produced JSON reports;
- computes SHA-256 and byte lengths;
- classifies only documented top-level conformance fields;
- writes one derived JSON report.

It does not execute checkers, shell commands, tests, network requests, deployment actions, policy actions or external standards.

## CI use

GitHub Actions may run the existing checker commands exactly as before while additionally capturing their JSON output into `.eigiib-results/components/`. The aggregate gate runs after those component gates and fails closed if required reports are absent or incompatible.

The aggregate artifact is generated evidence. It SHOULD NOT be committed as a second authority for component results.

## Non-goals

M0-A2 does not:

- replace E1 evidence semantics;
- replace E2 conformance;
- replace M0-A1 graph ownership;
- merge detailed findings into a new authority;
- establish production conformance;
- sign or timestamp reports;
- publish attestations to an external transparency service.

Those external transport/authentication concerns belong to later interoperability profiles.
