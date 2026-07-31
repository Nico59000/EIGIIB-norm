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

The checker family predates M0-A2 and has four historical top-level conformance carriers. M0-A2 supports this explicit, closed compatibility set in the following priority order:

1. `overall_result` — E2 and E4;
2. `structural_result` — current structural extension and several hardening checkers;
3. `hardening_result` — E7-H0.2 and E9-H0.2;
4. `result` — E3.

M0-A2 MUST NOT discover result carriers heuristically. In particular, it does not accept an arbitrary field merely because its name ends in `_result`. A future carrier requires an explicit M0-A2 contract update.

When a report contains more than one supported carrier, the first one in the ordered set above is authoritative for aggregation. This preserves E4's `overall_result` rather than silently replacing it with its narrower `structural_result`.

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
