# EIGIIB E14-A3 — Correlation-Control Enforcement, Single-Use Budget and Cross-Projection Linkability Replay

Status: draft normative E14 companion 1.0.

## 1. Purpose

E14-A3 converts the correlation-control identifiers carried by E14-A1 projections and required by E14-A2 policies into repository-checkable control state.

It defines:

- versioned correlation-control profiles;
- bounded disclosure-use budgets;
- enforcement requests bound to exact E14-A1 projections and E14-A2 decisions;
- an ordered consumption ledger;
- replay, exhaustion and cross-projection linkability decisions.

The slice preserves these distinctions:

```text
control identifier != control enforcement
permit decision != consumed disclosure use
single-use label != unique operation nonce
shared domain != unrestricted correlation
static ledger replay != distributed atomic commit
```

## 2. Functional inputs

The machine authority is `conformance/correlation-control.json`.

It consumes:

```text
conformance/confidential-evidence.json
conformance/disclosure-authorization.json
```

Every enforcement request binds the exact projection, source record, commitments, E14-A2 request and E14-A2 decision. A changed revision or commitment requires a new request.

## 3. Control profiles

A control profile binds:

```text
id + revision + state
required correlation-control identifiers
linkability mode
per-projection use limit
per-source-record use limit
operation-nonce uniqueness rule
cross-audience and cross-purpose sharing flags
declared shared domains
```

Profile states are `active`, `revoked`, `contested` and `unavailable`.

A revoked profile derives rejection. A contested profile derives `held`. An unavailable profile derives `unavailable`.

## 4. Linkability modes

Three modes are defined:

- `isolated` — a domain cannot be shared by different projections;
- `pairwise` — a domain may be shared only inside one source-record, audience and purpose tuple;
- `declared-shared` — a domain must be explicitly listed and may cross audience or purpose only when the corresponding profile flags allow it.

These modes constrain declared linkability. They do not prove anonymity, unlinkability or resistance to side-channel correlation.

## 5. Budgets

A budget binds one exact:

```text
control profile
source record + revision + commitment
audience + revision
purpose
linkability domain
maximum committed uses
```

A budget cannot exceed the profile's source-record limit.

Budget states are `active`, `exhausted`, `contested` and `unavailable`.

## 6. Enforcement requests

An enforcement request binds:

```text
E14-A2 decision and request
E14-A1 projection and source record
control profile
budget
linkability domain
operation nonce
```

The projection must carry every control required by the profile. The request must reproduce the exact audience, purpose and operation authorized by E14-A2.

## 7. Consumption replay

Each enforcement request has at most one consumption record.

Consumption states are:

```text
committed
rejected
held
unavailable
```

The reference derivation applies:

1. an E14-A2 denial, revoked profile or exhausted budget derives `rejected`;
2. otherwise a held decision or contested authority derives `held`;
3. otherwise an unavailable decision or authority derives `unavailable`;
4. otherwise replay, budget and linkability checks run;
5. a violating attempt derives `rejected`; a remaining attempt derives `committed`.

Committed and rejected states require material evidence identifiers.

## 8. Single-use and budget rules

When nonce uniqueness is required, an operation nonce used by a prior committed consumption cannot be committed again.

Before a new commitment, the checker counts prior committed uses against:

- the profile's per-projection limit;
- the profile's per-source-record limit;
- the selected budget's maximum use count.

Rejected, held and unavailable attempts do not consume a budget.

## 9. Ordered ledger

Within each budget, consumption sequences are unique and contiguous from one.

The sequence is an audit order in the supplied registry. It is not proof that an external store performed an atomic or linearizable transaction.

## 10. Cross-projection replay

The checker compares a candidate linkability domain with prior committed consumptions and applies the selected profile mode.

A conflicting attempt must be rejected with the corresponding replay reason.

No positive result establishes that external systems erased identifiers, prevented timing correlation or avoided linkage through payload content.

## 11. Structural-only baseline

The repository authority contains no production disclosures. Empty arrays are conformant and produce `not-evaluated` result carriers.

## 12. Non-goals

E14-A3 does not:

- release, transmit or publish a projection;
- implement a distributed lock or atomic counter;
- establish global exactly-once semantics;
- authenticate the audience;
- prove a pseudonym is cryptographically unlinkable;
- hide timing, network, payload or organizational correlation;
- provide confidential storage;
- establish revocation freshness or disclosure anti-rollback.

Those revocation and rollback properties remain assigned to E14-A4.

## 13. Reference checker

```text
tools/eigiib_correlation_control_check.py
```

The checker uses repository-local JSON, TOML and the Python standard library only.
