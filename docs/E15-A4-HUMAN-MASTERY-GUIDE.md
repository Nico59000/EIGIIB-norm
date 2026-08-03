# E15-A4 Human Mastery Guide

## 1. Question answered by this slice

E15-A4 answers a bounded governance question:

> Given one exact externally observed publication, what repository-visible evidence supports a withdrawal request, target-specific tombstones, target-specific distribution stops and post-withdrawal observations without claiming global erasure?

It does not answer whether every copy everywhere has disappeared.

## 2. Reading order

1. `conformance/e15-a4-adoption-transition.json`
2. `conformance/withdrawal-governance.json`
3. `schemas/eigiib-e15-a4-withdrawal-governance.schema.json`
4. `tools/eigiib_historical_e15_a3_replay.py`
5. `tools/eigiib_withdrawal_governance_check.py`
6. `conformance/e15-a4-authority-freeze.json`

## 3. Exact parent boundary

A withdrawal request must bind:

- the exact E15-A3 publication id and revision;
- the publication commitment;
- the exact E15-A3 lifecycle decision and commitment;
- a parent lifecycle state of `publication-observed`, `persistence-observed` or `independently-read-back`;
- the exact payload digest and byte count.

A matching display name, locator or digest alone is insufficient.

## 4. Roles

### Withdrawal authority

Authorizes one exact withdrawal request. It does not operate every external target merely because it authorized withdrawal.

### Distribution operator

Controls one declared set of targets and mechanisms. Operator identity, target identity and mechanism are all checked independently.

### Post-withdrawal observer

Uses an inherited E15-A3 observer profile. An observer reports one bounded target/locator event and does not establish global state.

## 5. Target-scoped evidence

A target profile binds its exact locator, locator kind, stop mechanisms and tombstone capability.

A tombstone is target-specific. A distribution stop is target-specific. A decision cannot use evidence from target A to satisfy target B.

## 6. Commitment-chained heads

Tombstone generations and stop sequences are contiguous from 1. Every later entry binds the immediately preceding id and commitment.

The decision must reference the latest head for each required target. Therefore:

```text
installed generation 1
  -> removed generation 2
```

cannot be evaluated by citing generation 1 alone. Likewise:

```text
stopped sequence 1
  -> resumed sequence 2
```

cannot be represented as currently stopped by replaying sequence 1.

## 7. Decision gates

E15-A4 evaluates:

```text
binding_result
authority_result
operator_result
observer_result
policy_result
freshness_result
request_result
tombstone_result
distribution_stop_result
post_withdrawal_observation_result
anti_rollback_result
content_identity_result
```

The values remain:

```text
permit | deny | held | unavailable
```

## 8. Lifecycle states

```text
withdrawal-requested
tombstoned
distribution-stopped
post-withdrawal-observed
rejected
held
contested
unavailable
```

A successful request without a required tombstone remains `withdrawal-requested`. A tombstone without full stop coverage remains `tombstoned`. Complete registered-target stops without enough bounded observations remain `distribution-stopped`.

## 9. Negative precedence

Known negative evidence wins over incomplete or unavailable evidence. Examples include:

- a cancelled request;
- a removed tombstone head;
- a resumed distribution head;
- a `still-available` post-withdrawal observation;
- a digest mismatch;
- stale-head replay;
- target or content substitution.

## 10. Claim boundary

E15-A4 establishes only repository-visible, target-scoped governance evidence.

```text
withdrawal requested != withdrawal executed
tombstone installed != bytes erased
distribution stopped != recipient copy deleted
not-found at one target != global absence
unreachable != absent
latest registered heads != global consensus
post-withdrawal observed != future unavailability
```

The final independent external-evidence matrix and E15 closure remain E15-A5 work.
