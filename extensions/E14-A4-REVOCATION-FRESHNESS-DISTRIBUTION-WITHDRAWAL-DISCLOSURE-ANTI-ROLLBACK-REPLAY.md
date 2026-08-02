# EIGIIB-E14-A4 — Revocation Freshness, Distribution Withdrawal and Disclosure Anti-Rollback Replay

Status: draft normative companion to E14-A1, E14-A2 and E14-A3.

## 1. Purpose

E14-A4 closes the gap between a previously admissible disclosure path and the current repository-visible status of its source record, projection and distribution channel.

It establishes a static replay relation:

```text
exact E14-A1 projection/source binding
+ exact E14-A2 authorization decision
+ exact E14-A3 consumption
+ current chained status heads
+ bounded freshness source
= disclosure admissibility replay
```

## 2. Authorities

The machine authority is `conformance/disclosure-revocation.json`.

It defines:

- freshness sources with an explicit revision, state and current evaluation epoch;
- projection-bound distribution channels;
- commitment-chained status histories for source records, projections and distribution channels;
- disclosure attempts bound to exact upstream revisions and commitments;
- derived decisions with explicit component results.

## 3. Freshness is bounded, not globally trusted

A freshness source carries an integer `current_epoch`. A disclosure attempt must bind that exact source revision and use that exact epoch.

E14-A4 checks only arithmetic and repository consistency:

```text
observed_epoch <= current_epoch <= valid_until_epoch
```

It does not prove that the epoch corresponds to globally trusted wall-clock time.

## 4. Status histories and heads

Every history entry binds:

```text
subject kind + id + revision + commitment
status authority + revision
generation
predecessor id + predecessor commitment
state
observed epoch
valid-until epoch
evidence
entry commitment
```

Generations are contiguous from 1. Generation 1 has no predecessor. Every later generation references the immediately preceding entry and its exact commitment.

The latest generation for one exact subject binding is the current head.

## 5. Anti-rollback replay

A disclosure attempt names exact source, projection and distribution heads and minimum accepted generations.

A referenced head is rolled back when:

- it is not the latest generation for the exact subject binding;
- its generation is below the attempt's minimum accepted generation;
- its predecessor chain is invalid;
- its commitment does not match the canonical entry envelope.

Rollback detection is a known negative and suppresses admissibility.

## 6. Revocation and withdrawal

Status states are:

```text
active
revoked
withdrawn
superseded
unavailable
```

For distribution channels, either a channel state or current status head of `withdrawn` suppresses admissibility.

A source or projection state of `revoked`, `withdrawn` or `superseded` suppresses admissibility even if an older authorization decision was `permit` and an older A3 consumption was `committed`.

## 7. Upstream bindings

Every attempt binds the exact:

- source record id, revision and commitment;
- projection id, revision and commitment;
- E14-A2 authorization request and decision revisions;
- E14-A3 enforcement request and consumption revisions;
- distribution channel revision and commitment;
- freshness source revision and evaluation epoch.

An A2 decision other than `permit` or an A3 consumption other than `committed` remains non-positive.

## 8. Decision precedence

The final state is derived in this order:

1. any known negative derives `rejected`;
2. otherwise any unavailable authority or component derives `unavailable`;
3. otherwise any contested or not-yet-effective component derives `held`;
4. otherwise the result is `admissible`.

Known negatives include revocation, withdrawal, supersession, stale status, rollback, authorization denial and rejected consumption.

## 9. Non-goals

E14-A4 does not:

- establish globally trusted time;
- prove instantaneous propagation of revocation or withdrawal;
- recall bytes already received by an audience;
- erase cached or copied projections;
- release or transmit a projection;
- prove distributed linearizability or consensus;
- prove that all external registries expose the same head;
- authenticate a real audience;
- prove confidential transport, anonymity, unlinkability or zero knowledge.

Therefore:

```text
admissible replay != projection released
withdrawn now != bytes recalled everywhere
fresh local status != globally fresh status
current repository head != global consensus head
```

## 10. Reference checker

The reference checker is `tools/eigiib_disclosure_revocation_check.py`. It uses repository-local JSON and the Python standard library only.
