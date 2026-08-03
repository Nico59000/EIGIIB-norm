# E16-A4 — Custodian Succession, Replica Migration, Loss, Quarantine and Anti-Rollback Recovery

Status: adopted as the fourth principal slice of E16.

## 1. Scope

E16-A4 governs bounded recovery interpretation after E16-A3 has produced an admissible preservation-and-restore verification decision.

The slice owns seven record families:

1. custodian succession authorizations;
2. replica migration plans;
3. migration observations;
4. loss reports;
5. quarantine records;
6. recovery replays;
7. recovery decisions.

Every record is revisioned and commitment-bound. Identifier equality alone is insufficient.

## 2. Historical entry

Current-tree E16-A4 evaluation begins only after byte-exact materialization and replay of the E16-A3 source commit:

`74cb64ebcb1b51b0a035e755be413dbd2a7e9e3e`.

The historical replay reconstructs E16-A3 in an isolated source tree, replays its E16-A2 history, verifies the frozen E16-A3 report and executes the targeted E16-A3 tests.

E16-A4 does not rewrite any E16-A1, E16-A2 or E16-A3 authority, claim, nonclaim, registry, transition or freeze.

## 3. Custodian succession authorization

A succession authorization binds:

- one exact positive E16-A3 decision;
- predecessor and successor custodian identities and revisions;
- predecessor replica identity and revision;
- exact content identity;
- one source generation;
- one represented evaluation context;
- an authorization state and evidence references.

The states are `authorized`, `withdrawn`, `held` and `unavailable`.

An authorization does not prove legal transfer, operational acceptance, byte movement, target placement or future custody.

## 4. Replica migration plan

A migration plan binds the exact succession authorization, predecessor and successor custodians, source and target replicas, exact content identity, source and target generations, action, evaluation context and idempotency key.

A positive plan requires the target generation to be strictly greater than the source generation.

The states are `planned`, `cancelled`, `held` and `unavailable`.

A plan does not prove execution.

## 5. Migration observation

A migration observation binds the exact plan commitment and repeats source, target and content identity. Its state is one of:

- `positive`;
- `negative`;
- `inconclusive`;
- `unavailable`.

A positive observation is bounded to the represented migration event. It does not establish future retention or complete eradication of older copies.

## 6. Loss reports

A loss report binds the exact migration plan and identifies whether the represented loss affects the source, target or both. Its state is `suspected`, `confirmed`, `cleared` or `unavailable`.

A confirmed target or joint loss is negative evidence for recovery. A confirmed source loss may be contained by a positive migration and recovery of the successor target, but it remains part of the accepted history and is not erased.

## 7. Quarantine

A quarantine record binds an exact subject by kind, identifier, revision, commitment and generation.

The states are:

- `active`;
- `released`;
- `held`;
- `unavailable`.

Active quarantine of the target replica, the positive migration observation or the recovery replay denies recovery. Active quarantine of a superseded source may be compatible with positive recovery and prevents silent rollback to that source.

Release does not erase the prior quarantine event.

## 8. Anti-rollback recovery replay

A recovery replay binds the exact migration plan and migration observation, candidate target replica, exact content identity, previously accepted generation, minimum admissible generation, candidate generation, replay sequence, superseded commitments and idempotency key.

A positive replay requires:

- exact binding to the current plan and observation;
- candidate generation equal to the target generation;
- candidate generation strictly greater than the previously accepted generation;
- candidate generation not lower than the declared minimum;
- a strictly ordered, duplicate-free replay sequence;
- explicit binding of superseded commitments;
- no active quarantine or confirmed loss on the candidate.

A positive replay is bounded to the represented recovery operation. It does not establish future durability or universal rollback resistance.

## 9. Decision derivation

The checker derives seven gates:

- E16-A3 continuity;
- succession authorization;
- migration plan;
- migration observation;
- loss;
- quarantine;
- anti-rollback recovery.

Gate precedence is:

1. any `deny` produces `rejected`;
2. otherwise any `unavailable` produces `unavailable`;
3. otherwise any `held` produces `held`;
4. otherwise the state is `successor-replica-recovered`.

A stored recovery decision must reproduce the derived gates and state exactly.

## 10. Negative evidence

Known negative evidence includes, at minimum:

- source decision substitution;
- custodian, replica, content or generation mismatch;
- withdrawn succession;
- cancelled migration;
- negative migration observation;
- confirmed loss of the target or both replicas;
- active target, migration-observation or recovery quarantine;
- candidate generation rollback;
- replay-order duplication or inversion;
- missing superseded commitment;
- commitment mismatch.

Known negative evidence is not weakened to `held` or `unavailable`.

## 11. Authority boundary

The slice-local authority manifest is:

`conformance/e16-a4-authority-manifest.json`.

It binds the contract, registry, schemas, checker, historical replay, transition, freeze, tests, workflow and review guidance. The descendant authority freeze excludes itself and freezes every other A4 authority byte-exactly.

## 12. Nonclaims

Conformance does not establish:

- legal transfer, ownership or contractual custody;
- actual provider acceptance;
- physical migration or deletion of old copies;
- complete loss detection;
- future retention or durability;
- globally trusted time;
- real organizational or failure-domain independence;
- resistance to all correlated failures or collusion;
- future recoverability;
- universal rollback prevention;
- external-service honesty;
- universal availability or interoperability.
