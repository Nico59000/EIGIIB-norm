# M0-A6 — E15 Normative Entry Normalization and Authority Continuity

Status: preparatory repository contract. M0-A6 does not adopt E15, does not modify the E14 profile, and does not create an E15 extension, schema or checker.

## 1. Decision

The E15 proposal is normalized as the working extension:

> **E15 — Externally Attested Delivery, Durable Publication, Recipient Acknowledgement and Withdrawal Governance**

The first principal slice is normalized as:

> **E15-A1 — Historical Authority Continuity, Delivery Intent, Endpoint and Carrier Binding**

M0-A6 is required because E14-A5-F1 froze central files such as `EIGIIB.toml` and the global workflow. A descendant extension cannot change those files and simultaneously demand current-tree byte equality against the E14 freeze. The transition must first turn E14 into a historical source authority anchored to its exact validated commit.

## 2. Exact source authority

The only E15 entry source is the E14-A5-F1 head:

```text
branch: agent/e14-a5-f1-portable-authority-rebind-workflow-neutral-publication
commit: 472e14fbb3d92205eabf10438e90295e19125ea4
profile: EIGIIB-E14-1.0
```

M0-A6 is strictly additive. Every path frozen by E14-A5-F1 must remain byte-identical on the M0-A6 branch.

## 3. Authority-continuity rule

E15-A1 may update the central profile and workflow only after it adds an explicit transition authority that:

1. verifies the exact E14 source commit;
2. materializes that commit in an isolated tree;
3. replays the historical E14 checker in that tree;
4. verifies all frozen E14 authority digests at that source commit;
5. records E15 adoption as an additive successor rather than an E14 rewrite;
6. freezes the new central profile, workflow and E15 transition authorities separately.

The intended order is:

```text
exact E14 lineage
  -> historical E14 freeze replay
  -> typed E15 transition
  -> current E15 profile evaluation
```

A branch name, pull-request state or current-tree coincidence cannot replace the exact historical commit.

## 4. Typed state model

E15 separates three vocabularies.

- Gate decisions: `permit`, `deny`, `held`, `unavailable`.
- External evidence states: `absent`, `pending`, `positive`, `negative`, `contested`, `unavailable`.
- Derived lifecycle states: `not-started`, `in-progress`, `externally-attested`, `rejected`, `held`, `contested`, `unavailable`, `withdrawn`, `partially-withdrawn`.

These vocabularies are not aliases. A positive external evidence item is not itself an authorization decision, and an externally attested event is not a claim of absolute material delivery.

For a crossing interpreted from source type `S` to target type `T`, the interpretation must declare:

```text
source type + target type + carrier + policy + context + non-preserved properties
```

No implicit transport is admitted.

## 5. Independent coordinates

E15 treats binding, delivery evidence, acknowledgement, persistence and withdrawal as separate coordinates. Their logical order is:

```text
lineage -> exact binding -> external evidence -> lifecycle interpretation
```

A component may be unavailable or contested without erasing a known negative in another component. Known negatives therefore precede held and unavailable outcomes.

There is no canonical scalar score combining the coordinates. Any future composite policy must declare its precedence and coefficients explicitly.

## 6. Planned slices

### E15-A1

Historical authority continuity, delivery intent, endpoint identity and carrier binding.

### E15-A2

Transfer attempts, externally authenticated delivery evidence and recipient acknowledgements.

### E15-A3

External publication records, bounded persistence observations and independent readback.

### E15-A4

Withdrawal requests, tombstones, future-distribution stops and bounded post-withdrawal observations.

### E15-A5

Independent verifier matrix, differential replay and final authority freeze.

The machine-owned dependency graph and non-reproof boundaries are in `conformance/m0-a6-e15-entry.json`.

## 7. Methodology translation guard

A contextual mathematical source supplied outside the repository is admitted only as a methodology input. Its source-specific terms, equations and objects are not EIGIIB authorities and are not reproduced here.

Only the following typed rules are retained:

- role changes require a declared transport;
- diagnostics with distinct roles remain separate;
- structural compatibility precedes interpretation;
- normalization is role-scoped;
- numerical or identifier coincidence is not semantic identity;
- local observations do not establish global state;
- composite weighting is application-specific and must be declared.

This preserves useful methodology without importing an unrelated mathematical ontology into EIGIIB.

## 8. Explicit nonclaims

M0-A6 and the normalized E15 plan do not establish:

- absolute material delivery;
- recipient possession or human awareness;
- universal availability;
- infinite durability;
- global erasure or legal recall;
- honesty or non-collusion of external services;
- universal interoperability.

## 9. Mechanical gate

`tools/eigiib_m0_a6_check.py` verifies:

- exact E14-A5-F1 source branch, commit and profile revision;
- byte identity of every E14 frozen authority in the current tree;
- continued absence of E15 adoption and implementation artifacts;
- exact E15 working title and A1-A5 plan;
- exact input, decision, safety and nonclaim vocabularies;
- the historical authority-continuity contract;
- the methodology translation guard;
- presence of the manual review and human-mastery guide.

Boundary:

```text
additive-e15-entry-normalization-with-historical-e14-authority-continuity
```
