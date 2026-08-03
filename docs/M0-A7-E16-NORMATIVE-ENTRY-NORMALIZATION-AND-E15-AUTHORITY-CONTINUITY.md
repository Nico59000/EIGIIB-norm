# M0-A7 — E16 Entry Normalization and E15 Authority Continuity

Status: preparatory repository contract. M0-A7 does not adopt E16, does not modify the `EIGIIB-E15-1.0` profile and does not create an E16 extension, schema or checker.

## 1. Decision

The successor proposal is normalized as:

> **E16 — External Custody, Replication, Retention and Recovery Governance**

The first principal slice is normalized as:

> **E16-A1 — Historical Authority Continuity, Preservation Intent, Custodian and Replica Binding**

M0-A7 is required because E15-A5 freezes the complete E15 authority surface, including the central profile and global workflow. A descendant extension cannot mutate those descendants and simultaneously require current-tree byte equality with the E15 freeze. E15 must first become an exact historical source authority.

## 2. Exact source authority

```text
branch: agent/e15-a5-independent-external-evidence-verifier-final-freeze
commit: 036b81c3c128524858d66d096a1eb87e23cc5dad
profile: EIGIIB-E15-1.0
terminal slice: E15-A5
historical replay matrix: 30811560795
final closure matrix: 30811560397
platforms: ubuntu-24.04, macos-15, windows-2025
```

Both matrices completed successfully. M0-A7 is strictly additive. Every path frozen by `conformance/e15-a5-authority-freeze.json` remains byte-identical.

## 3. Authority-continuity rule

E16-A1 may update the central profile and workflow only after it adds an explicit transition authority that:

1. verifies the exact E15-A5 source commit;
2. materializes that commit in an isolated tree;
3. replays the historical E15 checker, matrix and final closure;
4. verifies all E15 frozen authority digests at that source commit;
5. records E16 adoption as an additive successor;
6. preserves every E15 claim and nonclaim without reinterpretation;
7. freezes the new profile, workflow and E16 transition authorities separately.

Required order:

```text
exact E15 lineage
  -> historical E15 freeze and matrix replay
  -> typed E16 transition
  -> current E16 profile evaluation
```

A branch name, current PR state, service locator or present readback cannot replace the exact source commit.

## 4. Typed preservation boundary

E16 keeps six coordinates distinct:

```text
placement
custody acceptance
retention observation
content readback
restore verification
succession or migration
```

A conformant E15 publication or readback does not imply replication. A registered replica does not prove a separate physical failure domain. A retention declaration does not guarantee future retention. A successful restore establishes only the named source, target, content and observation time.

Gate decisions, preservation evidence states and derived lifecycle states remain separate vocabularies. Known negative evidence precedes held and unavailable outcomes.

## 5. Failure-domain declarations

Independence is never inferred from different labels alone. A future E16 profile may declare dimensions such as:

```text
principal
account
provider
region
implementation
process
network path
administrative authority
```

The declaration is evidence about the represented topology, not proof of non-collusion or correlated-failure resistance.

## 6. Planned slices

### E16-A1

Historical E15 authority continuity, preservation intent, custodian identity and replica binding.

### E16-A2

Replica placement, custody acceptance, failure-domain declarations and placement evidence.

### E16-A3

Bounded retention windows, preservation observations, independent content readback and restore verification.

### E16-A4

Custodian succession, replica migration, loss, quarantine and anti-rollback recovery.

### E16-A5

Independent preservation verifier matrix, differential restore replay and final authority freeze.

The machine-owned ownership and non-reproof boundaries are in `conformance/m0-a7-e16-entry.json`.

## 7. Methodology translation guard

External contextual sources may contribute only typed derived rules. Source-specific equations, terminology and ontology are not repository authorities.

Retained rules:

- role changes require a declared transport;
- preservation diagnostics remain role-separated;
- exact source binding precedes lifecycle interpretation;
- failure-domain dimensions are declared, not inferred;
- naming difference is not independence;
- finite observations are not indefinite durability;
- preservation thresholds and precedence are policy-scoped.

## 8. Explicit nonclaims

M0-A7 and the normalized E16 plan do not establish:

- indefinite durability;
- universal availability;
- honesty or non-collusion of external services;
- physical or administrative provider independence;
- correlated-failure resistance;
- prevention of administrative deletion;
- legal custody or ownership;
- global erasure;
- globally trusted time;
- universal interoperability.

## 9. Mechanical gate

`tools/eigiib_m0_a7_check.py` verifies:

- the exact E15-A5 source branch, commit and profile;
- the two successful three-platform closure runs;
- byte identity of all 86 E15 frozen authorities;
- continued absence of E16 adoption and implementation artifacts;
- the exact E16 title and A1–A5 plan;
- exact input, decision, safety and nonclaim vocabularies;
- the historical authority-continuity contract;
- the methodology translation guard;
- presence of the manual review and human-mastery guide.

Boundary:

```text
additive-e16-entry-normalization-with-historical-e15-authority-continuity
```
