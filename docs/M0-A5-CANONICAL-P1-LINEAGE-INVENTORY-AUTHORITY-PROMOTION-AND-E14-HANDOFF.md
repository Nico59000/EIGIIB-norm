# M0-A5 — Canonical P1 Lineage Inventory, Authority Promotion and E14 Handoff

Status: repository infrastructure contract. M0-A5 is not a numbered EIGIIB extension and does not add `E14` to the adoption profile.

## 1. Decision

M0-A5 closes the governance gap between the exact P1 implementation lineage and the repository's central authority map.

The canonical P1 authority is the exact commit:

```text
c1983e9f2e95879ee16c162075c8d72bc73d88f9
```

on the named lineage branch:

```text
agent/p1-a20-registered-runner-admission-toolchain-succession-compatibility-rollback
```

The commit is authoritative; the branch name is a discoverability aid. A pull-request state, branch label or default-branch position cannot replace exact commit identity.

## 2. One owner per fact

M0-A5 does not copy the proof content of P1-A1 through P1-A20.

Each P1 document remains the owner of its semantic boundary. Each conformance state remains the owner of its repository result. Each manual review remains the owner of its human attestation. The M0-A5 lineage registry owns only:

- ordered lineage identity;
- exact head and base commits;
- canonical-head designation;
- authority-promotion status;
- repository paths to the existing owners;
- the exceptional staged structure of P1-A7;
- the transition contract into E14 design.

This prevents the central index from becoming a second, drifting specification.

## 3. Canonical lineage

The machine authority is [`conformance/m0-a5-p1-lineage.json`](../conformance/m0-a5-p1-lineage.json).

It registers P1-A1 through P1-A20, including P1-A19-F2. Ordinary slices are exact single-child transitions. P1-A7 is explicitly recorded as a staged 35-commit closure from P1-A6 to P1-A7.7 rather than being falsely flattened into one commit.

P1-A7.1 through P1-A7.5 are transitively bound by the A7.7 full-corpus freeze. P1-A7.6 is additionally named by its exact source commit, and P1-A7.7 by its exact head commit. M0-A5 does not invent intermediate commit identities that are not separately declared by the frozen authority.

## 4. Authority promotion

Promotion means that the central adoption profile recognizes the M0-A5 lineage registry as the owner of P1 canonicality.

Promotion does not mean:

- merging every historical branch into `main`;
- changing any P1 claim boundary;
- converting P1 into an `E*` extension;
- treating a closed pull request as invalid evidence;
- accepting a branch name without commit verification;
- reusing an old pointer after the canonical branch moves.

A future canonical P1 head requires an additive M0-A5 registry revision and a new review. Silent retargeting is forbidden.

## 5. Controlled crossings

The lineage has four broad crossing classes:

1. **representation crossings** — P1-A1 through P1-A4 transport EIGIIB evidence through in-toto, signed bundle and receipt carriers;
2. **implementation crossings** — P1-A5 through P1-A7 compare independent and external verifiers and close bounded parser ambiguity;
3. **release-lifecycle crossings** — P1-A8 through P1-A14 bind distribution, release, authorization, time, transparency, revocation and remediation;
4. **live operational crossings** — P1-A15 through P1-A20 exercise public release readback, registry publication, persistence, governance, profile negotiation, runner admission and toolchain succession.

Each crossing must preserve the source identity and claim boundary that entered it. Acceptance at one crossing does not imply acceptance at a later crossing.

## 6. E14 handoff

The handoff authority is [`conformance/m0-a5-e14-handoff.json`](../conformance/m0-a5-e14-handoff.json).

It freezes the minimum input classes required before E14 design:

- the complete evidence artifact;
- the disclosable projection;
- a cryptographic commitment or source binding;
- a versioned disclosure policy;
- an authorized audience;
- a fixed evaluation context and purpose;
- correlation controls;
- current revocation state.

The handoff also fixes a conservative decision vocabulary: `permit`, `deny`, `held`, `unavailable`.

M0-A5 creates no E14 extension file, checker or schema. It records readiness for design while keeping normative adoption false.

## 7. Human control

The operator-facing control model is defined in [`M0-A5-HUMAN-MASTERY-GUIDE.md`](M0-A5-HUMAN-MASTERY-GUIDE.md).

Its central rule is simple: identify the exact authority first, then identify the crossing, then evaluate whether the available evidence is sufficient for that crossing. Do not infer later guarantees from an earlier pass.

## 8. Mechanical gate

`tools/eigiib_m0_a5_check.py` verifies:

- exact canonical branch and head;
- exact ordered slice identifiers and commit chain;
- existence of every referenced document, state and manual review;
- P1-A7 staged-closure paths and exact terminal bindings;
- reference-only promotion semantics;
- E14 handoff completeness;
- exact safety rules and nonclaim vocabulary;
- central adoption-profile registration;
- continued absence of `E14` from the adopted extension list.

Boundary:

```text
canonical-p1-lineage-reference-only-authority-promotion-and-e14-design-handoff
```
