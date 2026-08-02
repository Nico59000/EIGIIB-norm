# EIGIIB-E14 — Confidential Evidence, Selective Disclosure and Information Minimization

Status: draft normative extension 1.0, introduced by E14-A1 after the M0-A5-F1 handoff freeze.

## 1. Purpose

E14-A1 defines a repository-checkable boundary between a **confidential evidence record** and a **disclosure projection** derived from it.

The baseline keeps these distinctions explicit:

```text
confidential record != confidential storage
projection validity != disclosure authorization
projection commitment != encryption
source claim selected != source evidence disclosed
claim preserved != claim proven true
smaller projection != anonymous projection
sealed projection != released projection
```

E14-A1 consumes the eight design inputs frozen by M0-A5. It does not rewrite the historical M0-A5 pre-adoption finding; `conformance/e14-a1-adoption-transition.json` records the additive transition.

## 2. Functional position

E14 is versioned after E13 but functionally consumes the E1 claim boundary and E3 artifact identity boundary:

```text
E1 typed claim boundary ----\
                              -> E14 confidential record and projection
E3 artifact identity -------/
```

E14-A1 does not depend on an E13 composed permit and does not establish E10 authorization. A later disclosure-control slice may consume those authorities.

## 3. Registry objects

The machine authority is `conformance/confidential-evidence.json`.

It defines:

- **confidential evidence record** — exact artifact identity, bounded claim descriptors, confidentiality classification and revocation state;
- **disclosure projection** — a committed, audience/policy/context-bound selection or weakening of source claims;
- **record commitment** — SHA-256 commitment over the canonical record envelope excluding the commitment field itself;
- **projection commitment** — SHA-256 commitment over the canonical projection envelope excluding the commitment field itself.

The repository registry is structural-only and contains no production confidential evidence.

## 4. Confidential evidence records

A record binds:

```text
id
revision
subject
classification
source authority
artifact path + byte length + SHA-256
claim descriptors
revocation state
record commitment
```

Classifications are exactly:

```text
restricted
confidential
highly-confidential
```

E14-A1 does not prescribe where a production record is stored. Public repository placement is neither required nor recommended by the extension.

## 5. Claim descriptors

Each source claim has:

```text
id
type
subject
predicate
object
scope
assurance
evidence references
```

Assurance is an integer from 0 through 4. It is an ordering inside this registry only; it is not a universal truth scale.

Claim ids are unique within one record. Scope and evidence arrays contain unique identifiers.

## 6. Artifact and record identity

The checker recomputes the source artifact byte length and SHA-256 digest.

The record commitment is computed over canonical UTF-8 JSON with sorted keys, compact separators and one terminal LF, excluding the `commitment` field.

Therefore:

```text
same record id + changed artifact != same record
same artifact + changed claim envelope != same record commitment
same commitment label + different bytes != valid commitment
```

## 7. Disclosure projections

A projection binds the exact:

```text
source record id
source revision
source artifact digest
source record commitment
audience id and revision
disclosure policy id and revision
evaluation context id and revision
correlation-control identifiers
projected claims
omitted source claims
projection commitment
```

Projection states are only `prepared` and `sealed`. E14-A1 intentionally defines no `released` state.

An audience identifier named in a projection is not self-proving authorization. A policy or context identifier is not evidence that the policy was evaluated correctly.

## 8. Claim-boundary preservation

Every projected claim references one exact source claim.

The following fields must remain equal:

```text
type
subject
predicate
object
```

A projection may only weaken the remaining dimensions:

- projected scope must be a non-empty subset of source scope;
- projected assurance must not exceed source assurance;
- projected evidence references must be a subset of source evidence references.

A source claim may appear at most once in one projection.

No claim may be invented, merged, upgraded or rebound to another subject.

## 9. Omission accounting

`omitted_claims` must equal exactly the set of source claim ids not present in the projection.

This creates a mechanically checkable minimization boundary:

```text
unmentioned source claim != silently disclosed claim
unmentioned source claim != forgotten accounting state
```

A projection may contain zero claims if every source claim is listed as omitted. Such a projection is structurally valid but does not imply operational usefulness.

## 10. Revocation boundary

A projection may be prepared or sealed only from a source record whose revocation state is `active`.

States `revoked`, `withdrawn` and `unavailable` suppress positive projection validity.

E14-A1 does not yet define distributed revocation freshness, rollback replay or propagation latency. It checks only the exact registry state supplied to it.

## 11. Correlation controls

Correlation controls are explicit, non-empty identifiers bound by the projection commitment.

The checker verifies presence and commitment binding only. It does not prove that an identifier such as `audience-bound` or `single-use` is effectively enforced by an external system.

## 12. Structural failure

Any structural error makes the registry non-conformant and suppresses positive record or projection results.

A structural-only registry with no production records or projections remains conformant with result carriers `not-evaluated`.

## 13. Non-goals and proof boundary

E14-A1 does not:

- encrypt evidence or prove storage confidentiality;
- authorize disclosure;
- authenticate the audience, policy engine or evaluation context;
- prove anonymity, unlinkability or zero knowledge;
- prove correlation controls are effective;
- prove source claims are semantically true;
- prove revocation information is globally fresh;
- release, transmit or publish a projection;
- establish post-quantum or long-term cryptographic validity.

Therefore:

```text
valid projection != permitted disclosure
valid commitment != secret content
claim-boundary preservation != semantic truth
omission accounting != unlinkability
active local state != globally fresh revocation state
```

## 14. Reference checker

The reference checker is:

```text
tools/eigiib_confidential_evidence_check.py
```

It uses repository-local JSON and the Python standard library only.

## 15. E14-A2 disclosure authorization companion

E14-A2 adds the independent authorization crossing after projection validity:

```text
sealed projection
+ audience eligibility
+ disclosure policy evaluation
+ evaluation-context revalidation
= bounded disclosure decision
```

Its authority is `extensions/E14-A2-DISCLOSURE-AUTHORIZATION-AUDIENCE-ELIGIBILITY-CONTEXT-REVALIDATION.md`. E14-A2 does not change A1 record or projection commitments and still defines no release or transmission event.

## 16. E14-A3 correlation-control enforcement companion

E14-A3 binds each exact E14-A1 projection and E14-A2 decision to a versioned control profile, scoped budget, enforcement request and ordered consumption record.

Only prior `committed` consumptions reduce operation-nonce, per-projection, per-source-record and scoped-budget capacity. Isolated, pairwise and declared-shared modes are replayed separately.

Its authority is `extensions/E14-A3-CORRELATION-CONTROL-SINGLE-USE-LINKABILITY-REPLAY.md`. A committed A3 result is not a release event, distributed atomic transaction, audience-authentication proof or anonymity/unlinkability proof. Revocation freshness, withdrawal propagation and disclosure anti-rollback remain assigned to E14-A4.

## 17. E14-A4 revocation and anti-rollback companion

E14-A4 binds an otherwise positive A1/A2/A3 path to current commitment-chained status heads for the source record, projection and distribution channel. It rejects stale, revoked, withdrawn, superseded or rolled-back state while preserving unavailable and held as distinct non-positive results.

Its authority is `extensions/E14-A4-REVOCATION-FRESHNESS-DISTRIBUTION-WITHDRAWAL-DISCLOSURE-ANTI-ROLLBACK-REPLAY.md`. E14-A4 does not establish globally trusted time, global propagation, byte recall, release or external consensus.
