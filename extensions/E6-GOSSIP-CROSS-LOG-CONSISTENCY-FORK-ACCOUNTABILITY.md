# EIGIIB-E6 — Gossip, Cross-Log Consistency and Fork Accountability

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0 and EIGIIB-E1 through EIGIIB-E5 1.0  
**Reference checker:** `tools/eigiib_gossip_check.py`

---

## 1. Purpose

EIGIIB-E6 defines how independently obtained transparency views may be exchanged,
compared, cross-anchored, and converted into accountability evidence without
collapsing observation, consistency, authentication, attribution, or fault into a
single Boolean.

E6 exists because the following implications are invalid unless an explicit policy
supplies the missing premise:

```text
checkpoint received           != checkpoint authentic
checkpoint authentic          != checkpoint globally observed
same checkpoint observed twice != independent corroboration
different checkpoint          != fork
different-size checkpoints    != inconsistency
same-size conflicting roots   != identified culprit
conflict observed             != malicious behavior
signed conflict               != real-world actor identified
cross-log reference           != atomic cross-log state
cross-log anchoring           != both logs honest
gossip delivery               != freshness
no compared conflict          != no external conflict
accountability evidence       != punishment or remediation policy
```

E6 therefore treats gossip and accountability as typed relations over exact E5
checkpoint identities, observation paths, E4 authentication decisions, and
cross-log commitments.

---

## 2. Normative terms

- **gossip peer**: a named sender, receiver, relay, observer, auditor, log operator,
  or service participating in view exchange. A peer identifier is not proof of
  independence or real-world identity.
- **transmission**: a record that one peer transferred or attempted to transfer an
  exact checkpoint reference to another peer.
- **view**: a checkpoint identity as observed by one peer through a declared source.
- **comparison**: a typed relation between two views under a declared policy.
- **direct conflict**: two checkpoints for the same E5 log and same tree size with
  different Merkle roots.
- **compatible extension**: two same-log checkpoints of different sizes for which
  an E5 consistency proof reference exists for the smaller-to-larger pair.
- **unresolved relation**: two views for which E6 lacks sufficient mechanically
  admissible evidence to classify identity, extension, or direct conflict.
- **fork evidence**: preserved evidence of an incompatible pair or set of views.
- **attribution**: a claim that authenticated evidence associates a conflicting
  action with one E4 principal/key/policy domain.
- **accountability decision**: a policy-governed conclusion about what conflict and
  attribution evidence establish.
- **cross-log anchor**: a directed commitment from an E5 entry included in one
  checkpoint to the exact identity of another log's checkpoint.
- **federation**: a declared set of logs whose checkpoints are related through
  cross-log anchors or comparison policy.
- **gossip closure**: the explicitly evaluated set of peers, transmissions, and
  views. It is never implicitly global.

---

## 3. Core separation

For views `v1`, `v2`, checkpoint `C`, and policy `P`, E6 distinguishes:

```text
Received(v)
Authenticated(v)
Compared(v1, v2)
Consistent(v1, v2)
Conflict(v1, v2)
Attributed(conflict, subject)
Accountable(conflict, P)
```

A conforming implementation MUST NOT collapse these into one field named
`verified`, `safe`, `honest`, `forked`, or `guilty`.

### 3.1 Observation is not authentication

A peer may record bytes or a checkpoint identifier without authenticating its
origin. Authentication remains governed by E4.

### 3.2 Authentication is not global agreement

An E4-authenticated checkpoint may still be inconsistent with another
E4-authenticated checkpoint.

### 3.3 Conflict is not attribution

A direct conflict proves incompatible same-log/same-size commitments in the
evaluated evidence set. It does not by itself prove which system, key, operator,
relay, or observer caused the divergence.

### 3.4 Attribution is not remediation

E6 may establish a bounded accountability conclusion. Suspension, revocation,
rollback, disclosure, or other response belongs to project governance.

---

## 4. Exact checkpoint identity

E6 reuses E5 checkpoint identity and MUST NOT invent a parallel checkpoint
serialization.

For comparison purposes the operational identity is:

```text
CheckpointIdentity = (log_id, tree_size, root_hash)
```

Two checkpoint records with equal operational identity are equivalent for E6
comparison even if their local record identifiers differ.

A same-log, same-size, different-root pair is direct conflict evidence.

---

## 5. Gossip peers and transmissions

### 5.1 Peer object

```text
Peer = (
    id,
    role,
    principal?,
    domain?
)
```

Canonical roles are:

```text
observer
relay
auditor
log-operator
service
test
```

`principal` and `domain` are descriptive identifiers. Their presence does not prove
independence.

### 5.2 Transmission object

```text
Transmission = (
    id,
    sender,
    receiver,
    checkpoint,
    result,
    authentication?,
    sequence?
)
```

Canonical results are:

```text
received
dropped
malformed
unavailable
not-applicable
```

A transmission record states what the evaluated system recorded. It does not prove
network completeness.

### 5.3 No implicit time semantics

Wall-clock send/receive fields MAY be retained as observation metadata but MUST NOT
be used as trusted ordering evidence unless a policy explicitly binds them to a
trusted-time mechanism.

A monotone project-local `sequence` MAY order records inside one declared source,
but it does not imply global time.

---

## 6. View objects

A view is modeled as:

```text
View = (
    id,
    observer,
    checkpoint,
    source,
    transmission?,
    e4_decision?
)
```

`source` is one of:

```text
local
gossip
archive
external-attestation
test
```

If `source = gossip`, a transmission reference SHOULD be present.

An `e4_decision` MAY authenticate the checkpoint view, but E6 MUST verify that the
referenced E4 attestation explicitly binds the checkpoint identity before treating
the view as authenticated for accountability purposes.

---

## 7. Comparison relation

Let `I(C)` denote E5 operational checkpoint identity.

For two views `v1`, `v2`, E6 defines the mechanical relation:

```text
same-view
compatible-by-e5-reference
direct-conflict
unresolved
```

### 7.1 Same view

```text
I(C1) = I(C2)
```

implies `same-view`.

This is identity of commitment, not proof of independent observation.

### 7.2 Direct conflict

If:

```text
log(C1)  = log(C2)
size(C1) = size(C2)
root(C1) != root(C2)
```

then the relation is `direct-conflict`.

This result is mechanical and does not require trusted time.

### 7.3 Different sizes

Different-size checkpoints of the same log are not direct conflict merely because
their roots differ.

E6 MAY classify them as `compatible-by-e5-reference` only when the comparison
references an E5 consistency-proof object connecting the smaller checkpoint to the
larger checkpoint.

E6 does not duplicate E5 Merkle verification. The combined conformance pipeline
MUST run E5 validation before relying on this E6 relation.

Without such an E5 reference the E6 relation is `unresolved`.

### 7.4 Different logs

Two checkpoints from different logs have no intrinsic E6 consistency relation.
Cross-log relationships use explicit anchors defined in §11.

---

## 8. Comparison policy

A comparison policy MAY specify:

```text
ComparisonPolicy = (
    id,
    require_authenticated_views,
    allow_e5_consistency_reference,
    preserve_unresolved
)
```

A policy MUST NOT force an unresolved relation into `consistent` or `conflict`.

When `require_authenticated_views = true`, both views require admissible E4
authentication bindings for any policy-level conclusion stronger than
`unresolved`.

---

## 9. Fork evidence

A fork-evidence record SHOULD preserve:

```text
ForkEvidence = (
    id,
    comparison,
    views,
    relation,
    evidence_sources,
    state
)
```

Canonical states are:

```text
observed
authenticated-conflict
unattributed-conflict
superseded
invalid
```

A same-size direct conflict may be `observed` without any authentication.

`authenticated-conflict` requires E4-authenticated bindings for the conflicting
views, but still does not identify one culprit.

Fork evidence SHOULD be append-only. Corrections SHOULD supersede records rather
than erase evidence relevant to prior engineering decisions.

---

## 10. Authentication binding to E5 checkpoints

E6 consumes E4 decisions but does not reimplement E4 cryptography.

For a view `v` of checkpoint `C`, an E4 decision is admissible as a checkpoint
authentication binding only when:

1. the decision state is `authenticated`;
2. the decision resolves to an E4 attestation;
3. that attestation contains an explicit binding:

```text
type = local
id   = e5-checkpoint:<checkpoint-record-id>
```

4. the E4 registry and decision remain available to the evaluation.

A decision that is merely `authenticated` but signs an unrelated statement MUST
NOT authenticate the E6 view.

---

## 11. Cross-log anchors

### 11.1 Directed anchor

A cross-log anchor is:

```text
Anchor = (
    id,
    source_checkpoint,
    source_entry,
    inclusion_proof,
    target_checkpoint
)
```

The source entry exact bytes MUST use the reference encoding:

```text
eigiib-e6-cross-log-v1:<target-log>:<target-size>:<target-root>\n
```

The referenced E5 inclusion proof MUST bind `source_entry` to
`source_checkpoint`.

This proves that the target checkpoint identity is committed by the source
checkpoint under the E5 inclusion claim boundary. It does not prove the target log
is correct or available.

### 11.2 Directed semantics

`A -> B` does not imply `B -> A`.

A policy requiring reciprocal anchoring MUST request both directions explicitly.

### 11.3 No atomicity inference

Two logs cross-anchoring checkpoints do not thereby form one atomic transaction or
one linearizable history.

### 11.4 Circular exact anchors

A set of exact checkpoint anchors whose dependency graph forms a cycle is
structurally suspect because every checkpoint identity depends on entry bytes
committed by that same immutable checkpoint set.

The reference checker rejects direct exact-anchor cycles rather than interpreting
them as stronger consensus.

---

## 12. Cross-log consistency decisions

A cross-log policy MAY require:

```text
minimum_anchors
required_logs
reciprocal
require_authenticated_source_views
```

A decision state is one of:

```text
anchored
partially-anchored
unresolved
conflicted
not-evaluated
unavailable
```

`anchored` establishes only the declared commitment relation under the selected
policy.

It does not establish atomicity, synchronized freshness, or common operator trust.

---

## 13. Accountability

### 13.1 Accountability evidence

An accountability decision operates on preserved fork evidence and explicit E4
bindings.

Canonical states are:

```text
conflict-established
authenticated-conflict
single-principal-equivocation
unattributed-conflict
insufficient-evidence
not-evaluated
unavailable
```

### 13.2 Safe mechanical attribution profile

The E6-1.0 reference checker MAY mechanically report
`single-principal-equivocation` only under the restricted profile below.

For both conflicting views:

1. the E4 decision is `authenticated`;
2. the E4 attestation explicitly binds the corresponding E5 checkpoint;
3. the E4 policy threshold count is exactly `1`;
4. the attestation references exactly one signature;
5. that signature resolves to one key;
6. that key resolves to one principal;
7. both views resolve to the same principal id.

This profile is intentionally narrow.

If any condition is not met, E6 MUST retain `authenticated-conflict` or
`unattributed-conflict`; it MUST NOT guess attribution from display names, domains,
extra signatures, or root ownership.

### 13.3 Meaning of principal attribution

`single-principal-equivocation` means only:

> within the evaluated E4 registry and its trust policy, the same E4 principal
> identifier is the sole authenticated signer of two directly conflicting
> checkpoint statements.

It does not prove legal identity, intent, compromise source, or human action.

### 13.4 Key compromise

If a key is later marked compromised or revoked, policy may reinterpret the
operational response, but the historical conflict evidence remains.

A compromise record does not erase that the authenticated key produced the
evaluated signatures under the assumptions valid at the original decision time.

---

## 14. Accountability policy

A policy MAY define:

```text
AccountabilityPolicy = (
    id,
    require_direct_conflict,
    require_authenticated_views,
    attribution_mode,
    minimum_evidence_sources
)
```

The E6-1.0 mechanical attribution mode registry is:

```text
none
single-principal-v1
manual
```

`manual` MUST NOT be reported as mechanically established.

---

## 15. Gossip closure

Every E6 evaluation has a finite closure:

```text
GossipClosure = (
    peers,
    transmissions,
    views,
    comparison_records,
    external_registries
)
```

A checker MUST report conclusions only within that closure.

The following statement is invalid:

```text
no fork exists
```

when the evidence only establishes:

```text
no direct conflict was observed in the evaluated closure
```

---

## 16. Cross-observer corroboration

Two observations MAY provide useful corroboration, but identifiers alone do not
prove independence.

A policy MAY count distinctness by:

```text
peer
principal
domain
```

as an operational proxy.

Such a count MUST be labeled as declared distinctness, not proven organizational,
network, administrative, or economic independence.

---

## 17. Gossip replay and determinism

A repository-local E6 replay SHOULD be deterministic over:

- exact E5 and E4 registry bytes;
- exact E6 registry bytes;
- checker version;
- explicitly selected policies.

The reference checker performs no network access.

Live gossip collection belongs to an external collector. Its output can later be
evaluated by E6 as immutable records.

---

## 18. Registry model

A machine-readable E6 registry SHOULD contain:

```text
standard
revision
peers
transmissions
views
comparison_policies
comparisons
fork_evidence
cross_log_links
cross_log_policies
cross_log_decisions
accountability_policies
accountability_decisions
```

Every durable id MUST be unique in its object class.

Repository-relative external-registry paths MUST obey E2 confinement rules.

---

## 19. Mechanical checks

A generic E6 checker SHOULD verify at least:

- supported standard/version;
- unique ids and resolved references;
- E5 checkpoint references resolve;
- gossip transmissions resolve sender/receiver/checkpoint;
- gossip views resolve observer/source records;
- same-view classification matches checkpoint identity;
- direct-conflict classification matches same-log/same-size/different-root;
- different-size compatibility references an appropriate E5 consistency proof;
- E4 authentication bindings explicitly name the E5 checkpoint;
- fork evidence references a direct conflict before claiming conflict;
- cross-log source entries use the canonical target-checkpoint encoding;
- referenced E5 inclusion proof connects source entry and source checkpoint;
- exact-anchor graph is acyclic;
- cross-log decision policy is mechanically satisfied;
- restricted `single-principal-v1` attribution conditions are all satisfied;
- repository paths are confined.

A generic checker MUST NOT infer:

- global fork absence;
- peer independence;
- network completeness;
- malicious intent;
- real-world identity;
- legal responsibility;
- atomic cross-log state;
- correctness of E5 Merkle mathematics if the E5 checker was not run;
- correctness of E4 cryptography if the E4 checker was not run.

---

## 20. Reference checker boundaries

The E6 reference checker:

1. uses only the Python standard library;
2. requires Python 3.11+;
3. performs no network access;
4. executes no repository-provided commands;
5. does not invoke cryptographic providers;
6. consumes E4/E5 registries as prior-layer evidence;
7. recomputes only E6-local structural and relational rules;
8. emits deterministic findings and result dimensions.

E4 remains authoritative for authentication semantics.

E5 remains authoritative for Merkle inclusion, append-only consistency, witness
quorum, and transparent trust-history semantics.

---

## 21. Result model

The E6 reference report separates:

```text
structural_result
comparison_result
cross_log_result
accountability_result
fork_state
```

Canonical values are:

```text
structural_result:
    conformant
    non-conformant

comparison_result:
    compared
    not-evaluated

cross_log_result:
    anchored
    partially-evaluated
    not-evaluated

accountability_result:
    attributed
    conflict-only
    not-evaluated

fork_state:
    direct-conflict-observed
    none-observed
```

`none-observed` remains closure-bounded.

---

## 22. Conformance capabilities

E6 defines orthogonal capability claims:

### E6-S — Structural gossip conformance

Registry structure, references, and claim boundaries are valid.

### E6-C — Compared-view conformance

At least one material view comparison is validly evaluated.

### E6-X — Cross-log anchoring conformance

Selected cross-log policy is mechanically satisfied.

### E6-A — Accountability conformance

Selected accountability policy is evaluated without exceeding its evidence
boundary.

These capabilities are not a total order.

---

## 23. Security and abuse resistance

Implementations SHOULD bound:

- peer count;
- transmission count;
- comparison count;
- cross-log link count;
- graph traversal depth;
- external registry size.

A checker SHOULD reject cyclic exact-anchor graphs and malformed references before
performing expensive evaluation.

Untrusted text fields MUST NOT become shell commands, URLs to fetch, file paths
without confinement, or dynamic code.

---

## 24. Privacy boundary

Gossip evidence can reveal observer relationships, infrastructure topology, and
timing metadata.

E6 does not require publication of unnecessary personal or network-identifying
metadata.

Projects SHOULD retain only information material to the engineering claim.

Peer identifiers SHOULD prefer role/service identifiers over personal identity
when personal identity is not required.

---

## 25. Failure semantics

A checker MUST distinguish:

```text
conflict
unresolved
unavailable
invalid-record
not-evaluated
```

A missing E4 registry is `unavailable` for authentication-dependent attribution,
not proof that a view is unauthenticated in the world.

A missing E5 consistency proof leaves a different-size relation `unresolved`; it
does not make it a fork.

---

## 26. Reference scenarios

### 26.1 Same checkpoint via two peers

Two peers gossip the same checkpoint.

Result:

```text
comparison = same-view
independence = not-established
```

### 26.2 Same-size split view

Two observers hold same-log/same-size checkpoints with different roots.

Result:

```text
comparison = direct-conflict
fork_state = direct-conflict-observed
attribution = unresolved unless E4 profile is satisfied
```

### 26.3 Different-size views

One observer has size 100 and another size 120.

Without E5 consistency reference:

```text
comparison = unresolved
```

With an E5 consistency reference connecting 100 -> 120:

```text
comparison = compatible-by-e5-reference
```

### 26.4 Authenticated equivocation

Two conflicting same-size checkpoints are each explicitly bound by E4
attestations. Each accepted policy is one-of-one and each attestation has exactly
one signer key resolving to the same E4 principal.

Result:

```text
accountability = single-principal-equivocation
```

No intent or real-world identity conclusion follows.

### 26.5 Cross-log anchor

An included source entry contains the exact canonical identity of a target
checkpoint.

Result:

```text
cross-log = anchored
```

No atomicity or reciprocal agreement follows.

---

## 27. EIGIIB admissibility rule

E6 adds explicit machinery only where E5's local transparency model cannot safely
express multi-observer comparison or inter-log accountability.

A project SHOULD NOT introduce a gossip database, federation graph, or
accountability workflow merely for completeness.

The admission question is:

> Which ambiguity about independently observed transparency views cannot be
> prevented by E5 alone?

If the answer is not precise, remain at E5.

---

## 28. Non-goals

E6-1.0 does not standardize:

- a gossip wire protocol;
- peer discovery;
- transport encryption;
- anonymous communication;
- Byzantine consensus;
- distributed transactions;
- legal attribution;
- sanctions or incident response;
- trusted timestamp protocols;
- global log discovery;
- automatic revocation.

Those may be defined by later profiles or domain-specific standards.

---

## 29. Summary invariants

E6-1.0 requires preservation of these invariants:

```text
G1  received view != authenticated view
G2  authenticated view != globally consistent view
G3  different size != fork
G4  same log + same size + different root => direct conflict
G5  direct conflict != culprit identity
G6  E4 authentication must explicitly bind the E5 checkpoint
G7  attribution is restricted to policy-supported evidence
G8  cross-log anchor is directional
G9  cross-log anchor != atomicity
G10 observer identifiers != proven independence
G11 no observed conflict != no external fork
G12 accountability evidence != remediation policy
```

These invariants are the normative boundary of EIGIIB-E6 1.0.
