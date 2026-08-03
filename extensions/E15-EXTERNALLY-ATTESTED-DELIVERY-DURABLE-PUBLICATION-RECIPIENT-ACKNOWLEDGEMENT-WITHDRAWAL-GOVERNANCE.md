# EIGIIB-E15 — Externally Attested Delivery, Durable Publication, Recipient Acknowledgement and Withdrawal Governance

Status: draft normative extension 1.3, adopted through E15-A4 from the exact E15-A3 historical authority.

## 1. Purpose

E15 defines repository-checkable boundaries after an E14 release event. E15-A1 owns:

- historical continuity of the final E14 authority;
- delivery intent;
- endpoint identity;
- carrier binding;
- bounded pre-transfer admission.

The baseline keeps these distinctions explicit:

```text
E14 released event != external delivery
delivery intent != transfer attempt
endpoint identity != recipient identity
carrier binding != transport execution
admissible intent != remote acceptance
same identifier != same authority role
```

## 2. Historical authority continuity

E15 consumes E14 from the exact validated source commit:

```text
472e14fbb3d92205eabf10438e90295e19125ea4
```

That source commit is materialized in an isolated tree. Its final E14 checker, independent matrix and frozen authority digests are replayed there.

The current E15 tree is evaluated separately. Current-tree byte equality with the historical E14 freeze is neither required nor claimed after the typed transition.

The transition order is:

```text
exact E14 source commit
  -> isolated historical materialization
  -> historical E14 replay and freeze verification
  -> additive E15 adoption
  -> current E15-A1 evaluation
```

## 3. Functional position

E15 depends on the E14 release boundary and consumes selected authorities from E4, E11, E12 and E13 without re-proving them.

```text
E14 release event + receipt + released commitment
E4-compatible identity evidence classes
E11-compatible bounded context
E12-compatible idempotency discipline
E13-compatible delivery policy
  -> E15-A1 delivery-intent admission
```

E15-A1 does not authenticate a live external service, observe a transfer or prove possession.

## 4. Machine authorities

The registry authority is `conformance/delivery-intent.json`.

The adoption and continuity authority is `conformance/e15-a1-adoption-transition.json`.

The current descendant authority freeze is `conformance/e15-a1-authority-freeze.json`.

## 5. Endpoint profiles

An endpoint profile binds its identifier, revision, kind, locator, identity authority, identity state, accepted carriers, accepted recipient scopes and canonical commitment.

Endpoint kinds are `registry`, `service` and `recipient-interface`.

Identity states are `verified`, `rejected`, `contested` and `unavailable`.

A verified endpoint identity is a bounded registry fact. It is not a proof that a remote service is honest, reachable or controlled by the intended human recipient.

## 6. Carrier profiles

A carrier profile binds its identifier, revision, media type, protocol, integrity algorithms, authentication properties, confidentiality properties, declared transport properties, lifecycle state and canonical commitment.

Carrier states are `active`, `retired`, `contested` and `unavailable`.

A carrier profile describes an admitted representation and transport envelope. It is not evidence that transport occurred.

## 7. Delivery policies

A delivery policy binds allowed endpoint profiles, carrier profiles, recipient scopes, purposes, actions, required transport properties, maximum payload size, policy state and commitment.

Policy states are `active`, `retired`, `contested` and `unavailable`. No implicit wildcard is created by an empty array.

## 8. Delivery intents

A delivery intent binds the exact E14 release event and receipt, released object commitment, recipient scope, endpoint and carrier revisions, delivery policy, purpose, action, evaluation context, idempotency key, payload digest and size, requested transport properties and intent commitment.

The action is exactly `eigiib:e15:deliver`.

The reference envelope requires the payload digest to equal the released object commitment.

## 9. Admission coordinates

E15-A1 evaluates five independent coordinates:

```text
binding_result
endpoint_result
carrier_result
policy_result
idempotency_result
```

Each coordinate uses `permit`, `deny`, `held` or `unavailable`.

The derived intent state is `admissible`, `rejected`, `held` or `unavailable`.

Known negative results precede unavailable and held. Only a prior admissible decision consumes an idempotency key.

## 10. Structural-before-lifecycle rule

Lineage, revision and commitment binding are established before any delivery lifecycle interpretation.

Therefore:

```text
local registry validity != external evidence
admissible intent != in-progress transfer
missing evidence != positive attestation
one endpoint observation != global delivery state
```

## 11. Repository registry

The repository registry is structural-only and contains no production delivery destination, credential, payload or recipient identity.

An empty registry remains conformant with an intent result of `not-evaluated`.

## 12. E15-A2 transfer-attempt boundary

E15-A2 consumes only an E15-A1 intent whose derived state is `admissible`. It adds three independently bound objects:

```text
transfer attempt
external delivery evidence
recipient acknowledgement
```

A transfer attempt binds the exact intent revision, endpoint, carrier, recipient scope, payload commitment, attestation policy, attempt sequence, attempt idempotency key and local observation.

Local results are `prepared`, `submitted`, `locally-completed`, `failed`, `contested` and `unavailable`.

They are local observations only:

```text
locally-completed != remote acceptance
submitted != delivered
failed != proof of global non-delivery
```

## 13. External attesters and policies

An attester profile binds a versioned identity authority, evidence classes, endpoint scope and authentication algorithms. Identity states are `verified`, `rejected`, `contested` and `unavailable`.

An external-attestation policy binds allowed attesters, evidence types, authentication algorithms, freshness windows and whether an acknowledgement is required or optional.

The reference checker validates the declared bindings and policy state. It does not establish the honesty, availability or non-collusion of an external service.

## 14. External delivery evidence

External delivery evidence binds one exact transfer attempt, attester revision, policy revision, endpoint, carrier, recipient scope, payload digest, validity window, observed event and authentication reference.

Evidence states remain separate from lifecycle states:

```text
positive | negative | contested | unavailable
```

A positive `service-acceptance` record proves only the bounded statement carried by that authenticated record. It does not prove recipient possession or human awareness.

## 15. Recipient acknowledgements

A recipient acknowledgement binds one transfer attempt and one delivery-evidence record. Acknowledgement types are `service-generated`, `recipient-interface-generated` and `recipient-principal-signed`.

Even a positive acknowledgement does not establish physical possession, comprehension, awareness or downstream retention. It proves only the typed acknowledgement event and bindings represented by the record.

## 16. E15-A2 lifecycle decision

E15-A2 evaluates five gate coordinates:

```text
binding_result
attester_result
freshness_result
delivery_evidence_result
acknowledgement_result
```

Gate values are `permit`, `deny`, `held` and `unavailable`. The derived lifecycle state is one of:

```text
not-started
in-progress
externally-attested
rejected
held
contested
unavailable
```

Known negative evidence precedes contested, unavailable and held states. A local attempt with no external evidence is `not-started` or `in-progress`, never `externally-attested`. Positive delivery evidence with a missing required acknowledgement is `held`.

## 17. Structural-before-lifecycle replay

E15-A2 replays the exact E15-A1 source commit in an isolated tree before interpreting transfer evidence. Current-tree substitution is forbidden.

The order is:

```text
exact E15-A1 source commit
  -> historical E14 + E15-A1 replay
  -> additive E15-A2 transition
  -> current transfer/evidence/acknowledgement evaluation
```

## 18. E15-A3 publication boundary

E15-A3 consumes only an exact E15-A2 lifecycle decision whose state is `externally-attested`. It adds four independently bound objects:

```text
external publication record
bounded persistence observation
independent readback
publication lifecycle decision
```

A publication record binds the exact A2 attempt and decision commitment, publisher revision, publication policy, locator kind, mechanism, payload digest and size, time window, idempotency key, process and network-path identifiers, external event and authentication reference.

A positive publication record proves only the bounded external event represented by that record.

```text
published != publicly reachable
published != persistent
published != durable
published != independently readable
```

## 19. Publisher, observer and policy profiles

Publisher and readback-observer profiles have distinct identity, principal, provider and implementation coordinates. A publication policy states allowed publishers and observers, locator and mechanism classes, freshness limits, the minimum number and spacing of persistence observations, whether readback is required, and the exact independence dimensions that a readback must satisfy.

A different process does not imply a different implementation, provider or principal. Independence is never inferred from a display name or one differing identifier.

## 20. Bounded persistence observations

A persistence observation records one exact publication, observer revision, locator, payload digest, observation time, validity limit, event, evidence state and authentication reference.

Positive observations are counted only when they are exact, fresh and sufficiently spaced. Their result is bounded by the recorded times, observer, locator and policy.

```text
one observation != durability
repeated observations != indefinite retention
unreachable != absent
absence at one locator != global absence
```

## 21. Independent readback

A readback binds one exact publication and records the bytes obtained through one declared route. Positive readback requires matching locator, payload digest and byte count, plus every independence dimension required by policy.

Digest equality establishes byte identity only. It does not establish semantic truth, publisher honesty, future availability or provider independence beyond the declared dimensions.

## 22. E15-A3 lifecycle decision

E15-A3 evaluates nine gate coordinates:

```text
binding_result
publisher_result
observer_result
freshness_result
publication_result
persistence_result
readback_result
independence_result
content_identity_result
```

Gate values remain `permit`, `deny`, `held` and `unavailable`. Lifecycle states are:

```text
not-published
publication-observed
persistence-observed
independently-read-back
rejected
held
contested
unavailable
```

Known negatives precede contested, unavailable and incomplete results. Satisfying bounded persistence without a qualifying readback yields `persistence-observed`, not a universal durability claim.

## 23. Structural-before-lifecycle replay

E15-A3 materializes exact E15-A2 source commit `25988d80571f0f8d3587d976810a2dd8e0ce2328` in an isolated tree, replays the complete historical E14→E15-A2 chain and executes the frozen A2 unit suite before interpreting A3 records.

The order is:

```text
exact E15-A2 source commit
  -> historical E14 + E15-A1 + E15-A2 replay
  -> additive E15-A3 transition
  -> current publication/persistence/readback evaluation
```

## 24. E15-A4 withdrawal boundary

E15-A4 consumes only an exact E15-A3 publication record and an exact E15-A3 lifecycle decision whose state is one of:

```text
publication-observed
persistence-observed
independently-read-back
```

It adds distinct authorities for:

```text
withdrawal authority profile
distribution operator profile
distribution target profile
withdrawal policy and request
registry tombstone
distribution stop record
post-withdrawal observation
withdrawal lifecycle decision
```

A withdrawal authority authorizes the request. A distribution operator acts on one declared target. A post-withdrawal observer reports one bounded target event. These roles are not interchangeable.

## 25. Requests, targets and operators

A withdrawal request binds the exact E15-A3 publication and decision commitments, payload digest and byte count, authority revision, policy revision, withdrawal sequence, idempotency key, registered target set and bounded time window.

A target profile binds one locator, locator kind, tombstone capability and admitted stop mechanisms. An operator profile binds its managed targets, mechanisms and authentication algorithms.

```text
withdrawal authority != target operator
target A evidence != target B evidence
same locator label != same target revision
request admitted != request executed
```

## 26. Tombstone and distribution-stop heads

Registry tombstones and distribution-stop records form commitment-chained histories per exact withdrawal request and target.

The first entry has sequence or generation 1 and no predecessor. Every later entry binds the immediately preceding id and commitment. Decisions must cite the latest registered head.

Therefore a stale positive head cannot hide a later negative head:

```text
installed -> removed
stopped -> resumed
```

A removed tombstone or resumed distribution is a known negative. It is not reduced to an unavailable or incomplete result.

## 27. Bounded post-withdrawal observations

A post-withdrawal observation binds one exact request, target, locator, inherited E15-A3 observer revision, payload identity, event, observation time, validity limit, process, network path and authentication reference.

Positive events are limited to:

```text
tombstone-visible
not-found
```

Known negative events include:

```text
still-available
digest-mismatch
```

`unreachable` remains unavailable evidence and is never interpreted as absence.

## 28. E15-A4 lifecycle decision

E15-A4 evaluates twelve gate coordinates:

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

Gate values remain `permit`, `deny`, `held` and `unavailable`. Lifecycle states are:

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

Known negatives precede contested, unavailable and incomplete results. Missing target evidence preserves the strongest completed bounded state; it does not fabricate global completion.

## 29. Structural-before-lifecycle replay

E15-A4 materializes exact E15-A3 source commit `f403e93dd6d1dcb058474d67f2cc7e73b8ad13bd` in an isolated tree, replays the complete historical E14→E15-A3 chain and executes the frozen A3 unit suite before interpreting A4 records.

The order is:

```text
exact E15-A3 source commit
  -> historical E14 + E15-A1 + E15-A2 + E15-A3 replay
  -> additive E15-A4 transition
  -> current withdrawal/tombstone/stop/observation evaluation
```

## 30. E15-A5 independent verifier boundary

E15-A5 consumes only explicit result coordinates from the closed A1–A4 chain. It does not reopen or reinterpret individual delivery, publication or withdrawal records.

The final relation classifies the deepest explicitly established bounded stage after applying precedence:

```text
known negative
  -> unavailable
  -> held
  -> deepest positive bounded stage
```

The positive stages range from `delivery-evidence-bounded` through `withdrawal-evidence-bounded`.

## 31. Differential replay

The frozen matrix is replayed by two separate Python implementations. Neither imports the other. A matrix case conforms only when both implementations agree with the frozen expected state.

This separation reduces accidental implementation identity. It does not prove conceptual independence, mathematical completeness or absence of correlated defects.

## 32. Exact A4 replay and final freeze

E15-A5 materializes exact E15-A4 source commit `fce0ba52930e32069b54ab8f5634501a130222a7`, executes the exact inherited replay chain, compares the A4 report with its frozen fixture and runs the A4 unit tests before current-tree closure evaluation.

The profile is promoted to:

```text
EIGIIB-E15-1.0
```

The final freeze records exact bytes and SHA-256 digests for the complete E15 authority surface and excludes itself to avoid a self-digest cycle.

## 33. Non-goals and proof boundary

E15 does not establish absolute material delivery, remote service honesty, recipient possession or human awareness, universal availability, indefinite durability, global withdrawal or erasure, recipient-side deletion, legal recall, instantaneous propagation, unregistered-mirror closure, collusion resistance, universal verifier correctness or external durability of the freeze.

Therefore:

```text
withdrawal requested != withdrawal executed
tombstone installed != bytes erased
distribution stopped != recipient copy deleted
not-found at one target != global absence
matrix agreement != universal correctness
final freeze != externally durable storage
```

## 34. Reference tools

Current E15-A5 checker: `tools/eigiib_e15_final_closure_check.py`.

Independent matrix tools:

```text
tools/eigiib_e15_external_evidence_reference.py
tools/eigiib_e15_external_evidence_independent.py
tools/eigiib_e15_verifier_matrix.py
```

Historical E15-A4 replay bridge: `tools/eigiib_historical_e15_a4_replay.py`.

All reference tools use Python standard-library facilities and repository-local Git history.
