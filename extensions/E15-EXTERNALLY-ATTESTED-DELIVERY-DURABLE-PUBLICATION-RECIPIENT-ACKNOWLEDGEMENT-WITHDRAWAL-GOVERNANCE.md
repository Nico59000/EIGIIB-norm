# EIGIIB-E15 — Externally Attested Delivery, Durable Publication, Recipient Acknowledgement and Withdrawal Governance

Status: draft normative extension 1.1, adopted through E15-A2 from the exact E15-A1 historical authority.

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

## 18. Planned companions

E15-A3 will own external publication records, bounded persistence observations and independent readback.

E15-A4 will own withdrawal, tombstones and post-delivery governance.

E15-A5 will own the independent external-evidence verifier matrix and final freeze.

## 19. Non-goals and proof boundary

E15-A1 does not establish absolute material delivery, remote service acceptance, recipient possession or human awareness, publication or persistence, universal availability, infinite durability, global withdrawal or erasure, legal recall, external-service honesty, collusion resistance or universal interoperability.

Therefore:

```text
admissible != delivered
endpoint verified != endpoint reachable
carrier active != carrier used
policy permit != external acceptance
idempotency available != exactly-once external effect
```

## 20. Reference tools

Current E15-A2 checker: `tools/eigiib_delivery_evidence_check.py`.

Historical E15-A1 replay bridge: `tools/eigiib_historical_e15_a1_replay.py`.

The E15-A1 checker and historical E14 bridge remain historical source authorities. All reference tools use Python standard-library facilities and repository-local Git history.
