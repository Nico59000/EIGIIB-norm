# E14-A5 — Independent Verifier Matrix, Release-Boundary Replay and Final E14 Authority Freeze

Status: final normative closure slice 1.0.

## 1. Purpose

E14-A5 closes the remaining distinction between an A4-admissible disclosure path and a recorded release boundary.

```text
A4 admissible != released
release event != external delivery proof
release receipt != recipient possession proof
matching verifiers != universal correctness
final authority freeze != immutable external storage
```

A5 also promotes the E14 profile revision from `EIGIIB-E14-draft-1.0` to `EIGIIB-E14-1.0` and freezes the exact repository authority set used for closure.

## 2. Functional chain

```text
A1 committed projection
+ A2 bounded authorization
+ A3 correlation-control consumption
+ A4 fresh non-rolled-back admissibility
+ A5 release policy, recipient/transport evidence and release replay
= bounded release event
```

No lower-layer positive result is silently inherited. Every A5 release request binds the exact identifiers, revisions and commitments consumed from A1 through A4.

## 3. Release policies

A release policy is versioned and states:

- allowed audiences;
- allowed purposes;
- allowed endpoints;
- required transport-property identifiers;
- maximum payload bytes;
- whether recipient-authentication evidence is required;
- active, retired, contested or unavailable state.

Policy identifiers do not prove external policy authority. They are repository-local authorities subject to exact revision binding.

## 4. Release requests

A release request binds:

```text
A4 decision + attempt revision
A1 record/projection commitments
A2 request/decision revision
A3 enforcement/consumption revision
A4 distribution commitment
audience + purpose + endpoint
release policy + revision
payload bytes + payload SHA-256
release nonce
recipient-authentication state + evidence identifiers
transport state + properties + evidence identifiers
```

The reference envelope uses the projection commitment as the payload digest. A different byte carrier requires a separately defined artifact-binding extension and is outside E14-A5.

## 5. Release events

Release-event states are exactly:

```text
released
rejected
held
unavailable
```

The checker derives five component results:

```text
upstream_result
policy_result
recipient_result
transport_result
replay_result
```

Known negative states dominate:

1. A4 rejection, policy denial, unauthenticated recipient, unprotected transport or nonce replay → `rejected`;
2. otherwise any unavailable component → `unavailable`;
3. otherwise any held component → `held`;
4. otherwise → `released`.

Only prior `released` events consume a release nonce. Rejected, held and unavailable events do not consume it.

One event is permitted per release request. Event sequence numbers are unique and contiguous from 1.

## 6. Release receipts

A `released` event requires one committed receipt binding the exact:

- event and request;
- request revision;
- release nonce;
- projection and distribution commitments;
- audience and endpoint;
- payload digest;
- transport-session identifier.

The receipt commitment is canonical SHA-256 over the receipt envelope excluding the commitment field.

A non-released event must not reference a receipt. Orphan receipts are invalid.

A valid receipt proves only that the repository envelope is internally consistent. It does not prove that a remote recipient received, retained, decrypted or understood the payload.

## 7. Independent verifier matrix

The matrix authority is `conformance/e14-a5-verifier-matrix.json`.

Two implementations replay every frozen vector:

- reference: `tools/eigiib_e14_release_check.py`;
- independent: `tools/eigiib_e14_release_independent.py`.

The independent implementation does not import the reference implementation. The matrix requires both implementations and the frozen expected state to agree for every vector.

The matrix covers positive release, each known negative, held and unavailable states, including negative precedence over unavailability.

This is bounded differential replay of the release-decision relation. It is not proof that both implementations cannot share the same conceptual defect.

## 8. Final authority freeze

`conformance/e14-a5-authority-freeze.json` binds:

- the exact E14-A4 source head;
- the final E14 profile revision;
- every required E14 authority path;
- exact byte length and SHA-256 digest for each frozen authority.

The freeze excludes itself to avoid a self-digest cycle. Its schema and checker are frozen as separate entries.

Any missing, extra or altered authority makes the freeze non-conformant.

## 9. Profile promotion

The final profile revision is:

```text
EIGIIB-E14-1.0
```

A1–A4 checkers accept the final revision for backward-compatible replay of their own boundaries. A5 requires the final revision exactly.

## 10. Non-goals

E14-A5 does not establish:

- external delivery or recipient possession;
- recipient identity beyond supplied evidence identifiers;
- confidential transport beyond supplied state and evidence identifiers;
- distributed linearizability or exactly-once external effects;
- globally trusted time or instantaneous revocation propagation;
- recall, erasure or deletion from remote systems;
- anonymity, unlinkability or zero knowledge;
- universal verifier independence;
- external persistence of the frozen repository state.

Therefore:

```text
released repository event != proven external delivery
receipt commitment != remote possession
matrix agreement != mathematical completeness
frozen authority set != externally durable publication
```

## 11. Reference tools

```text
tools/eigiib_e14_release_check.py
tools/eigiib_e14_release_independent.py
tools/eigiib_e14_release_matrix.py
```

All use the Python standard library only.

## 12. E14-A5-F1 bounded correction

A5-F1 rebinds the final freeze to the corrected A4 head, refreezes the corrected checker bytes and makes report comparison independent of platform newline representation. It does not change the release relation, registry schema, verifier vectors or final profile revision.

