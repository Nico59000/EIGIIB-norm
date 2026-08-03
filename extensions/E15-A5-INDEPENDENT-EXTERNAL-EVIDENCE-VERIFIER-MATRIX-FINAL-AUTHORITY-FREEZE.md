# E15-A5 — Independent External-Evidence Verifier Matrix and Final Authority Freeze

Status: final normative closure slice 1.0.

## 1. Purpose

E15-A5 closes the E15 lineage without collapsing bounded evidence into physical delivery, universal persistence or global erasure.

```text
external evidence != physical-world fact
matrix agreement != universal correctness
final freeze != externally durable storage
post-withdrawal observation != global erasure
```

The slice promotes the profile revision from `EIGIIB-E15-draft-1.3` to `EIGIIB-E15-1.0`, replays the exact E15-A4 source, differentially evaluates frozen external-evidence vectors with two non-importing implementations and freezes the complete final E15 authority surface.

## 2. Closure relation

The matrix consumes only explicit component results:

```text
lineage
external delivery
publication and readback
withdrawal governance
content identity
observer independence
anti-rollback
```

Known negatives dominate unavailable and held states. Otherwise unavailable dominates held. A positive result is classified at the deepest explicitly established bounded stage, from delivery evidence through post-withdrawal observation.

## 3. Final bounded states

```text
delivery-evidence-bounded
acknowledgement-evidence-bounded
publication-evidence-bounded
persistence-evidence-bounded
independent-readback-bounded
withdrawal-request-bounded
tombstone-bounded
distribution-stop-bounded
withdrawal-evidence-bounded
rejected
held
unavailable
```

These are verifier outputs over frozen vectors, not claims about a live external system.

## 4. Independent matrix

The matrix authority is `conformance/e15-a5-verifier-matrix.json`.

Two implementations replay every vector:

- reference: `tools/eigiib_e15_external_evidence_reference.py`;
- independent: `tools/eigiib_e15_external_evidence_independent.py`.

The independent implementation does not import the reference implementation. `tools/eigiib_e15_verifier_matrix.py` executes both as separate processes and requires agreement with the frozen expected state.

The vectors cover each bounded positive stage, known-negative precedence, insufficient declared independence, rollback detection, held and unavailable states.

## 5. Exact historical continuity

`tools/eigiib_historical_e15_a4_replay.py` materializes the exact E15-A4 head in an isolated tree. It executes the exact inherited replay chain, the exact A4 checker, the frozen A4 report comparison and the A4 unit tests before A5 interpretation begins.

Current-tree substitution for the historical A4 authority is forbidden.

## 6. Final closure authority

`conformance/e15-final-closure.json` binds the exact A4 source head, final profile revision, verifier implementations, matrix catalog, matrix runner and historical replay tool. It is structural closure metadata; it contains no production endpoint, locator, credential or external event.

## 7. Final authority freeze

`conformance/e15-a5-authority-freeze.json` records exact byte lengths and SHA-256 digests for the complete E15 authority surface used by the final checker. The freeze excludes itself to avoid a self-digest cycle.

Any missing, extra or altered authority makes the final closure non-conformant.

## 8. Profile promotion

The final profile revision is:

```text
EIGIIB-E15-1.0
```

A1–A4 current-tree checkers accept this final revision only for backward-compatible descendant replay of their own boundaries. Their frozen source revisions and exact historical replays remain unchanged.

## 9. Nonclaims

E15-A5 does not establish:

- physical or absolute material delivery;
- recipient possession or human awareness;
- external-service honesty;
- universal availability or indefinite durability;
- global erasure, recipient-side deletion or legal recall;
- instantaneous withdrawal propagation;
- deletion from unregistered mirrors;
- globally trusted time;
- universal verifier independence or mathematical completeness;
- external durability of the frozen repository state.
