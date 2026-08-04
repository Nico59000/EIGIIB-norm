# M0-A15-F1 — Authenticated evidence binding and derived reconciliation

M0-A15-F1 is an additive corrective successor to M0-A15. It replaces declarative positive evidence flags with canonical, digest-bound and Ed25519-authenticated records while leaving the frozen M0-A15 authority unchanged.

The verifier materializes the exact M0-A14 commit and tree, validates its frozen authority inventory, loads the exact historical A14 replay implementation from that commit, and replays the supplied A14 continuity history. Four registered witnesses must endorse the resulting replay digest.

Every registry receipt is signed by its registered key. Receipt digests and candidate views are recomputed from canonical payloads. A split brain exists only when authenticated receipts at one sequence derive different candidate views. The proof, supporting registries, quarantined registries, accepted view, reconciliation digest, checkpoint digest and long-term certificate are all derived rather than trusted as labels.

The baseline includes no live evidence and is therefore `NF`. A future `T` remains limited to the exact source revisions and bounded authenticated history supplied to the checker. It does not establish legal identity, universal independence, future agreement, external-service honesty or global absence of divergence.
