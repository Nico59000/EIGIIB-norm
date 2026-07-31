# EIGIIB-E12 manual boundary review

Revision reviewed: `EIGIIB-E12-draft-1.0` with additive hardening profile `EIGIIB-E12-hardening-0.2`.

- `commit-revalidation-boundary-review`: complete.
- E12 owns only exact operation binding across check/use, conservative E11 commit-time revalidation, declared one-shot consumption relations, idempotency binding, and bounded commit/replay conclusions.
- E10 remains authoritative for proposal, policy, authorization, approval, execution and effect semantics. E12 consumes an E10 `authorized` decision and execution record but does not recreate their proof.
- E11 remains authoritative for temporal observations, validity, freshness, leases and replay semantics. E12 compares explicit E11 observations but never reads the host clock or invents cross-domain time conversion.
- E7 remains authoritative for remediation/compensation semantics. An E12 `compensated` commit preserves historical commit identity and is not evidence that the commit never happened.
- `operation_identity` is a SHA-256 plus byte-length binding selected by the E10 proposal/E12 operation. It is not semantic correctness, authentication, confidentiality or benign intent.
- An evidence-backed `atomic_store` declaration is only a bounded premise. The static checker does not prove database linearizability, acquire a lock, execute compare-and-set, run a transaction, consume a token or establish exactly-once behavior in an external system.
- A unique E12 idempotency key binds one declared operation to one canonical commit within the declared store/namespace. It does not establish application-level semantic idempotence beyond that boundary.
- `commit-safe` does not imply an E10 effect was observed, that a remote side effect occurred exactly once, or that the commit cannot later be disputed or compensated.
- `idempotent-replay` means that the current reused attempt resolves the pre-existing canonical E12 commit without a new consumption or commit record. It does not assert byte-identical remote response content without operation-specific evidence.

Post-baseline audit added E12-H0.2 without rewriting the green baseline. H0.2 requires a commit-time E11 decision to use an observation distinct from the check-time observation; a second decision object over the same observation is not commit-time revalidation. For positive `commit-safe`, the commit also declares one baseline-valid `atomic_store`, and any required one-shot consumption and idempotency binding must use that same store. For `idempotent-replay`, the committed idempotency record must use the canonical commit's atomic store.

These H0.2 relations close repository-level false positives only. They still do not prove that a remote storage engine provides linearizable transactions, that a remote effect occurs exactly once, or that the application operation is semantically idempotent.

The repository's `conformance/commit.json` remains structural-only: it asserts no production atomic store, committed production operation, consumed authorization token, live idempotency binding or production commit-safety decision.

No deviation is accepted by this attestation.
