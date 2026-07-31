# EIGIIB-E12 manual boundary review

Revision reviewed: `EIGIIB-E12-draft-1.0`.

- `commit-revalidation-boundary-review`: complete.
- E12 owns only exact operation binding across check/use, conservative E11 commit-time revalidation, declared one-shot consumption relations, idempotency binding, and bounded commit/replay conclusions.
- E10 remains authoritative for proposal, policy, authorization, approval, execution and effect semantics. E12 consumes an E10 `authorized` decision and execution record but does not recreate their proof.
- E11 remains authoritative for temporal observations, validity, freshness, leases and replay semantics. E12 compares two explicit E11 observations but never reads the host clock or invents cross-domain time conversion.
- E7 remains authoritative for remediation/compensation semantics. An E12 `compensated` commit preserves historical commit identity and is not evidence that the commit never happened.
- `operation_identity` is a SHA-256 plus byte-length binding selected by the E10 proposal/E12 operation. It is not semantic correctness, authentication, confidentiality or benign intent.
- An evidence-backed `atomic_store` declaration is only a bounded premise. The static checker does not prove database linearizability, acquire a lock, execute compare-and-set, run a transaction, consume a token or establish exactly-once behavior in an external system.
- A unique E12 idempotency key binds one declared operation to one canonical commit within the declared store/namespace. It does not establish application-level semantic idempotence beyond that boundary.
- `commit-safe` does not imply an E10 effect was observed, that a remote side effect occurred exactly once, or that the commit cannot later be disputed or compensated.
- `idempotent-replay` means that the current reused attempt resolves the pre-existing canonical E12 commit without a new consumption or commit record. It does not assert byte-identical remote response content without operation-specific evidence.

The repository's `conformance/commit.json` remains structural-only: it asserts no production atomic store, committed production operation, consumed authorization token, live idempotency binding or production commit-safety decision.

No deviation is accepted by this attestation.
