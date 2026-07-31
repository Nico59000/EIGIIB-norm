# EIGIIB-E13 manual boundary review

Revisions reviewed: `EIGIIB-E13-draft-1.0` and additive `EIGIIB-E13-hardening-0.2`.

- `policy-composition-boundary-review`: complete.
- E13 owns explicit multi-policy composition, conflict derivation, obligation activation/evaluation and bounded obligation waivers.
- E10 remains authoritative for each constituent authorization and for the separate E10 authorization used to waive an obligation.
- E12 remains authoritative for commit-time revalidation and atomic commit safety; E13 `permitted` is not E12 `commit-safe`.
- Composition algorithm selection is itself an explicit authoritative profile fact. EIGIIB provides no ambient `deny-overrides`, `permit-overrides` or ordering rule.
- A conflict resolved mechanically by an algorithm is not evidence that the contributing policies semantically agree.
- Residual pre-commit/post-commit/audit obligations are not silently treated as satisfied.
- The baseline defines only `obligation-waiver`; it does not introduce ambient permit/deny break-glass override.
- Hardening 0.2 requires every `required` member to be conclusively evaluated before a positive `permitted` result; presence alone is insufficient.
- Hardening 0.2 rejects unknown E10 states consumed by the composition layer.
- Hardening 0.2 binds an active obligation waiver to the exact request context and context revision; an authorization from another or stale context cannot waive the current obligation.
- The static checkers do not run an external policy engine, discover live policy applicability, execute actions or infer legal responsibility.

`conformance/policy-composition.json` remains structural-only and asserts no production composition, policy conflict, waiver or obligation satisfaction.

No deviation is accepted by this attestation.
