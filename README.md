# EIGIIB norm

EIGIIB defines a general engineering rule for software and systems projects:

> **Explicit Is Good, Implicit Is Better. Too explicit is never good.**

The repository separates authority by concern instead of repeating the standard.

- [`EIGIIB-STANDARD.md`](EIGIIB-STANDARD.md) — canonical core specification.
- [`extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md`](extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md) — typed evidence, claim boundary, uncertainty, contradiction, and conformance semantics.
- [`extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md`](extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md) — mechanically decidable repository-conformance contract.
- [`extensions/E3-REPRODUCIBLE-EVIDENCE-PROVENANCE-ARTIFACT-IDENTITY.md`](extensions/E3-REPRODUCIBLE-EVIDENCE-PROVENANCE-ARTIFACT-IDENTITY.md) — artifact identity, production provenance, replay and reproducibility semantics.
- [`extensions/E4-AUTHENTICATED-ATTESTATIONS-TRUST-ROOTS-PROVENANCE-INTEGRITY.md`](extensions/E4-AUTHENTICATED-ATTESTATIONS-TRUST-ROOTS-PROVENANCE-INTEGRITY.md) — authenticated attestations, trust roots, delegation, revocation and provenance-integrity semantics.
- [`extensions/E5-TRANSPARENCY-WITNESSING-APPEND-ONLY-TRUST-HISTORY.md`](extensions/E5-TRANSPARENCY-WITNESSING-APPEND-ONLY-TRUST-HISTORY.md) — transparency logs, append-only checkpoints, witnessing and transparent trust-history semantics.
- [`extensions/E6-GOSSIP-CROSS-LOG-CONSISTENCY-FORK-ACCOUNTABILITY.md`](extensions/E6-GOSSIP-CROSS-LOG-CONSISTENCY-FORK-ACCOUNTABILITY.md) — multi-observer gossip comparison, cross-log anchoring and bounded fork-accountability semantics.
- [`extensions/E7-RECOVERY-REMEDIATION-TRUST-STATE-CONTINUITY.md`](extensions/E7-RECOVERY-REMEDIATION-TRUST-STATE-CONTINUITY.md) — recovery actions, remediation plans, monotone trust-state transitions, rollback and bounded closure semantics.
- [`extensions/E7-RECOVERY-HARDENING-PROFILE-0.2.md`](extensions/E7-RECOVERY-HARDENING-PROFILE-0.2.md) — additive E7 incident-boundary, rollback and verified-result hardening profile.
- [`extensions/E8-RELYING-PARTY-CONVERGENCE-MIGRATION-SAFETY-TRUST-STATE-ADOPTION.md`](extensions/E8-RELYING-PARTY-CONVERGENCE-MIGRATION-SAFETY-TRUST-STATE-ADOPTION.md) — relying-party adoption, legacy rejection, compatibility windows, explicit exceptions and bounded cutover semantics.
- [`extensions/E9-DEGRADED-OPERATION-SAFE-FALLBACK-PARTIAL-TRUST-AVAILABILITY.md`](extensions/E9-DEGRADED-OPERATION-SAFE-FALLBACK-PARTIAL-TRUST-AVAILABILITY.md) — degraded operation, explicit fallback substitution, capability gating, partial trust and bounded nominal restoration.
- [`extensions/E9-DEGRADED-HARDENING-PROFILE-0.2.md`](extensions/E9-DEGRADED-HARDENING-PROFILE-0.2.md) — additive E9 evidence-materiality, guarantee-partition and fallback-minimum hardening profile.
- [`extensions/E10-POLICY-SAFE-AUTOMATION-DELEGATED-EXECUTION-DECISION-ACCOUNTABILITY.md`](extensions/E10-POLICY-SAFE-AUTOMATION-DELEGATED-EXECUTION-DECISION-ACCOUNTABILITY.md) — policy-safe authorization, explicit delegation, revision-bound approvals, delegated execution and bounded accountability traces.
- [`extensions/E10-AUTOMATION-HARDENING-PROFILE-0.2.md`](extensions/E10-AUTOMATION-HARDENING-PROFILE-0.2.md) — additive E10 exact-boundary and revision binding for all decision states.
- [`extensions/E11-TEMPORAL-VALIDITY-FRESHNESS-LEASES-REPLAY-RESISTANCE.md`](extensions/E11-TEMPORAL-VALIDITY-FRESHNESS-LEASES-REPLAY-RESISTANCE.md) — explicit temporal observations, conservative uncertainty, freshness, leases, renewal lineage, grace intervals and replay resistance.
- [`schemas/eigiib-e1-record.schema.json`](schemas/eigiib-e1-record.schema.json) — E1 typed registry schema.
- [`schemas/eigiib-e2-ownership.schema.json`](schemas/eigiib-e2-ownership.schema.json) — E2 durable-fact ownership schema.
- [`schemas/eigiib-e3-provenance.schema.json`](schemas/eigiib-e3-provenance.schema.json) — E3 provenance-registry schema.
- [`schemas/eigiib-e4-trust.schema.json`](schemas/eigiib-e4-trust.schema.json) — E4 trust/attestation registry schema.
- [`schemas/eigiib-e5-transparency.schema.json`](schemas/eigiib-e5-transparency.schema.json) — E5 transparency/witness registry schema.
- [`schemas/eigiib-e6-gossip.schema.json`](schemas/eigiib-e6-gossip.schema.json) — E6 gossip/cross-log/accountability registry schema.
- [`schemas/eigiib-e7-recovery.schema.json`](schemas/eigiib-e7-recovery.schema.json) — E7 recovery/trust-state continuity registry schema.
- [`schemas/eigiib-e7-recovery-hardening.schema.json`](schemas/eigiib-e7-recovery-hardening.schema.json) — supplementary E7 hardening schema.
- [`schemas/eigiib-e8-convergence.schema.json`](schemas/eigiib-e8-convergence.schema.json) — E8 relying-party convergence registry schema.
- [`schemas/eigiib-e9-degraded.schema.json`](schemas/eigiib-e9-degraded.schema.json) — E9 degraded-operation and partial-trust registry schema.
- [`schemas/eigiib-e9-degraded-hardening.schema.json`](schemas/eigiib-e9-degraded-hardening.schema.json) — supplementary E9 hardening schema.
- [`schemas/eigiib-e10-automation.schema.json`](schemas/eigiib-e10-automation.schema.json) — E10 automation/delegation/accountability registry schema.
- [`schemas/eigiib-e11-temporal.schema.json`](schemas/eigiib-e11-temporal.schema.json) — E11 temporal-validity registry schema.
- [`eigiib-conformance.schema.json`](eigiib-conformance.schema.json) — E2 normalized checker-report schema.
- [`tools/eigiib_check.py`](tools/eigiib_check.py) — dependency-free Python 3.11+ E2 reference checker.
- [`tools/eigiib_provenance_check.py`](tools/eigiib_provenance_check.py) — static E3 artifact/provenance checker.
- [`tools/eigiib_trust_check.py`](tools/eigiib_trust_check.py) — E4 trust checker with optional fixed OpenSSL Ed25519 verification.
- [`tools/eigiib_transparency_check.py`](tools/eigiib_transparency_check.py) — E5 Merkle/inclusion/consistency/witness checker.
- [`tools/eigiib_gossip_check.py`](tools/eigiib_gossip_check.py) — E6 static gossip, cross-log and fork-accountability checker.
- [`tools/eigiib_recovery_check.py`](tools/eigiib_recovery_check.py) — E7 static recovery-plan, transition, rollback and continuity checker.
- [`tools/eigiib_recovery_hardening_check.py`](tools/eigiib_recovery_hardening_check.py) — additive E7 hardening checker.
- [`tools/eigiib_convergence_check.py`](tools/eigiib_convergence_check.py) — E8 static relying-party convergence and cutover checker.
- [`tools/eigiib_degraded_check.py`](tools/eigiib_degraded_check.py) — E9 static degraded-operation, fallback and partial-trust checker.
- [`tools/eigiib_degraded_hardening_check.py`](tools/eigiib_degraded_hardening_check.py) — additive E9 hardening checker.
- [`tools/eigiib_automation_check.py`](tools/eigiib_automation_check.py) — E10 static policy, delegation, approval, execution and accountability checker.
- [`tools/eigiib_automation_hardening_check.py`](tools/eigiib_automation_hardening_check.py) — additive E10 decision-boundary hardening checker.
- [`tools/eigiib_temporal_check.py`](tools/eigiib_temporal_check.py) — E11 static temporal observation, lease, freshness, renewal and replay checker.
- [`conformance/provenance.json`](conformance/provenance.json) — this repository's E3 provenance authority.
- [`conformance/trust.json`](conformance/trust.json) — this repository's E4 trust authority; structural-only with no production trust root asserted.
- [`conformance/transparency.json`](conformance/transparency.json) — this repository's E5 transparency authority; structural-only with no production log or witness asserted.
- [`conformance/gossip.json`](conformance/gossip.json) — this repository's E6 gossip/accountability authority; structural-only with no live gossip network, production fork or attribution asserted.
- [`conformance/recovery.json`](conformance/recovery.json) — this repository's E7 recovery authority; structural-only with no production incident or recovery success asserted.
- [`conformance/convergence.json`](conformance/convergence.json) — this repository's E8 convergence authority; structural-only with no production relying-party inventory or convergence asserted.
- [`conformance/degraded.json`](conformance/degraded.json) — this repository's E9 degraded-operation authority; structural-only with no production outage, fallback or partial-trust mode asserted.
- [`conformance/automation.json`](conformance/automation.json) — this repository's E10 automation authority; structural-only with no production authorization, execution or accountability trace asserted.
- [`conformance/temporal.json`](conformance/temporal.json) — this repository's E11 temporal authority; structural-only with no production time source, lease, freshness or replay result asserted.
- [`EIGIIB.toml`](EIGIIB.toml) — this repository's adoption profile.

The checkers execute no repository-provided build, test, generator, remediation, deployment, fallback, routing, automation, or shell command. E2 validates mechanically decidable repository invariants. E3 recomputes local artifact identities and provenance/replay graph invariants. E4 may invoke only its fixed cryptographic provider adapter and keeps signature validity, trust, authorization and semantic truth separate. E5 recomputes its reference Merkle profile, inclusion/consistency relations and declarative witness quorum mechanics, while consuming E4 authentication only as an external typed decision. E6 compares exact E5 checkpoint views, validates directed cross-log references and applies a deliberately narrow attribution profile without inferring malicious intent, real-world identity, peer independence, global fork absence, or atomic cross-log state. E7 validates recovery structure, acyclic plans, evidenced completed actions, monotone trust-state transitions, rollback compensation and bounded closure without executing recovery actions or inferring root-cause resolution or global safety; its hardening profile closes additional mechanically decidable boundary gaps. E8 evaluates bounded relying-party observations, distinctness rules, explicit exceptions, legacy rejection and cutover prerequisites without contacting parties, inferring real-world independence, or claiming global convergence. E9 evaluates dependency observations, capability prerequisites, explicit fallback substitution, unknown-state policy, partial-trust modes and nominal-restoration prerequisites without probing dependencies or promoting service availability to full trust; its hardening profile requires material evidence items, coherent guarantee partitions and preservation of capability-specific availability minima across fallback substitution. E10 validates explicit authority roots and delegation paths, revision-bound approvals, authorization policy, independent executor authority, execution/effect separation and bounded accountability traces without executing actions, creating approvals, inferring consent, identity, culpability or global safety; its hardening profile preserves exact proposal/policy/context identity for every decision state, including negative and unavailable decisions. E11 never reads the host clock: it validates explicit in-domain observations with bounded uncertainty, half-open lease windows, freshness thresholds, renewal lineage, grace-state separation and replay assertions while keeping temporal admissibility distinct from E10 authority and from any claim of globally trusted time.

## Validation

```sh
python -m unittest discover -s tests -p 'test_*.py'
python tools/eigiib_check.py . --json
python tools/eigiib_provenance_check.py . --json
python tools/eigiib_trust_check.py . --crypto-provider openssl --json
python tools/eigiib_transparency_check.py . --json
python tools/eigiib_gossip_check.py . --json
python tools/eigiib_recovery_check.py . --json
python tools/eigiib_recovery_hardening_check.py . --json
python tools/eigiib_convergence_check.py . --json
python tools/eigiib_degraded_check.py . --json
python tools/eigiib_degraded_hardening_check.py . --json
python tools/eigiib_automation_check.py . --json
python tools/eigiib_automation_hardening_check.py . --json
python tools/eigiib_temporal_check.py . --json
```

MIT License.
