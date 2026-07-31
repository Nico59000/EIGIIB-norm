# EIGIIB-E8 — Relying-Party Convergence, Migration Safety and Trust-State Adoption

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0 and EIGIIB-E1 through EIGIIB-E7 1.0  
**Reference checker:** `tools/eigiib_convergence_check.py`

---

## 1. Purpose

EIGIIB-E8 defines how a project may establish that a trust-state transition has been adopted by its intended relying parties without collapsing local continuity, fleet adoption, compatibility, stale acceptance, cutover, or global convergence into one Boolean.

The following implications are invalid unless an explicit policy supplies the missing premise:

```text
replacement state active      != relying party adopted
one party migrated            != fleet converged
quorum observed               != every party migrated
new state accepted            != old state rejected
compatibility maintained      != migration complete
dual acceptance allowed       != dual acceptance safe forever
cutover declared              != cutover observed
old state still accepted      != relying party compromised
no stale acceptance observed  != no stale acceptance exists
convergence in scope          != global convergence
exception authorized          != migration fully complete
```

E8 models convergence as explicit observations of relying-party behavior under a bounded migration policy.

---

## 2. Core terms

- **relying party**: a consumer, verifier, service, deployment class, or other bounded actor whose trust-state behavior is relevant to a migration.
- **migration**: a declared move from one E7 trust-state epoch to a later epoch.
- **adoption observation**: evidence describing whether one relying party accepts the new state and/or rejects the old state.
- **compatibility window**: an explicit period or logical phase during which old and new states may coexist.
- **migration policy**: a rule for minimum observed adoption, distinctness, required parties, legacy rejection, and explicit exceptions.
- **exception**: a bounded authorization for one relying party not to satisfy the ordinary migration requirement.
- **adoption decision**: a typed conclusion about convergence for one migration under one policy.
- **cutover decision**: a typed conclusion that a migration may treat the replacement state as the operational state for its declared scope.
- **stale acceptance**: continued acceptance of the superseded state after the point at which the applicable policy expected rejection.

---

## 3. Core separation

For migration `M`, E8 distinguishes:

```text
E7Continuity(M)
NewStateAcceptance(M, party)
OldStateRejection(M, party)
Compatibility(M)
AdoptionCoverage(M)
Cutover(M)
GlobalConvergence(M)
```

A conforming implementation MUST NOT collapse these into one `migrated`, `healthy`, `current`, or `complete` field when the distinction changes engineering action.

E7 remains authoritative for trust-state transition and continuity. E8 begins at the relying-party adoption boundary.

---

## 4. Relying parties

A relying-party record SHOULD identify:

```text
id
domain
class
required
status
boundary?
```

Canonical status values are:

```text
active
retired
unknown
```

`domain` and `class` are declared grouping labels. They are not proof of organizational, infrastructural, legal, or failure-domain independence.

A checker MUST NOT infer real-world independence from distinct identifiers alone.

---

## 5. Migration identity

A migration SHOULD record:

```text
id
from_epoch
to_epoch
e7_transition?
scope?
status
```

Canonical migration states are:

```text
planned
in-progress
cutover
closed
aborted
```

A migration from epoch `e0` to `e1` MUST satisfy:

```text
e1 > e0
```

When an E7 transition is declared, the transition remains authoritative for the actual trust-state relation.

---

## 6. Adoption observations

An observation SHOULD record:

```text
id
migration
party
phase
new_state
old_state
evidence
```

Canonical phases are:

```text
pre-cutover
cutover
post-cutover
```

Canonical acceptance states are:

```text
accepted
rejected
unknown
unavailable
not-applicable
```

An observation is evidence, not a command and not a desired state.

A party accepting the new state does not imply that it rejects the old state.

A party still accepting the old state does not imply compromise, malicious behavior, or operator fault.

Material observations used to establish positive adoption MUST carry evidence.

---

## 7. Compatibility windows

A compatibility window SHOULD record:

```text
id
migration
state
allow_old
evidence?
```

Canonical states are:

```text
planned
open
closed
expired
```

A closed compatibility window MUST NOT claim `allow_old = true`.

Compatibility is a migration mechanism, not evidence that migration is complete.

Dual acceptance MUST remain explicit when it exists.

---

## 8. Migration policies

A migration policy SHOULD record:

```text
id
minimum
distinct_by
require_old_rejected
require_all_required_parties
allow_exceptions
required_domains?
required_classes?
```

Reference distinctness dimensions are:

```text
party
domain
class
```

A distinctness label is a counting rule, not proof of independence.

A policy requiring all required parties MUST be evaluated against the relying parties marked `required = true` in the evaluated registry, subject only to explicitly authorized exceptions when the policy permits exceptions.

---

## 9. Exceptions

An exception MUST be explicit and bounded.

It SHOULD record:

```text
id
migration
party
reason
disposition
evidence?
```

Canonical dispositions are:

```text
temporary
permanent
not-applicable
```

An exception does not silently convert a non-adopting party into an adopting party.

If a convergence result depends on exceptions, the decision MUST use a state that exposes that fact.

---

## 10. Adoption decisions

Canonical decision states are:

```text
converged
converged-with-exceptions
partial
stalled
unavailable
```

A `converged` decision requires, for its selected observations and policy:

1. the policy minimum is satisfied under the declared distinctness rule;
2. every counted observation reports `new_state = accepted`;
3. if legacy rejection is required, every counted observation reports `old_state = rejected`;
4. required domains/classes are represented when declared;
5. if all required parties are required, every required party is represented by a satisfying observation;
6. no exception contributes to a `converged` result.

A `converged-with-exceptions` decision additionally requires the policy to allow exceptions and every uncovered required party to have an explicit exception for the migration.

Neither state establishes global convergence outside the declared registry and policy boundary.

---

## 11. Cutover

A verified cutover SHOULD bind:

```text
migration
adoption_decision
compatibility_window
require_e7_continuity
e7_decision?
```

A reference cutover requires:

- migration state `cutover` or `closed`;
- adoption decision `converged` or `converged-with-exceptions`;
- compatibility window `closed`;
- `allow_old = false`;
- required E7 continuity decision when the cutover profile asks for it.

Cutover does not prove every external cache, offline verifier, disconnected deployment, or unknown relying party has migrated.

---

## 12. Stale acceptance

Stale acceptance is a typed observation:

```text
phase = post-cutover
old_state = accepted
```

Its presence MUST remain visible.

It MUST NOT be rewritten as compromise, malicious intent, or identity attribution without separate evidence.

A policy MAY permit a bounded exception for a stale party, but the resulting convergence state must expose the exception.

---

## 13. Lower-layer authority

E8 may consume E7 continuity or closure decisions but does not replace E7.

```text
E7 remains authoritative for recovery and trust-state continuity.
E8 owns relying-party adoption, migration coverage, compatibility and cutover semantics.
```

E8 does not re-run E4 authentication, E5 Merkle/witness checking, E6 gossip/accountability, or E7 recovery transitions.

---

## 14. Orthogonal capabilities

E8 defines independent capability results:

```text
structural
adoption-verified
legacy-rejection-verified
cutover-verified
```

A repository may conform structurally while making no production relying-party convergence claim.

A convergence result may be established without a cutover result.

---

## 15. Mechanical checks

A generic E8 checker SHOULD verify:

- supported standard/version and collection structure;
- path confinement for local evidence;
- unique relying-party, migration, observation, policy, exception, window, and decision identifiers;
- migration epoch advancement;
- relying-party references;
- positive observations used by decisions carry evidence;
- compatibility window closure does not allow the old state;
- quorum and distinctness mechanics;
- required domain/class coverage;
- required-party coverage;
- exception authorization and explicit `converged-with-exceptions` state;
- E7 continuity reference resolution when required;
- verified cutover requires a closed compatibility window and a converged adoption decision.

A generic checker MUST NOT contact relying parties, mutate their configuration, infer real-world independence, infer compromise from stale acceptance, infer global convergence, or infer that unobserved parties have migrated.

---

## 16. Invariants

E8-I1. Local trust continuity is not relying-party adoption.  
E8-I2. New-state acceptance is not old-state rejection.  
E8-I3. Quorum coverage is not global convergence.  
E8-I4. Distinct identifiers are not proof of independence.  
E8-I5. Compatibility is not migration completion.  
E8-I6. Exceptions remain explicit in positive conclusions.  
E8-I7. Cutover requires explicit adoption evidence.  
E8-I8. Stale acceptance does not imply compromise.  
E8-I9. E7 remains authoritative for trust-state continuity.  
E8-I10. Unobserved parties remain unobserved.

---

## 17. Non-goals

E8-1.0 does not standardize deployment orchestration, package rollout, service discovery, client telemetry transport, certificate pinning UX, browser update channels, endpoint management, distributed consensus, fleet inventory discovery, or automatic cutover execution.

---

## 18. Repository adoption

A repository adopting E8 SHOULD declare `conformance/convergence.json` as its convergence authority.

A structurally empty E8 registry is valid when no production migration or relying-party adoption claim is being made. A repository MUST NOT invent relying parties, observations, or successful convergence merely to demonstrate conformance.
