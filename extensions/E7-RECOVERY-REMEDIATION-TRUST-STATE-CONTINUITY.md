# EIGIIB-E7 — Recovery, Remediation and Trust-State Continuity

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0 and EIGIIB-E1 through EIGIIB-E6 1.0  
**Reference checker:** `tools/eigiib_recovery_check.py`

---

## 1. Purpose

EIGIIB-E7 defines how a project may recover from trust-relevant incidents without collapsing detection, containment, repair, trust-state transition, continuity, rollback, closure, or root-cause resolution into one Boolean.

The following implications are invalid unless an explicit policy supplies the missing premise:

```text
incident detected             != incident contained
key revoked                   != trust restored
new key installed             != old authority safely superseded
service resumed               != continuity established
recovery action completed     != action effective
rollback performed            != prior state restored exactly
incident closed               != root cause eliminated
remediation succeeded         != historical evidence erased
```

Recovery is modeled as an explicit transition between typed trust states, justified by actions and evidence, with reversible conclusions when later evidence invalidates an earlier recovery decision.

---

## 2. Core terms

- **incident**: a bounded trust-relevant condition requiring containment, remediation, recovery, or explicit non-action.
- **containment**: action intended to limit further use or propagation of unsafe authority or state.
- **remediation**: action intended to change a defective or unsafe condition.
- **trust state**: a named snapshot of trust-relevant authority configuration at one recovery epoch.
- **recovery epoch**: a non-negative logical ordering of trust states; it is not wall-clock time.
- **recovery action**: one typed planned or executed change.
- **recovery plan**: a finite dependency graph over recovery actions.
- **transition**: an asserted move from one trust state to a strictly later trust state.
- **continuity**: an explicitly evidenced relation connecting a superseded trust state to an active replacement state.
- **closure**: a bounded decision that declared incident closure criteria hold.
- **rollback**: a later compensating transition after a recovery step is rejected, superseded, or found unsafe.
- **reopen**: reactivation of a previously closed incident because new evidence invalidates or narrows the closure claim.

---

## 3. Core separation

For an incident `I`, E7 distinguishes:

```text
Detection(I)
Containment(I)
Remediation(I)
TrustTransition(I)
Continuity(I)
Closure(I)
CauseResolution(I)
```

A conforming implementation MUST NOT collapse them into one `resolved`, `fixed`, `healthy`, or `recovered` field when the distinction changes engineering action.

Detection is not containment. Containment is not repair. Repair is not continuity. Continuity is not closure. Closure is bounded and does not prove global safety, complete causal understanding, or absence of latent defects.

---

## 4. Incident lifecycle

Canonical incident states are:

```text
detected
contained
recovering
continuity-established
closed
reopened
```

The lifecycle state records position only; evidence justifying it remains separate.

Incident classes MAY include key compromise, root compromise, policy defect, fork, split view, artifact corruption, provenance break, signature failure, witness failure, operator error, supply-chain break, and `unknown`.

`unknown` MUST remain available while classification is not established.

---

## 5. Trust states and epochs

A trust state SHOULD record:

```text
id
epoch
status
roots
policies
delegations
revocations
checkpoints
artifacts
boundary
```

Canonical status values are:

```text
candidate
active
retired
superseded
quarantined
```

A verified recovery transition from `S0` to `S1` MUST satisfy:

```text
S1.epoch > S0.epoch
```

Rollback MUST NOT decrease the epoch. A rollback creates another later state, even when the later state intentionally resembles an earlier one. This preserves rejected and superseded history.

---

## 6. Recovery evidence

E7 evidence is a typed binding and does not replace E1. It MAY refer to E1 evidence, E3 artifacts/events/replays, E4 authenticated decisions, E5 checkpoints/history decisions, E6 fork/accountability evidence, tests, replays, manual reviews, or project-local immutable artifacts.

A lower-layer fact MUST NOT be promoted silently. For example, an E6 direct conflict remains evidence of incompatible commitments and MUST NOT become evidence of malicious intent merely because recovery was initiated.

---

## 7. Recovery actions

Canonical action classes are:

```text
freeze
quarantine
revoke
rotate
replace-root
replace-policy
rebuild
replay
restore
publish
re-witness
fork-resolution
resume
rollback
verify
```

Canonical action status values are:

```text
planned
in-progress
completed
failed
reverted
skipped
```

A material action marked `completed` MUST carry evidence describing what was observed after execution.

An attempted command is not automatically evidence of its intended effect. For example, a successful revocation command is not equivalent to proof that all relying parties now reject the key.

A generic E7 checker MUST NOT execute remediation commands supplied by the repository.

---

## 8. Recovery plans

A recovery plan is a finite directed acyclic graph over concrete action identifiers.

A dependency `(a,b)` means `a` precedes `b` under that plan. Cyclic recovery plans MUST be rejected mechanically.

Operational procedures may repeat the same *kind* of action, but each concrete action instance occupies one finite position in the recovery graph.

Partial execution MUST NOT be reported as completed recovery.

---

## 9. Containment

A containment decision MAY be established when its selected containment actions are completed and evidenced. Reference containment actions are:

```text
freeze
quarantine
revoke
```

Containment does not establish replacement authority. A compromised key can be successfully contained while no valid replacement exists.

---

## 10. Trust transitions

A transition SHOULD record:

```text
id
incident
from_state
to_state
actions
status
evidence?
policy?
```

Canonical transition states are:

```text
proposed
verified
rejected
superseded
```

A verified transition requires resolvable source/destination states, strict epoch advancement, completed required actions, evidence for completed actions, and satisfaction of any declared lower-layer bindings.

---

## 11. Trust-state continuity

Continuity is written:

```text
S_old =>[T] S_new
```

where `T` is a verified E7 transition and `S_new` is active for the claimed scope.

A profile MAY additionally require:

```text
E4 authentication of replacement authority
AND
E5 append-only publication of the transition
AND
E5 witness satisfaction
AND
E6 absence of conflicting observed replacement views in the evaluated closure
```

The profile MUST state which premises are mandatory.

A replacement state MUST NOT silently inherit all authority from its predecessor. Preserved authority must be explicit or derivable from an explicit policy.

---

## 12. Rotation and replacement

Rotation MUST distinguish at least:

```text
old authority disabled
new authority introduced
new authority authenticated
new authority published
new authority observed
historical treatment of old authority declared
```

E7 MUST NOT invent retrospective revocation semantics; E4 remains authoritative for that layer.

---

## 13. Rollback

Rollback is a forward compensating transition, never deletion of history.

A rollback record MUST identify:

```text
incident
superseded_transition
reason
compensating_actions
replacement_transition?
```

At least one compensating action is required.

If `S0(epoch=5) -> S1(epoch=6)` is rejected, rollback produces a later state such as `S2(epoch=7)`. It MUST NOT reset logical history to epoch 5.

Marking an action `reverted` records a later result and MUST NOT erase that the original action occurred.

---

## 14. Reopening

A closed incident MUST be reopenable when new evidence invalidates a closure premise.

Reopening does not erase the historical closure decision. A project SHOULD preserve the original closure, new contradicting evidence, reopen decision, and subsequent recovery plan or explicit no-action decision.

---

## 15. Closure

Closure requires the incident to be explicitly `closed`, required transitions to be verified, the destination trust state to be active, required E4/E5 bindings to resolve, required actions to be completed and evidenced, and `open_blockers` to be empty.

Closure MUST NOT imply complete root-cause analysis, global safety, or absence of recurrence risk unless a separate policy explicitly requires and establishes those claims.

---

## 16. Lower-layer authority

E7 MAY consume E4, E5, and E6 typed results but does not replace them:

```text
E4 remains authoritative for authentication
E5 remains authoritative for append-only/witness semantics
E6 remains authoritative for gossip/fork accountability
```

An E7 recovery response to `single-principal-equivocation` MUST preserve E6's boundary and MUST NOT rewrite it as intent or legal responsibility.

---

## 17. Typed decisions

Canonical E7 decision states are:

```text
contained
transition-verified
continuity-established
closed
reopened
unavailable
```

They are typed lifecycle conclusions, not scalar confidence levels.

---

## 18. Orthogonal capabilities

E7 defines independent capability results:

```text
structural
containment-verified
transition-verified
continuity-verified
closure-verified
```

A repository may conform structurally while having no production recovery incident or recovery history.

---

## 19. Mechanical checks

A generic E7 checker SHOULD verify:

- supported standard/version and unique ids;
- repository path confinement;
- incident/action/plan/state/transition references;
- trust-state epoch validity;
- completed actions have evidence;
- recovery action dependency graph is acyclic;
- verified transitions strictly advance epoch;
- transition actions are completed;
- rollback records include compensating actions;
- continuity destination is active;
- required E4/E5 decisions resolve when supplied;
- closed decisions have no open blockers;
- closed decisions correspond to incidents explicitly marked closed.

A generic checker MUST NOT execute recovery actions, mutate trust stores, rotate or revoke keys, infer that external relying parties adopted the replacement state, infer malicious intent or root cause, infer global safety, or erase superseded history.

---

## 20. Invariants

E7-I1. Detection is not containment.  
E7-I2. Containment is not remediation.  
E7-I3. Completed actions require evidence.  
E7-I4. Recovery plans are acyclic.  
E7-I5. Verified trust transitions strictly advance epoch.  
E7-I6. Rollback is forward compensation, never history deletion.  
E7-I7. Continuity requires an explicit transition.  
E7-I8. Closure is bounded and reopenable.  
E7-I9. Lower-layer semantics remain authoritative.  
E7-I10. Recovery does not imply cause resolution or global safety.

---

## 21. Non-goals

E7-1.0 does not standardize paging systems, disaster-recovery orchestration, secret escrow, HSM vendor procedures, backup formats, legal incident attribution, human approval UX, network failover, distributed consensus, automatic key rotation, or automatic rollback execution.

---

## 22. Repository adoption

A repository adopting E7 SHOULD declare `conformance/recovery.json` as its recovery authority.

A structurally empty E7 registry is valid when no production recovery claim is being made. A repository MUST NOT invent incidents, recovery actions, or successful closure merely to demonstrate conformance.
