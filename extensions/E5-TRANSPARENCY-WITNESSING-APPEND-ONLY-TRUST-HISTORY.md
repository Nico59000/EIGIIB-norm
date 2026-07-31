# EIGIIB-E5 — Transparency, Witnessing and Append-Only Trust History

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0 and EIGIIB-E1 through EIGIIB-E4 1.0  
**Reference checker:** `tools/eigiib_transparency_check.py`

---

## 1. Purpose

EIGIIB-E5 defines how a project may make trust-relevant history externally inspectable, append-only verifiable, and independently witnessed without collapsing publication, inclusion, consistency, witnessing, authentication, freshness, or semantic truth into one Boolean.

E5 exists because the following implications are invalid unless an explicit policy supplies the missing premise:

```text
entry published              != entry true
entry included               != history append-only
checkpoint signed            != checkpoint globally observed
checkpoint witnessed         != witness independent
witness quorum               != diversity
newer checkpoint             != consistent extension
no observed fork             != no fork exists
proof of consistency         != globally unique view
log availability             != log completeness
history inclusion            != trust-policy authorization
root-change logged           != root-change legitimate
revocation logged            != revocation effective
fresh checkpoint             != trusted time
```

E5 therefore treats transparency as a set of explicit relations over exact log entries, checkpoint commitments, append-only proofs, witness observations, and E4-authenticated trust-history events.

---

## 2. Normative terms

- **transparency log**: an ordered append-only commitment structure whose entries are addressed by stable sequence positions and committed by checkpoints.
- **entry**: exact bytes admitted at one log index. Inclusion establishes membership in a checkpoint, not semantic truth.
- **leaf hash**: the domain-separated hash commitment to exact entry bytes under the log's hash profile.
- **checkpoint**: a statement committing to a log identifier, tree size, and Merkle root, optionally carrying sequence, time, operator authentication, or previous-checkpoint metadata.
- **inclusion proof**: evidence that one entry contributes to one checkpoint root.
- **consistency proof**: evidence that a later checkpoint extends an earlier checkpoint without changing the earlier prefix.
- **append-only relation**: the verified relation `C_old ⪯ C_new` between two checkpoints of the same log.
- **fork**: two checkpoint views that cannot both belong to one append-only history under the selected log profile.
- **split view**: observation of incompatible checkpoint views by different consumers or witnesses.
- **witness**: an independently identified observer that records a checkpoint view. A witness identifier is not proof of independence.
- **witness observation**: a record binding a witness to exact checkpoint identity, optionally authenticated through E4.
- **witness policy**: a rule for required witness count, distinctness, diversity, authentication, and freshness.
- **gossip**: exchange or comparison of checkpoint views between observers. E5 defines the semantics of compared views but not a network protocol.
- **trust-history event**: an entry that binds a transition or object from E4 trust governance into the transparency history.
- **history coverage**: the declared set of trust-relevant event classes that a log promises to record.
- **baseline checkpoint**: a checkpoint explicitly accepted as the starting state for one append-only evaluation.

---

## 3. Core separation

For a checkpoint `C`, E5 distinguishes:

```text
CheckpointIdentity(C)
InclusionValidity(e, C)
ConsistencyValidity(C0, C1)
WitnessCoverage(C, W)
AuthenticationValidity(C, P_E4)
TrustHistoryCoverage(H)
```

A conforming implementation MUST NOT collapse these into a single `verified`, `transparent`, or `trusted` field.

### 3.1 Inclusion

A valid inclusion proof establishes only that exact entry bytes are committed by the specified checkpoint root at the specified index under the declared tree algorithm.

### 3.2 Consistency

A valid consistency proof establishes only that two exact checkpoints are related by the declared append-only construction.

### 3.3 Witnessing

A witness observation establishes that a declared witness observed or endorsed exact checkpoint identity according to the observation record. If authentication is required, E4 must authenticate that observation.

### 3.4 Trust history

A trust-history event establishes that exact history bytes were committed. Legitimacy of a root, delegation, revocation, or policy transition remains governed by E4.

---

## 4. Reference Merkle profile

E5-1.0 defines the reference profile:

```text
sha256-merkle-domain-v1
```

Let `H = SHA-256` and `||` denote byte concatenation.

### 4.1 Empty tree

```text
MTH([]) = H("")
```

### 4.2 Leaf

For exact leaf bytes `d`:

```text
MTH([d]) = H(0x00 || d)
```

### 4.3 Internal node

For child hashes `L` and `R`:

```text
Node(L, R) = H(0x01 || L || R)
```

For more than one leaf, the tree is split at the largest power of two strictly smaller than the number of leaves, recursively applying the same rule.

The domain prefixes `0x00` and `0x01` are normative. A checker MUST NOT omit them.

### 4.4 Exact bytes

Entry bytes MUST be identified without implicit semantic reserialization. A local reference entry may identify either:

- a repository-relative file path, whose exact bytes are hashed; or
- an explicit UTF-8 string, whose encoded bytes are hashed exactly.

JSON objects MUST NOT be parsed and reserialized as leaf bytes unless a separately identified canonicalization profile explicitly requires it.

---

## 5. Log object

A log is modeled as:

```text
Log = (
    id,
    purpose,
    tree_profile,
    operator,
    history_coverage,
    status
)
```

Canonical status values are:

```text
active
frozen
retired
compromised
unknown
```

A log identifier MUST be stable within its authority domain.

A log's `purpose` and `history_coverage` are claims of intended use, not proof that all matching events were actually included.

---

## 6. Entry object

An entry is modeled as:

```text
Entry = (
    id,
    log,
    index,
    bytes,
    kind,
    subject,
    external_bindings
)
```

### 6.1 Index uniqueness

For one log, each material index MUST identify at most one entry byte sequence in one evaluated view.

Two different leaf hashes claimed for the same `(log, index)` constitute conflicting registry data and MUST NOT be silently reconciled.

### 6.2 Kinds

E5 does not impose a universal entry taxonomy. Common kinds include:

```text
artifact
attestation
checkpoint
evidence
trust-root-add
trust-root-retire
delegation
revocation
policy-change
release
incident
```

Custom kinds are permitted if their semantics are owned by an explicit authority.

### 6.3 E4 binding

A trust-relevant entry MAY bind to an E4 object or authenticated attestation. Logging that binding does not by itself authenticate it.

---

## 7. Checkpoint object

A checkpoint is modeled as:

```text
Checkpoint = (
    id,
    log,
    size,
    root_hash,
    statement_artifact,
    operator_attestation,
    issued_at,
    predecessor
)
```

The minimum commitment is `(log, size, root_hash)`.

### 7.1 Tree size

`size` is the number of leaves committed by the checkpoint. It MUST be a non-negative integer.

### 7.2 Root identity

`root_hash` MUST use the log's declared tree profile.

### 7.3 Signed checkpoint

A checkpoint MAY be authenticated through E4. A valid operator signature establishes authenticated checkpoint origin under policy; it does not establish append-only consistency or global visibility.

### 7.4 Same-size conflict

For one log, two checkpoints with the same `size` and different `root_hash` values are incompatible views.

A checker MUST preserve this as fork/split-view evidence. It MUST NOT choose one root by timestamp, lexical order, or majority unless a policy explicitly defines that recovery rule.

---

## 8. Inclusion relation

Write:

```text
e ∈ C
```

when an inclusion proof establishes that entry `e` at index `i < size(C)` is committed by `root(C)`.

For the reference profile, an inclusion proof is an ordered sequence of sibling hashes with explicit side:

```text
left
right
```

The verifier starts at the entry leaf hash and applies `Node(sibling,current)` for `left` or `Node(current,sibling)` for `right` until the checkpoint root is obtained.

A path that yields the root but refers to a different log, index, or checkpoint is not a valid proof for the claimed relation.

---

## 9. Append-only relation

For checkpoints `C0` and `C1` of the same log, write:

```text
C0 ⪯ C1
```

when:

1. `size(C0) <= size(C1)`;
2. both checkpoint identities are established;
3. a consistency method accepted by the log policy establishes that the first `size(C0)` leaves committed by `C1` are exactly those committed by `C0` in the same order.

### 9.1 Equality

If sizes and root hashes are equal, the checkpoints are content-equivalent for the Merkle commitment, though their statement artifacts or observation metadata may differ.

### 9.2 Strict extension

If `size(C0) < size(C1)` and `C0 ⪯ C1`, `C1` is a strict append-only extension of `C0`.

### 9.3 No monotonic-size shortcut

`size(C0) < size(C1)` alone MUST NOT establish append-only extension.

---

## 10. Reference consistency profile

The E5-1.0 reference checker supports:

```text
prefix-recompute-v1
```

A proof record identifies an older checkpoint, a newer checkpoint, and the complete ordered entry-id sequence for the newer checkpoint.

The verifier:

1. resolves exactly `size(C1)` entries;
2. verifies indices are contiguous from zero;
3. recomputes `MTH(entries[0:size(C0)])` and compares it with `root(C0)`;
4. recomputes `MTH(entries[0:size(C1)])` and compares it with `root(C1)`.

This profile is intentionally simple and may be linear in tree size. It is a reference correctness profile, not a scalability recommendation.

Implementations MAY define compact consistency-proof profiles. Such profiles MUST identify their algorithm and MUST NOT be treated as equivalent merely because they also use SHA-256.

---

## 11. Fork and split-view semantics

### 11.1 Observed fork

A registry has direct fork evidence if it contains incompatible same-log checkpoints for which no accepted append-only relation can make both views part of one history.

Same-size/different-root checkpoints are direct fork evidence.

### 11.2 Attribution

Fork evidence does not by itself prove which party caused the conflict. Attribution to an operator or witness requires authenticated identities and appropriate policy evidence.

### 11.3 Absence of fork evidence

No observed fork means only that the evaluated data contains no detected fork. It MUST NOT be reported as proof that no unobserved split view exists.

### 11.4 Gossip

Gossip systems SHOULD compare exact checkpoint identity tuples rather than human-readable version labels.

E5-1.0 does not standardize transport or gossip scheduling.

---

## 12. Witness object

A witness is modeled as:

```text
Witness = (
    id,
    principal,
    key_or_attestation_policy,
    domain,
    operator_relation,
    status
)
```

Canonical witness status values are:

```text
active
retired
suspended
unknown
```

A witness record describes an asserted observer identity. Real independence is a policy and governance property, not derivable from a string field.

---

## 13. Witness observation

A witness observation is modeled as:

```text
WitnessObservation = (
    id,
    witness,
    checkpoint,
    observed_at,
    attestation,
    result
)
```

Canonical result values are:

```text
observed
rejected
conflict
unavailable
```

An `observed` record without E4 authentication is only a declared observation unless the selected witness policy explicitly permits unauthenticated observations.

---

## 14. Witness policies

A witness policy MAY constrain:

- minimum witness count;
- distinctness unit;
- required domains;
- prohibited common operator relation;
- E4 authentication requirement;
- maximum observation staleness;
- required consistency path to a baseline;
- mandatory conflict handling.

Canonical mechanically comparable distinctness units are:

```text
witness
principal
domain
```

### 14.1 No count-to-independence inference

Three witness IDs do not establish three independent witnesses.

A policy MAY count distinct domains, but domain labels themselves remain governance assertions unless authenticated or externally validated.

### 14.2 Quorum

A checkpoint satisfies a simple witness quorum only if the selected observations meet all count, distinctness, required-domain, authentication, and checkpoint-identity constraints.

---

## 15. Witnessed checkpoint relation

Write:

```text
W ⊨P observe(C)
```

when witness observation set `W` satisfies witness policy `P` for exact checkpoint `C`.

This relation establishes policy-compliant observation coverage. It does not establish semantic truth of log entries and does not replace append-only consistency proofs.

A checkpoint may therefore be:

```text
included-but-unwitnessed
witnessed-but-consistency-unverified
consistency-verified-but-unwitnessed
witnessed-and-consistency-verified
```

All are meaningful states.

---

## 16. Checkpoint freshness and time

### 16.1 Observation time

An observation timestamp proves only what its authentication/time source permits.

### 16.2 Freshness policy

A witness policy MAY require observations within an explicit interval relative to a trusted evaluation time.

A generic checker MUST NOT silently use wall-clock time as a normative input when deterministic replay matters.

### 16.3 Signed time field

A signed `issued_at` field remains an authenticated assertion by the signer, not independently trusted time unless E4 policy supplies trusted-time evidence.

---

## 17. Append-only trust history

E5 may bind E4 governance changes into a log.

A trust-history event is modeled as:

```text
TrustHistoryEvent = (
    id,
    entry,
    event_class,
    e4_object,
    e4_attestation,
    effective_at,
    coverage_policy
)
```

Common event classes include:

```text
root-added
root-retired
root-revoked
key-compromised
delegation-added
delegation-revoked
policy-changed
revocation-added
recovery-action
```

### 17.1 Logging is not authorization

Inclusion of `root-added` does not make a key a root. E4 must authorize the transition.

### 17.2 Authorization is not logging

An E4-authorized trust change may still violate an E5 policy that requires every such change to be transparently logged before activation.

### 17.3 History binding

A trust-history policy MAY require:

```text
E4 authentication of transition
AND
E5 inclusion before activation
AND
append-only consistency from baseline
AND
witness quorum on containing checkpoint
```

Only the conjunction establishes the stronger transparent-governance claim.

---

## 18. History coverage

A project MUST declare which event classes its transparency history claims to cover.

Examples:

```text
all production trust-root changes
all production revocations
release signing policy changes
```

A checker MUST NOT infer completeness from a non-empty log.

### 18.1 Coverage gaps

If a required event class cannot be mapped to log entries for an evaluated interval, the history state is `partially-evaluated`, `incomplete`, or `unavailable` according to policy; it is not silently `complete`.

### 18.2 Bootstrap

A transparency system MUST identify its bootstrap/baseline semantics. Events before the baseline are outside the append-only claim unless separately imported and committed.

---

## 19. Trust-history state reconstruction

E5 MAY be used to reconstruct a sequence of E4 trust-governance statements, but E5 does not replace E4 state semantics.

A reconstruction procedure MUST distinguish:

```text
logged event
E4-authenticated event
E4-authorized transition
currently effective trust state
```

Replay order MUST follow explicit log order and E4 temporal policy.

Two logged events that are individually authenticated can still be mutually incompatible under E4 policy.

---

## 20. Transparency decision states

### 20.1 Inclusion decision

```text
included
not-included
invalid-proof
not-evaluated
unavailable
```

### 20.2 Consistency decision

```text
consistent
inconsistent
same-checkpoint
not-evaluated
unavailable
```

### 20.3 Witness decision

```text
witnessed
partially-witnessed
conflicted
not-evaluated
unavailable
```

### 20.4 Trust-history decision

```text
bound
partially-bound
incomplete
conflicted
not-evaluated
unavailable
```

These axes are independent.

---

## 21. E5 capabilities, not a scalar level

E5-1.0 defines four capability claims:

```text
structural
append-only-verified
witnessed
trust-history-bound
```

They are not a universal total order.

- `structural` means registry/reference invariants were mechanically validated.
- `append-only-verified` means selected checkpoint relations were verified under declared consistency profiles.
- `witnessed` means selected checkpoint observations satisfy declared witness policies.
- `trust-history-bound` means selected E4 trust-history events satisfy declared inclusion/authentication/history policy.

A conformance report MUST identify which capability was evaluated and which remains `not-evaluated`.

---

## 22. Machine-readable registry

A machine-readable E5 registry SHOULD contain:

```text
standard
revision
logs
entries
checkpoints
inclusion_proofs
consistency_proofs
witnesses
observations
witness_policies
witness_decisions
trust_history_events
trust_history_policies
trust_history_decisions
```

Repository-relative paths MUST obey E2 confinement rules.

E4 attestation/decision identifiers SHOULD be referenced rather than manually duplicating trust results.

---

## 23. Mechanical E5 checks

A generic E5 checker SHOULD verify:

- supported standard/profile identifiers;
- unique IDs and resolved references;
- log/index uniqueness;
- exact local entry-byte confinement;
- reference leaf hashes and checkpoint roots;
- inclusion proof reconstruction;
- reference consistency-proof recomputation;
- same-size/different-root conflict detection;
- checkpoint/log/index agreement;
- witness-policy count/distinctness rules;
- required witness-domain presence;
- E4 authenticated-decision references when policy requires them;
- trust-history entry and E4-object references when available;
- deterministic result ordering.

A generic checker MUST NOT infer:

- witness real-world independence;
- log operator honesty;
- global absence of forks;
- semantic truth of entries;
- completeness of external gossip;
- completeness of revocation sources;
- legitimacy of E4 roots beyond E4 policy results.

---

## 24. Reference checker boundary

The E5-1.0 reference checker:

1. uses Python 3.11+ standard library only;
2. performs no network access;
3. executes no repository-provided commands;
4. recomputes the reference Merkle profile locally;
5. verifies explicit-sided inclusion paths;
6. verifies `prefix-recompute-v1` consistency records;
7. detects direct same-size split views;
8. checks declared witness quorum mechanics;
9. may consume E4 decision records but does not perform E4 cryptography itself;
10. reports unsupported/unevaluated semantics instead of guessing.

E4 cryptographic authentication remains owned by E4 and its checker/provider boundary.

---

## 25. Reference report

A report SHOULD separate:

```json
{
  "structural_result": "conformant",
  "append_only_result": "not-evaluated",
  "witness_result": "not-evaluated",
  "trust_history_result": "not-evaluated",
  "fork_state": "none-observed",
  "findings": []
}
```

`none-observed` MUST NOT be presented as `fork-free`.

---

## 26. Test-only logs and witnesses

Projects MAY ship test fixtures for Merkle proofs, checkpoints, witness policies, and fork detection.

Test fixtures MUST NOT become production logs, production witnesses, or production baselines merely because they exist in the repository.

A fixture witness SHOULD be visibly marked `test_only = true` or equivalent.

---

## 27. Retention

A project claiming append-only verification MUST retain enough information to re-establish the selected checkpoint relations.

Depending on profile, this may include:

- checkpoints;
- compact consistency proofs;
- complete prefixes;
- witness observations;
- authenticated checkpoint statements.

Retention policy MAY prune bulk entry payloads if retained commitments and policy still support the claimed verification.

A project MUST NOT claim replayability after deleting the only data needed by its selected proof profile.

---

## 28. Recovery and key/log compromise

If a log operator key or witness key is compromised, E4 governs cryptographic trust while E5 preserves historical observations.

A recovery process SHOULD record:

- last accepted checkpoint;
- compromise boundary if known;
- recovery/root-change E4 authorization;
- replacement log or key identity;
- continuity or discontinuity declaration;
- witness observations around the transition.

A new key does not automatically repair an inconsistent history.

---

## 29. Multi-log systems

A project MAY use multiple logs for availability or governance separation.

Cross-logging MAY strengthen observability, but E5 does not infer independence from log count.

Policies SHOULD state whether they require:

```text
entry in any one accepted log
entry in every required log
checkpoint cross-logged by another log
witness quorum spanning operator domains
```

---

## 30. Privacy boundary

Transparency can conflict with confidentiality or data minimization.

E5 does not require plaintext sensitive content in public logs.

Projects MAY log commitments to private artifacts if the commitment scheme and disclosure policy preserve the required identity semantics.

A digest commitment may itself leak information for small/guessable domains; confidentiality is not implied by hashing.

---

## 31. Denial-of-service and resource bounds

A checker SHOULD bound:

- maximum entry count;
- maximum proof path length;
- maximum inline entry byte length;
- maximum checkpoint count;
- maximum witness observation count.

A registry that exceeds implementation limits should yield `unavailable` or a resource-limit finding rather than unbounded resource consumption.

Limits MUST be implementation metadata, not silently interpreted as normative limits of E5.

---

## 32. Cross-extension relations

The intended separation is:

```text
E1: what claim/evidence is asserted?
E2: is repository conformance mechanically coherent?
E3: what exact artifacts and provenance are involved?
E4: who authenticated/authorized exact statements under trust policy?
E5: are trust-relevant statements transparently committed, append-only related, and sufficiently witnessed?
```

No later extension retroactively changes the semantics owned by an earlier authority.

---

## 33. Canonical invariants

An E5-conforming design preserves at least:

1. inclusion does not imply truth;
2. signing does not imply append-only consistency;
3. increasing size does not imply consistency;
4. one witness does not imply independence;
5. witness count does not imply diversity without a distinctness rule;
6. absence of observed fork does not prove global uniqueness;
7. logging a trust change does not authorize it;
8. authorizing a trust change does not prove it was logged when logging is required;
9. same-size/different-root views are preserved as conflict evidence;
10. proof algorithms are identified explicitly;
11. exact bytes are committed without implicit reserialization;
12. E4 authentication remains distinct from E5 transparency;
13. history coverage is explicit and bounded;
14. test logs/witnesses cannot silently become production authorities;
15. transparency capability claims never exceed evaluated proof/witness data.

---

## 34. Adoption rule

A project adopting E5 SHOULD first identify the ambiguity it needs transparency to remove.

It SHOULD NOT introduce a log merely to increase apparent process maturity.

A useful transparency artifact answers a concrete question such as:

- Was this exact release/trust transition committed before activation?
- Does this checkpoint extend the checkpoint I previously observed?
- Did sufficiently distinct witnesses observe the same checkpoint?
- Is this revocation/root change present in the declared history interval?

If no engineering decision depends on the answer, additional transparency machinery is probably unjustified explicitness.
