# EIGIIB — Engineering Information Governance, Implicitness and Interface Boundaries

**Canonical rule:** **Explicit Is Good, Implicit Is Better. Too explicit is never good.**

**Status:** Draft normative specification 1.0  
**Intended scope:** Any software, systems, infrastructure, data, scientific, embedded, kernel, service, library, CLI, mobile, web, automation, or mixed-language development project.  
**Canonical format:** Markdown.  
**Normative language:** The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative as defined in §2.

---

## 1. Purpose

EIGIIB is a project-wide engineering standard for deciding **what must be made explicit, what should remain implicit in structure, and what must not be duplicated**.

Its goal is not minimal documentation. Its goal is **minimal sufficient explicitness**: every fact that must survive ambiguity, boundary crossing, maintenance, review, failure, or handoff is represented by one authoritative carrier; routine mechanics are carried by code, types, names, structure, generated artifacts, and executable evidence whenever those carriers are stronger than prose.

EIGIIB treats excessive explicitness as an engineering defect because redundant statements drift, create false authorities, increase review surface, hide important constraints in noise, and make stale documentation look trustworthy.

A conforming project therefore optimizes for all of the following at once:

1. contracts are unambiguous;
2. hazards and irreversible choices are discoverable;
3. routine mechanics are readable without narration;
4. each durable fact has one authority;
5. evidence and claims are kept distinct;
6. unavailable or unevaluated states are represented explicitly rather than guessed;
7. generated facts are generated, not manually re-described;
8. documentation grows only when a new ownership boundary requires it.

---

## 2. Normative language

Within this specification:

- **MUST / MUST NOT**: required for EIGIIB conformance;
- **SHOULD / SHOULD NOT**: default requirement; deviation is permitted only when the local reason is documented at the nearest authoritative boundary;
- **MAY**: permitted but not required;
- **authority**: the unique artifact or executable source that owns a fact;
- **fact**: a proposition about behavior, structure, state, evidence, policy, compatibility, risk, or lifecycle;
- **carrier**: the mechanism by which a fact is represented: type, name, code structure, schema, test, generated output, prose, diagram, protocol definition, configuration, or machine-readable registry;
- **boundary**: a place where responsibility, trust, lifecycle, component ownership, process, machine, repository, privilege, persistence, or user expectation changes;
- **claim**: a statement asserting that a property holds;
- **evidence**: an observation or executable result that supports a claim;
- **routine mechanic**: local behavior whose meaning is already complete in code, types, names, or standard language/platform semantics;
- **drift**: divergence between two representations that purport to describe the same fact.

---

## 3. Core principle

### 3.1 Minimal sufficient explicitness

For every engineering fact `f`, a project MUST select the **least verbose carrier** that preserves the fact across every boundary where loss or ambiguity would be material.

Let:

- `B(f)` be the set of boundaries crossed by `f`;
- `R(f)` be the risk caused by misunderstanding, omission, or stale restatement of `f`;
- `C(k,f)` be the maintenance and drift cost of expressing `f` through carrier class `k`;
- `A(k,f)` be the ambiguity remaining when carrier class `k` is used.

A conforming representation selects a carrier class `k*` such that:

```text
k* = argmin_k C(k,f)
subject to A(k,f) <= tolerated_ambiguity(B(f), R(f)).
```

This is the formal meaning of the EIGIIB rule:

- **Explicit is good** when a fact crosses a meaningful boundary or carries non-local risk.
- **Implicit is better** when the fact can be carried more reliably by structure, types, names, generated data, or executable checks.
- **Too explicit is never good** when additional prose does not close a real ambiguity and instead creates duplication, drift, or noise.

### 3.2 Explicitness classes

EIGIIB uses five representation classes. A project SHOULD choose the lowest sufficient class.

| Class | Carrier | Typical use |
|---|---|---|
| `E0` | language/platform semantics | universally standard local mechanics |
| `E1` | names, types, module boundaries, signatures, schemas | routine project semantics |
| `E2` | local rationale or hazard note | non-obvious local reason, workaround, trap |
| `E3` | normative contract or policy document | public/cross-component behavior, security, lifecycle, compatibility |
| `E4` | duplicated manual restatement | normally prohibited |

`E4` is not a higher quality level. It is a warning class. A manually repeated statement MUST NOT be introduced unless it has a distinct authority role that cannot be satisfied by reference or generation.

---

## 4. The six EIGIIB obligations

Every conforming project MUST satisfy six obligations.

### 4.1 Contract obligation

A behavior MUST be explicit when another component, process, repository, operator, user, or external system must rely on it without reading its implementation.

This includes, as applicable:

- public APIs and ABI constraints;
- wire formats and protocol versions;
- persistent data formats and migrations;
- CLI syntax with compatibility promises;
- configuration precedence and administrative locks;
- error and retry semantics;
- cancellation and timeout semantics;
- resource ceilings;
- concurrency guarantees;
- transaction and durability semantics;
- security/trust boundaries;
- compatibility and platform claims.

### 4.2 Structural obligation

Routine mechanics SHOULD be made self-explanatory through structure before prose is added.

A project SHOULD prefer, in this order where practical:

1. a stronger type;
2. a better name;
3. a narrower interface;
4. a clearer module boundary;
5. an executable invariant;
6. a generated representation;
7. a comment or prose explanation.

If prose is required to explain what straightforward code does, the code SHOULD first be evaluated for structural improvement.

### 4.3 Rationale obligation

A non-obvious decision MUST document **why** it exists when removing or changing it could reintroduce a defect, security weakness, compatibility break, irreversible migration, data loss, undefined behavior, or operational hazard.

Rationale MUST describe the constraint, not narrate the implementation.

Good:

> Parent-directory synchronization is separate from publication because successful rename does not by itself establish post-crash directory-entry durability.

Bad:

> Call `fsync()` after `rename()`.

The first preserves the engineering reason. The second merely repeats a mechanic visible in code.

### 4.4 Authority obligation

Each durable fact MUST have one authoritative owner.

Other artifacts MUST do one of the following:

- reference the authority;
- consume it mechanically;
- generate from it;
- state only the locally relevant consequence without pretending to be the fact's second authority.

Manual copy-and-paste synchronization of normative facts is non-conformant.

### 4.5 Evidence obligation

Claims MUST be typed by evidence. A project MUST NOT promote a design statement into an implementation or validation claim merely because the design is detailed.

At minimum, a project MUST distinguish:

- what is intended;
- what is implemented;
- what has been executed;
- where it has been executed;
- what remains unevaluated or unavailable.

### 4.6 Boundary obligation

A project MUST state the limit of every material claim.

Examples:

- “tested on Linux amd64” is not “portable to all supported systems”;
- “checksum verified” is not “origin authenticated”;
- “unit tested” is not “integration tested”;
- “source path exists” is not “runtime feature is available”;
- “design specified” is not “implementation complete”.

Claim boundaries SHOULD be adjacent to the claim or to its authoritative evidence record, not hidden in unrelated prose.

---

## 5. Information ownership model

### 5.1 Fact classes

A project SHOULD classify durable facts into the following ownership domains:

| Domain | Examples | Preferred authority |
|---|---|---|
| Scope | active, deferred, suspended, excluded work | charter / project map |
| Architecture | component responsibility and dependency direction | architecture document or executable module graph |
| Interface | API, protocol, schema, configuration | headers, IDL, schema, normative interface document |
| Policy | security, extraction, retention, privilege, compatibility | policy document |
| Capability | build/runtime availability | generated capability registry |
| State | milestone or feature lifecycle | machine-readable progress registry |
| Evidence | test execution, platform result, benchmark | validation record / CI artifact |
| Rationale | non-obvious choice or rejection | decision record or nearest authoritative design section |
| Operations | deployment, recovery, rollback, on-call action | runbook |
| Release | version, compatibility, migration | release metadata / changelog |

A project MAY combine domains in one artifact when doing so does not blur ownership. It MUST split them when different update cadences or authorities would create ambiguity.

### 5.2 One fact, one owner

For a fact `f`, let `owner(f)` be its normative source. A conforming project maintains:

```text
count(normative_owners(f)) = 1
```

Generated mirrors do not count as independent owners if they are reproducibly derived from the authority.

### 5.3 References instead of repetition

A document MUST NOT restate a long list already owned by a schema, generated capability report, registry, or other authoritative source merely for convenience.

It SHOULD state the semantic rule and link to the authoritative data.

---

## 6. Claim and evidence model

### 6.1 Orthogonal state axes

EIGIIB forbids overloaded status words whose meaning changes by context. Project state SHOULD be represented as a tuple with separate axes.

A recommended model is:

```text
State(feature) = (disposition, realization, evidence, environment)
```

#### Disposition

- `active`
- `deferred`
- `suspended`
- `rejected`
- `not-applicable`

#### Realization

- `idea`
- `adopted`
- `specified`
- `implemented`
- `integrated`
- `released`

#### Evidence

- `not-evaluated`
- `compiled`
- `unit-tested`
- `integration-tested`
- `platform-tested`
- `operationally-observed`

#### Environment

The environment field identifies the relevant compiler, runtime, operating system, architecture, service, hardware, dataset, or deployment context.

Projects MAY use a different vocabulary, but MUST preserve the separation between disposition, realization, and evidence.

### 6.2 Unknown and unavailable states

A project MUST represent absence of knowledge without inventing a Boolean result.

Recommended values include:

- `unknown`: the fact may be true or false but is not established;
- `not-evaluated`: no relevant evaluation was run;
- `unavailable`: required input, platform, service, artifact, or capability was not accessible;
- `not-applicable`: the question does not apply.

These values MUST NOT be silently collapsed into success or failure.

### 6.3 Monotone claims

Evidence MAY justify a stronger claim only when the stronger claim is a valid consequence of the evidence.

For example:

```text
specified -> implemented -> compiled -> unit-tested
```

is a common progression, but the existence of a later artifact does not prove all environments or integrations. A project MUST attach the environment and scope necessary to prevent false monotonicity.

### 6.4 Negative evidence

A failed test, rejected design, unavailable dependency, or unsupported platform is valid evidence and SHOULD be preserved when it constrains future engineering decisions.

EIGIIB does not treat “not successful” as “not useful”.

---

## 7. Code rules

### 7.1 Comments

Comments MUST explain one of the following:

- rationale;
- invariant not expressible locally;
- hazard;
- external constraint;
- intentional deviation;
- non-obvious complexity bound;
- compatibility requirement;
- synchronization or ownership rule.

Comments MUST NOT narrate obvious statements, repeat identifiers, paraphrase control flow, or duplicate public documentation.

### 7.2 Names

Names SHOULD encode stable semantics, not implementation history.

Prefer:

```text
publication_durability_confirmed
```

over:

```text
second_sync_ok
```

Prefer domain names over comments that repair weak names.

### 7.3 Types and invariants

If a property can be made invalid-by-construction, a project SHOULD encode it in types or constructors rather than document a usage warning.

Examples include:

- bounded sizes;
- validated identifiers;
- normalized paths;
- non-null ownership wrappers;
- explicit state machines;
- typed durations and byte counts;
- result/error variants.

### 7.4 Local duplication

A helper SHOULD remain private when its abstraction has no independent contract. Splitting implementation text into many exported modules solely to make every internal action “explicit” is non-conformant when it creates accidental API surface.

### 7.5 Magic values

A value MUST be explicit by name when its semantics are project-specific or safety-relevant. A standard idiom need not receive prose merely because it is numeric.

---

## 8. Interface and API rules

A public interface MUST make explicit all behavior a correct caller cannot safely infer.

At minimum, where applicable, document or encode:

- ownership and lifetime;
- mutability;
- thread safety;
- blocking behavior;
- cancellation;
- timeout/deadline basis;
- ordering;
- idempotence;
- retryability;
- error classes;
- partial-success semantics;
- resource limits;
- persistence/durability;
- compatibility/versioning;
- security assumptions.

An API SHOULD NOT describe internal algorithm steps unless those steps are part of the compatibility contract.

---

## 9. Architecture rules

### 9.1 Responsibility boundaries

Architecture documentation MUST explain which component owns which responsibility and which dependency directions are permitted.

It SHOULD NOT reproduce file-by-file implementation inventories unless the inventory is generated.

### 9.2 Hidden coupling

A dependency that is semantically required but invisible in interfaces is non-conformant. It MUST be represented through one of:

- an explicit dependency;
- a capability requirement;
- a state transition;
- a schema relation;
- a test-enforced invariant.

### 9.3 Private cohesion

EIGIIB permits large private implementation units when they preserve shared invariants better than artificial decomposition. Modularity is judged by contract clarity, not file count.

### 9.4 Optional capabilities

Optional dependencies MUST degrade explicitly. A missing provider MUST NOT silently activate a weaker or behaviorally different fallback unless that fallback is itself an explicit contract.

---

## 10. Security and trust rules

Security-relevant assumptions MUST be explicit at trust boundaries and SHOULD be implicit nowhere.

A conforming security description identifies, as applicable:

- trusted and untrusted inputs;
- privilege changes;
- filesystem/path authority;
- network peers and authentication;
- cryptographic purpose distinctions;
- resource ceilings;
- rollback ownership;
- persistence and durability boundaries;
- execution of external text or programs;
- residual obligations.

EIGIIB specifically requires semantic distinctions that are commonly blurred. Examples:

```text
integrity != authenticity
authentication != authorization
published != durable
available != permitted
parsed != validated
validated != trusted
encrypted != authenticated
successful call != successful transaction
```

These distinctions SHOULD be encoded as separate states or types when operationally material.

---

## 11. Configuration rules

Configuration MUST make precedence, source authority, validation, and locking semantics explicit when multiple sources exist.

Configuration SHOULD NOT expose internal tuning knobs merely to make implementation behavior visible.

A configuration option is justified only when at least one of the following holds:

- users need a legitimate policy choice;
- environments differ materially;
- compatibility requires it;
- a resource or safety ceiling must be controlled;
- diagnostics require intentional opt-in.

An option that merely externalizes an internal implementation detail SHOULD remain internal.

---

## 12. Testing and verification rules

### 12.1 Tests as executable documentation

A stable behavioral invariant SHOULD be expressed as an executable test when feasible.

A prose statement is not a substitute for a test when the property is executable and regression-sensitive.

### 12.2 Evidence records

Validation records MUST state:

- what was run;
- against which revision or artifact;
- in which environment;
- the observed result;
- the untested boundary.

### 12.3 Generated evidence

Counts, capability matrices, benchmark tables, schemas, and test inventories SHOULD be generated from authoritative inputs. Manually synchronized copies SHOULD NOT be maintained.

### 12.4 Adversarial evidence

When a contract rejects input or failure modes, tests SHOULD include negative cases. Success-path evidence alone does not establish a rejection policy.

---

## 13. Documentation rules

### 13.1 Document admission test

A new document is justified only if an existing authority cannot own the new fact without mixing concerns, conflicting update cadence, or creating unclear responsibility.

Before creating a document, answer:

1. What unique facts will it own?
2. Why can no existing authority own them cleanly?
3. What artifacts will reference or generate from it?
4. What would become ambiguous if it did not exist?

If no concrete answer exists, the document SHOULD NOT be created.

### 13.2 Document structure

A normative engineering document SHOULD favor:

1. purpose;
2. scope;
3. definitions;
4. invariants/contracts;
5. state or lifecycle;
6. failure semantics;
7. evidence or validation expectations;
8. exclusions/residual obligations.

Long narrative histories SHOULD live in changelogs or progress registers rather than contract documents.

### 13.3 Duplication rule

A document MUST NOT manually reproduce:

- generated command help;
- schema field inventories;
- full configuration defaults already generated from code;
- test counts derived from CI;
- capability tables generated by the program;
- version metadata owned by release tooling.

It MAY explain the semantics of those artifacts and reference them.

### 13.4 Diagrams

A diagram SHOULD express structure or flow that is materially clearer visually. A diagram that merely redraws a short list or mirrors source filenames SHOULD NOT be maintained manually.

---

## 14. Version control, issues, and pull requests

### 14.1 Commits

A commit message SHOULD state the semantic change and, when non-obvious, the reason. It SHOULD NOT restate the full diff.

### 14.2 Pull requests

A substantial pull request SHOULD make explicit:

- scope;
- delivered contract changes;
- evidence executed;
- claim boundary;
- intentionally deferred work.

It SHOULD NOT duplicate every implementation detail visible in the diff.

### 14.3 Issues

An issue SHOULD own a decision, defect, requirement, or unresolved question. It SHOULD NOT become a second architecture document.

### 14.4 Decision records

A dedicated decision record is justified when the rejected alternatives and rationale are likely to matter after the implementation context disappears. Trivial or reversible choices SHOULD remain in normal review history.

---

## 15. Generated artifacts and machine-readable state

If a fact is naturally machine-readable, the machine-readable source SHOULD be authoritative and human-readable views SHOULD be generated from it.

Suitable examples:

- capability registries;
- feature matrices;
- compatibility tables;
- schema catalogs;
- milestone state;
- test inventories;
- dependency manifests;
- build metadata.

Generated files MUST identify their authority or generation path. A generated view MUST NOT be edited as if it were an independent source.

---

## 16. Multi-language and multi-runtime projects

EIGIIB is language-neutral.

A mixed-language project MUST make explicit only the semantics that cross language/runtime boundaries. Internal idioms SHOULD remain native to each language.

Examples of boundary facts that often require explicit treatment:

- ownership transfer between C and Rust/C++/Python;
- exception/error translation;
- integer width and endianness;
- string encoding;
- allocator ownership;
- ABI stability;
- FFI callback lifetime;
- thread/runtime entry rules;
- serialization contracts.

A project SHOULD NOT force one language's internal documentation style onto another language when equivalent structural guarantees already exist.

---

## 17. Domain profiles

The core standard applies unchanged; profiles identify facts that commonly cross boundaries in particular project types.

### 17.1 Library / SDK

Make explicit: API stability, ownership, errors, thread safety, compatibility, feature gates.  
Keep implicit: routine implementation algorithms and private helper decomposition.

### 17.2 CLI tool

Make explicit: command contract, exit semantics, destructive operations, config precedence, reproducibility, output format stability.  
Keep implicit: parser plumbing and routine formatting code.

### 17.3 Network service

Make explicit: protocol, authentication/authorization, idempotence, retries, timeouts, partial failure, durability, rate/resource limits.  
Keep implicit: ordinary handler composition.

### 17.4 Embedded / kernel / low-level systems

Make explicit: memory ownership, interrupt/concurrency context, ordering, ABI/UAPI, hardware assumptions, failure containment, privilege boundaries.  
Keep implicit: standard register-access or language idioms when unambiguous locally.

### 17.5 Data / ML / scientific software

Make explicit: dataset identity, preprocessing contract, randomness/seeds, numerical precision, model/checkpoint version, evaluation protocol, reproducibility boundary.  
Keep implicit: routine tensor/dataframe mechanics already expressed by code and types.

### 17.6 Infrastructure / deployment

Make explicit: desired state, privilege, credentials boundary, rollback, idempotence, environment scope, persistence, destructive actions.  
Keep implicit: generated provider boilerplate and routine resource syntax.

### 17.7 Prototype / research project

Make explicit: which results are exploratory, which are implemented, which were actually executed, and what has not been validated.  
Keep implicit: temporary mechanics that are not promises and carry no handoff value.

---

## 18. Anti-patterns

The following are EIGIIB violations unless a documented boundary-specific reason exists.

### 18.1 Narrated code

```c
/* Increment i by one. */
i++;
```

The comment adds no information.

### 18.2 Duplicate authority

The same timeout default appears independently in code, README, deployment guide, and wiki.

Conforming alternative: one authoritative default, generated help/config output, prose explaining policy only.

### 18.3 Status inflation

A roadmap says a feature is “supported” because implementation files exist, despite no executed platform evidence.

Conforming alternative: separate realization from evidence.

### 18.4 Boolean collapse

An unavailable integration test is recorded as failed, or worse, as passed because it was skipped.

Conforming alternative: represent `unavailable` or `not-evaluated`.

### 18.5 Premature abstraction

Private helpers are exported to make component boundaries “more explicit,” creating an ABI that no consumer needs.

Conforming alternative: keep private cohesion; expose only real contracts.

### 18.6 Exhaustive prose inventory

A document copies every schema field and command flag even though authoritative machine-readable definitions already exist.

Conforming alternative: document semantics and generate reference material.

### 18.7 Hidden irreversible choice

A migration destroys rollback compatibility but the only indication is the implementation diff.

Conforming alternative: explicit rationale, migration boundary, and recovery consequence.

### 18.8 Optimistic ambiguity

“Portable,” “secure,” “atomic,” “verified,” or “compatible” appears without stating the exact dimension and evidence boundary.

Conforming alternative: qualify the claim.

---

## 19. Conformance model

### 19.1 Conformance levels

A project MAY report one of three EIGIIB conformance levels.

#### `EIGIIB-C1 — Structural`

Required:

- one authority per durable fact;
- public contracts explicit;
- routine mechanics not narrated;
- duplicate manual normative statements removed;
- project scope and exclusions explicit.

#### `EIGIIB-C2 — Evidential`

Includes C1, plus:

- realization and evidence states separated;
- unknown/unavailable states preserved;
- material claims carry boundaries;
- executable evidence records exist for validation claims;
- generated facts are generated where practical.

#### `EIGIIB-C3 — Operational`

Includes C2, plus:

- trust and failure boundaries explicit;
- rollback/durability/retry semantics explicit where applicable;
- machine-readable project state available for critical capabilities;
- conformance checks integrated into CI or equivalent review gates;
- stale/duplicate documentation is mechanically detectable where practical.

A project MUST NOT claim a level when a required item is merely planned.

### 19.2 Conformance result

An audit result SHOULD use:

```text
conformant
conformant-with-documented-deviations
non-conformant
not-evaluated
```

A skipped audit is `not-evaluated`, not `conformant`.

---

## 20. Audit procedure

A reviewer can audit any project with the following sequence.

### Step 1 — Identify boundaries

List public interfaces, component boundaries, trust boundaries, persistence boundaries, runtime boundaries, repository boundaries, and operational handoffs.

### Step 2 — Identify durable facts

For each boundary, list the facts another party must rely on.

### Step 3 — Resolve authority

For each fact, identify exactly one authority. Flag facts with zero owners or multiple manual owners.

### Step 4 — Check carrier strength

Ask whether prose can be replaced by a stronger type, name, schema, test, generated artifact, or module boundary.

### Step 5 — Check rationale

Find non-obvious hazards, irreversible choices, compatibility constraints, and rejected fallbacks. Ensure the reason survives independently of implementation details.

### Step 6 — Check evidence typing

For every material claim, identify realization state, evidence state, and environment. Flag unqualified promotion.

### Step 7 — Check unknowns

Ensure unavailable, skipped, not-evaluated, and not-applicable states are preserved.

### Step 8 — Check duplication

Find repeated defaults, tables, capability lists, schemas, test counts, and state descriptions. Replace copies with references or generation.

### Step 9 — Check claim boundaries

Search for broad words such as “supported,” “secure,” “portable,” “atomic,” “compatible,” “verified,” “tested,” and “complete.” Require exact scope.

### Step 10 — Record only actionable deviations

An EIGIIB audit SHOULD NOT create exhaustive prose about already conformant details. It records only:

- missing authority;
- duplicate authority;
- insufficient boundary contract;
- unjustified explicitness;
- missing rationale;
- evidence/claim mismatch;
- unrepresented unknown state;
- stale generated/manual duplication.

---

## 21. CI and tooling recommendations

Projects targeting C2 or C3 SHOULD automate high-value EIGIIB checks rather than adding reviewer checklists without enforcement.

Useful checks include:

- documentation links resolve;
- schemas validate generated JSON;
- generated files are clean after regeneration;
- capability records match compiled features;
- public headers and reference docs are synchronized by generation;
- no forbidden manual tables diverge from source data;
- milestone state vocabulary is schema-validated;
- claim-bearing validation records identify revision and environment;
- unsupported features fail closed rather than silently degrade.

Automation SHOULD verify boundaries, not enforce cosmetic verbosity metrics.

Line counts, comment percentages, document counts, and comment-to-code ratios MUST NOT be used as EIGIIB quality targets.

---

## 22. Adoption procedure for an existing project

A project adopting EIGIIB SHOULD proceed in this order:

1. **Do not add documentation first.** Inventory existing authorities and duplicates.
2. Establish a short project charter containing active scope, excluded scope, and claim boundary.
3. Identify authoritative interface/schema/configuration sources.
4. Replace duplicated facts with links or generated views.
5. Introduce typed project/evidence states.
6. Add rationale only for non-obvious, hazardous, or irreversible choices.
7. Make tests enforce the most important contracts.
8. Add new documents only where a real ownership boundary remains unresolved.
9. Run the conformance audit in §20.
10. Record deviations, not cosmetic documentation debt.

Adoption is complete when the project is easier to navigate **because less text owns more precise meaning**.

---

## 23. Repository layout guidance

EIGIIB does not prescribe a universal directory tree. A small project SHOULD remain small.

A larger project MAY use a layout such as:

```text
docs/
  EIGIIB.md                 # project adoption/profile, not a copy of this standard
  ARCHITECTURE.md           # responsibility boundaries
  SECURITY-MODEL.md         # trust and residual obligations
  TEST-AND-EVIDENCE.md      # interpretation of evidence
schemas/
  project-state.schema.json
PROJECT-STATUS.json         # machine-readable state authority
README.md                   # entry point, not a duplicate manual
```

The important property is ownership, not filenames.

When this standard lives in a dedicated repository, downstream projects SHOULD reference its version and keep only project-specific adoption rules locally.

---

## 24. Project-local EIGIIB profile

A project MAY define a compact profile containing only deviations and local ownership decisions.

Recommended form:

```yaml
standard: EIGIIB-1.0
conformance_target: EIGIIB-C2
authorities:
  scope: docs/PROGRAM-CHARTER.md
  architecture: docs/ARCHITECTURE.md
  security: docs/SECURITY-MODEL.md
  evidence: docs/TEST-AND-EVIDENCE.md
  capability_state: BUILD-CAPABILITIES.json
local_rules:
  - Public compatibility promises require platform-specific executed evidence.
deviations: []
```

A local profile MUST NOT copy the standard itself.

---

## 25. Compact review checklist

A change is EIGIIB-aligned when the reviewer can answer **yes** to all applicable questions:

- Is every new public or cross-boundary behavior explicit?
- Is routine local behavior carried by code/types/names rather than narration?
- Is any non-obvious hazard or irreversible choice justified by rationale?
- Does each new durable fact have exactly one authority?
- Is duplicated information generated or referenced instead of copied?
- Are realization and evidence kept separate?
- Are unknown, unavailable, and not-evaluated states preserved?
- Are broad claims qualified by environment and scope?
- Does the change avoid accidental new API/ABI/configuration surface?
- Would deleting any new prose lose real information rather than only repetition?

If the final answer to the last question is “no,” that prose SHOULD be deleted.

---

## 26. Canonical EIGIIB invariant set

The standard can be summarized by the following invariant set:

```text
I1  Every material boundary has an explicit contract.
I2  Every durable fact has exactly one normative owner.
I3  Routine local mechanics are represented structurally before textually.
I4  Rationale is explicit where future removal could reintroduce material risk.
I5  Generated facts are not manually duplicated.
I6  Claims never exceed their executed or otherwise valid evidence.
I7  Unknown, unavailable and not-applicable states remain distinguishable.
I8  Optional capability loss is explicit and does not silently change semantics.
I9  Public surface is created only for real consumers and real contracts.
I10 Documentation growth requires a new information-ownership boundary.
```

A project that preserves these invariants is EIGIIB-aligned even when its implementation language, repository layout, toolchain, and documentation volume differ radically from another conforming project.

---

## 27. Final rule

When deciding whether to add a statement, comment, document, option, abstraction, status, table, or interface, ask:

> **What ambiguity or boundary failure does this explicit artifact prevent that a stronger implicit carrier cannot prevent?**

If the answer is precise, make the fact explicit at its authority.

If the answer is only “for completeness,” prefer structure, generation, reference, or deletion.

That is EIGIIB.
