# EIGIIB-E1 — Typed Evidence, Claim Boundary and Conformance Model

**Status:** Normative extension, draft 1.0  
**Extends:** EIGIIB 1.0 §§4.5–4.6, 6, 12, 19–21, 24–26  
**Rule:** This extension refines claim/evidence semantics. It does not replace the EIGIIB core rule or duplicate its general documentation requirements.

---

## 1. Purpose

EIGIIB-E1 defines a typed model for engineering claims, evidence, scope, uncertainty, contradiction, and conformance decisions.

The extension exists to prevent four recurrent category errors:

1. treating a detailed specification as implementation evidence;
2. treating one successful execution as universal support;
3. collapsing unknown, unavailable, partial, and contradictory states into Boolean success/failure;
4. ranking incomparable forms of evidence on one optimistic scalar scale.

E1 therefore makes **claim satisfaction a relation**, not a status label copied by convention.

A conforming implementation of E1 MUST preserve enough information to answer:

- what proposition is being asserted;
- about which subject and revision;
- within which scope and environment;
- under which policy the proposition may be accepted;
- which evidence supports or contradicts it;
- which dimensions remain uncovered;
- which authority owns the claim and evidence records.

---

## 2. Normative terms

In addition to EIGIIB 1.0 terminology:

- **subject**: the feature, component, artifact, interface, release, service, dataset, or repository state to which a claim applies;
- **predicate**: the property asserted about a subject;
- **scope**: the set of contexts for which a claim is intended to hold;
- **coverage**: the subset of claim scope actually addressed by evidence;
- **evidence record**: an immutable description of one executed, observed, derived, or formally established result;
- **evidence policy**: a declared rule specifying what kinds and combinations of evidence are sufficient for a class of claim;
- **satisfaction**: the relation by which an evidence set establishes a claim under a policy;
- **contradiction**: admissible evidence whose result is incompatible with a claim in an overlapping scope;
- **promotion**: replacement of a claim state or scope by a stronger one;
- **projection**: a deliberately narrower claim derived from evidence whose coverage does not justify the broader original claim;
- **manual gate**: a conformance obligation requiring human or domain-specific judgment and therefore not safely decidable by generic repository automation.

---

## 3. Typed state model

### 3.1 Feature state

A durable project feature SHOULD be represented as:

```text
FeatureState = (
    disposition,
    realization,
    claims,
    evidence,
    context
)
```

where the axes are independent.

### 3.2 Disposition

The canonical E1 disposition vocabulary is:

```text
active
deferred
suspended
rejected
not-applicable
```

A project MAY add values, but MUST NOT use a disposition word to imply implementation or validation.

Examples:

```text
active + specified + not-evaluated
active + implemented + integration-tested
suspended + implemented + platform-tested
rejected + idea + not-evaluated
```

All four combinations are semantically possible.

### 3.3 Realization

The canonical realization vocabulary is:

```text
idea
adopted
specified
implemented
integrated
released
```

The realization axis describes what artifact or behavior exists. It MUST NOT state how well that artifact has been validated.

### 3.4 Evidence is not a scalar level

EIGIIB 1.0 lists common evidence labels for practical reporting. E1 clarifies that these labels MUST NOT be interpreted as a universal total order.

For example:

- `unit-test` and `static-analysis` cover different defect classes;
- `formal-proof` may establish a mathematical property without establishing toolchain portability;
- `integration-test` may establish interoperability without proving absence of undefined behavior;
- `operational-observation` may establish deployment behavior without identifying all boundary conditions.

Therefore E1 represents evidence as a **set of typed records** rather than one monotonically increasing number.

---

## 4. Claim object

### 4.1 Canonical form

A material claim `c` is modeled as:

```text
c = (id, subject, predicate, revision, scope, authority, policy, state)
```

A claim MUST have a stable identifier within its authority domain.

### 4.2 Required fields

A machine-readable material claim MUST identify:

- `id` — stable claim identifier;
- `subject` — claim target;
- `predicate` — asserted property;
- `revision` — source/artifact/release revision when applicable;
- `scope` — explicit domain of validity;
- `authority` — normative owner of the claim;
- `policy` — evidence policy used for acceptance, or `manual` when no generic policy is sound;
- `state` — current claim decision state.

### 4.3 Claim decision states

The canonical decision states are:

```text
established
partially-established
contested
refuted
not-evaluated
unavailable
not-applicable
```

Their meanings are normative:

- `established`: the declared policy is satisfied for the entire declared scope and there is no unresolved admissible contradiction;
- `partially-established`: admissible supporting evidence exists, but some declared scope or mandatory evidence dimension is uncovered;
- `contested`: admissible supporting and contradicting evidence overlap materially, or two required authorities disagree;
- `refuted`: admissible contradicting evidence establishes failure in a scope that invalidates the claim as written;
- `not-evaluated`: no acceptance decision has been executed;
- `unavailable`: evaluation requires an input, artifact, environment, dependency, service, permission, or capability that is unavailable;
- `not-applicable`: the predicate does not apply to the subject or scope.

A project MUST NOT encode `partially-established`, `contested`, `not-evaluated`, or `unavailable` as `false` merely to simplify a dashboard.

### 4.4 Claim strength

Claim strength is determined by semantic breadth, not adjectives.

For two claims with the same subject and predicate, `c1` is no stronger than `c2` when:

```text
scope(c1) ⊆ scope(c2)
```

and every qualification required by `c1` is at least as restrictive as the corresponding qualification in `c2`.

Words such as `complete`, `portable`, `secure`, `verified`, `supported`, `atomic`, or `compatible` MUST NOT substitute for an explicit scope.

---

## 5. Scope model

### 5.1 Scope is structured

Claim scope SHOULD be represented as a finite map of dimensions to values or sets:

```json
{
  "os": ["linux"],
  "arch": ["x86_64"],
  "compiler": ["gcc-14", "clang-18"],
  "mode": ["release", "asan-ubsan"]
}
```

Typical dimensions include:

- operating system;
- architecture;
- compiler or interpreter;
- runtime version;
- protocol version;
- dependency/provider;
- hardware;
- deployment class;
- dataset;
- configuration/profile;
- trust or privilege context;
- temporal validity window.

### 5.2 Coverage relation

Let `S_e` be evidence scope and `S_c` claim scope. Evidence can cover a claim dimension only when the declared matching rule establishes:

```text
S_c ⊆ S_e
```

For ordinary finite enumerations, coverage is set inclusion.

A project MAY define stronger domain-specific coverage rules, but those rules MUST be explicit and authoritative.

### 5.3 Wildcards

A wildcard such as `*`, `any`, or omitted scope dimension MUST NOT automatically mean universal coverage.

A wildcard is valid only when an evidence policy defines its semantics. Otherwise it means `unspecified`, which cannot establish a universal claim.

### 5.4 Projection rule

If evidence covers only a subset `S_e` of a broader claim `S_c`, the safe result is a projection:

```text
c' = c restricted to (S_c ∩ S_e)
```

The original broader claim remains `partially-established`, `not-evaluated`, or `refuted` as appropriate.

E1 prefers a narrower true claim over a broader optimistic claim.

---

## 6. Evidence object

### 6.1 Canonical form

An evidence record `e` is modeled as:

```text
e = (
    id,
    subject,
    revision,
    kind,
    procedure,
    result,
    scope,
    provenance,
    artifacts,
    observed_at
)
```

### 6.2 Evidence kinds

The following registry is canonical but extensible:

```text
inspection
compile
unit-test
property-test
fuzz-test
static-analysis
dynamic-analysis
integration-test
interoperability-test
platform-test
benchmark
formal-proof
model-check
reproducibility-replay
operational-observation
external-attestation
manual-review
```

Projects MAY define additional kinds. Custom kinds MUST document their semantics before they are used in an acceptance policy.

### 6.3 Evidence result

An evidence result MUST be one of:

```text
pass
fail
inconclusive
not-run
unavailable
not-applicable
```

A timeout, missing dependency, skipped platform, inaccessible service, or parser failure MUST NOT be silently converted to `pass` or `fail` unless the evidence policy explicitly defines that failure mode as the property being tested.

### 6.4 Evidence immutability

Executed evidence records SHOULD be append-only.

If an observed result is corrected because the record itself was malformed, the project SHOULD retain provenance linking the superseding record to the superseded one.

A later successful run MUST NOT erase a prior failure when that failure is relevant to the current claim boundary or regression history.

### 6.5 Provenance

Evidence provenance SHOULD identify enough information to replay or audit the result when practical:

- revision or artifact digest;
- command or procedure identifier;
- toolchain/runtime version;
- environment;
- input fixture or dataset identity;
- CI run, log, report, proof object, or external record;
- timestamp when temporal validity matters.

E1 does not require retaining every transient log forever. It requires retaining the facts needed to support the claim.

---

## 7. Evidence policies

### 7.1 Policy object

An evidence policy `P` defines sufficiency for a class of claims.

A policy SHOULD declare:

```text
P = (
    id,
    applicable_predicates,
    required_kinds,
    allowed_alternatives,
    scope_rule,
    contradiction_rule,
    freshness_rule,
    manual_gates
)
```

### 7.2 No universal evidence ladder

A generic project MUST NOT define:

```text
compile < unit-test < integration-test < platform-test < formal-proof
```

as a universal implication chain.

Only policy-declared implication is valid.

Example:

```text
policy: parser-memory-safety
requires:
  - dynamic-analysis
  - fuzz-test
```

does not become satisfied merely because an integration test passed.

### 7.3 Alternative evidence sets

A policy MAY accept alternative evidence sets.

Example:

```text
requires_any:
  - [formal-proof, proof-kernel-check]
  - [property-test, exhaustive-finite-enumeration]
```

The alternatives MUST be intentional, not inferred from convenient available data.

### 7.4 Manual policy

Some claims are not safely decidable by a generic checker, including many usability, maintainability, threat-model completeness, or domain-correctness claims.

Such a claim MUST use a `manual` or domain-specific policy rather than pretending machine decidability.

---

## 8. Satisfaction relation

### 8.1 Definition

Let `E` be a set of evidence records and `P` the policy attached to claim `c`.

Write:

```text
E ⊨P c
```

when all of the following hold:

1. every required evidence dimension of `P` is satisfied by an admissible record or accepted alternative set;
2. the evidence subject and revision correspond to the claim subject and revision under the policy's identity rule;
3. evidence scope covers claim scope under the policy's scope rule;
4. required evidence results are `pass`;
5. freshness requirements, when any, are satisfied;
6. every manual gate is completed by its declared authority;
7. no unresolved admissible contradiction overlaps the claim scope.

Only then may the claim be `established`.

### 8.2 Sound promotion rule

A transition to `established` is permitted only if:

```text
E ⊨P c
```

A transition to a broader scope `c+` is permitted only if:

```text
E ⊨P c+
```

Evidence for a narrower scope cannot be reused to silently broaden the claim.

### 8.3 Partial satisfaction

If some but not all mandatory policy dimensions are covered, the checker or reviewer SHOULD compute the maximal safe projection and set the broader claim to `partially-established`.

### 8.4 Inconclusive evidence

`inconclusive`, `not-run`, and `unavailable` evidence records do not satisfy positive requirements.

They remain informative and MAY explain why a claim is `not-evaluated`, `unavailable`, or `partially-established`.

---

## 9. Contradiction model

### 9.1 Contradicting evidence

Evidence `e` contradicts claim `c` when:

- `e` is admissible under the claim's policy or its contradiction rule;
- `e.result = fail` or otherwise establishes the negation of the predicate;
- `scope(e)` overlaps materially with `scope(c)`.

### 9.2 Conflict preservation

A project MUST preserve unresolved contradiction as a first-class state.

A later pass does not automatically delete an earlier fail. The project must determine whether:

- the revision changed;
- the environment differs;
- the failure was invalid evidence;
- the defect was fixed;
- the claim scope must be narrowed;
- the claim is genuinely contested.

### 9.3 Revision distinction

Evidence attached to revision `r1` does not establish or refute revision `r2` unless an explicit identity or inheritance rule permits it.

This prevents stale validation from silently following code changes.

---

## 10. Claim boundaries

### 10.1 Boundary record

A material claim SHOULD carry a boundary object with applicable dimensions such as:

```json
{
  "scope": {
    "os": ["linux"],
    "arch": ["x86_64"]
  },
  "excludes": [
    "native-macos-validation",
    "manifest-authenticity"
  ],
  "assumptions": [
    "trusted-local-configuration"
  ]
}
```

### 10.2 Exclusions are semantic

An exclusion is not a disclaimer appended for legal completeness. It identifies a nearby proposition that the current evidence does not establish.

A claim boundary SHOULD list exclusions when a reasonable reader could otherwise infer them.

### 10.3 Security distinctions

Where applicable, boundaries MUST preserve distinctions including:

```text
integrity != authenticity
authentication != authorization
publication != durability
availability != permission
parsing != validation
validation != trust
transport encryption != endpoint identity
local test success != cross-platform support
```

---

## 11. Conformance as a typed decision

### 11.1 Conformance target

A conformance evaluation has a target:

```text
Target = (standard_version, extension_set, level, revision, scope)
```

The extension set MUST be explicit. A project claiming E1 semantics SHOULD report an identifier such as:

```text
EIGIIB-1.0+E1-1.0
```

### 11.2 Conformance obligations

Each target level expands into obligations. Each obligation has:

```text
Obligation = (
    id,
    class,
    decidability,
    authority,
    evidence_policy
)
```

`decidability` is one of:

```text
mechanical
manual
domain-specific
```

A generic checker MUST NOT report a manual obligation as mechanically proven.

### 11.3 Conformance decision states

E1 refines the core conformance result into:

```text
conformant
conformant-with-documented-deviations
non-conformant
partially-evaluated
not-evaluated
unavailable
```

`partially-evaluated` is required when only a strict subset of mandatory obligations has been evaluated.

### 11.4 Deviations

A documented deviation MUST identify:

- affected obligation;
- reason;
- scope;
- authority accepting it;
- compensating control, if any;
- expiry/review condition, if any.

A deviation is not evidence that the obligation was satisfied.

### 11.5 Mechanical conformance is not total conformance

A repository checker may establish:

```text
mechanical_obligations = conformant
```

while overall conformance remains:

```text
partially-evaluated
```

because manual or domain-specific gates remain.

This distinction is mandatory for E2 and later automation.

---

## 12. Transition system

### 12.1 State transitions

A claim transition is:

```text
(c, E, P) -> (c', E', P')
```

A transition is admissible only when its justification is explicit and replayable from authorities.

### 12.2 Permitted promotion classes

Typical permitted transitions include:

```text
not-evaluated -> partially-established
not-evaluated -> established
unavailable -> not-evaluated
partially-established -> established
established -> contested
contested -> established
contested -> refuted
```

No transition is intrinsically monotone merely because its label appears later in this list.

### 12.3 Demotion

Claims MUST be demotable when:

- contradicting evidence appears;
- evidence expires;
- revision identity changes;
- required evidence is invalidated;
- scope broadens beyond coverage;
- an authority is withdrawn.

A conformance system that can promote but cannot demote is non-conformant.

### 12.4 Termination requirement for automated resolution

If a tool automatically rewrites or resolves claim states, its transition rules MUST terminate for finite repository input.

A sufficient implementation pattern is to evaluate a fixed finite set of claims against immutable evidence without recursive self-promotion.

Tools that use iterative rules MUST define a well-founded measure or otherwise demonstrate termination.

### 12.5 Determinism and confluence

If multiple evaluation orders are permitted, the tool MUST either:

- produce the same final normalized result for all orders; or
- make evaluation order part of the explicit policy.

A checker MUST NOT depend on filesystem enumeration order, JSON object insertion order, or nondeterministic traversal to decide conformance.

---

## 13. Machine-readable registry rules

### 13.1 Identity

Claim, evidence, policy, and authority identifiers MUST be unique within their registry namespace.

### 13.2 References

Machine-readable cross-references MUST resolve exactly or be explicitly external.

A dangling evidence reference is an error, not `not-evaluated`.

### 13.3 Path safety

Repository-relative artifact references MUST be normalized, non-absolute paths that do not escape the repository root.

### 13.4 Hashes

When a claim depends on byte identity, the evidence record SHOULD include a cryptographic digest and algorithm name.

A digest establishes identity/integrity relative to the referenced object; it does not establish authorship or authenticity unless an explicit authenticity mechanism is also present.

---

## 14. Evidence-policy examples

### 14.1 Compilation claim

Claim:

```text
subject: library revision abc123
predicate: compiles without warnings promoted to errors
scope: gcc-14 / linux-x86_64 / release
```

Policy:

```text
required kind: compile
required result: pass
exact revision: true
scope coverage: exact-or-superset
```

A Clang build does not satisfy the GCC claim unless the claim is rewritten to include both and evidence exists for both.

### 14.2 Portability claim

Claim:

```text
predicate: native publication adapter supported
scope: linux + macos + freebsd
```

Evidence only covers Linux.

Required result:

```text
partially-established
```

with the safe projection:

```text
supported on linux under the tested environment
```

### 14.3 Formal property

Claim:

```text
predicate: state transition preserves invariant I
```

A formal proof may satisfy the semantic invariant policy while leaving compiler, ABI, performance, deployment, and platform claims unevaluated.

### 14.4 Security claim

Claim:

```text
predicate: remote peer identity is authenticated
```

Encrypted transport evidence without endpoint identity validation is insufficient. The claim remains unevaluated or refuted according to observed behavior.

---

## 15. Conformance requirements for E1

A project claiming **EIGIIB-E1 conformance** MUST:

1. represent material claims with explicit subject, predicate, revision/scope where applicable, authority, and state;
2. represent evidence as typed records rather than a single optimistic level;
3. preserve `not-evaluated`, `unavailable`, `partially-established`, `contested`, and `not-applicable` when they occur;
4. define evidence sufficiency by policy rather than by undocumented intuition;
5. prevent claim scope from exceeding evidence coverage;
6. retain material contradictory evidence until explicitly resolved;
7. separate machine-decidable conformance obligations from manual/domain-specific gates;
8. permit demotion when evidence or assumptions cease to support a claim;
9. make automated evaluation deterministic for fixed input;
10. avoid exposing this typed model through redundant prose when schemas and generated reports can carry the same facts.

---

## 16. Minimal E1 invariant set

```text
E1-I1  Claim state is not realization state.
E1-I2  Evidence is a typed set, not a universal scalar ladder.
E1-I3  Establishment requires policy satisfaction over the declared scope.
E1-I4  Narrow evidence yields a narrow claim, not optimistic generalization.
E1-I5  Unknown, unavailable, partial and contradictory states remain distinct.
E1-I6  Contradictory evidence is preserved until explicitly resolved.
E1-I7  Revision and environment are part of evidence meaning.
E1-I8  Automated conformance proves only mechanically decidable obligations.
E1-I9  Promotion and demotion are both supported.
E1-I10 Fixed input yields deterministic normalized decisions.
```

---

## 17. Relationship to later extensions

EIGIIB-E2 MAY automate the mechanically decidable subset of E1.

E2 MUST NOT:

- infer semantic equivalence from prose similarity;
- claim manual obligations are proven by repository shape;
- use comment density, document count, line count, or verbosity as quality metrics;
- promote a repository to full EIGIIB conformance merely because its machine-readable files validate.

E1 is the semantic contract. E2 is an implementation of a safe subset of that contract.
