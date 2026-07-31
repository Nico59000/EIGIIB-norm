# EIGIIB-E3 — Reproducible Evidence Provenance and Artifact Identity

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0, EIGIIB-E1 1.0, and EIGIIB-E2 1.0  
**Reference checker:** `tools/eigiib_provenance_check.py`

---

## 1. Purpose

EIGIIB-E3 defines a portable model for binding engineering evidence to exact artifacts, production events, replay attempts, and reproducibility claims.

E1 establishes that evidence must be typed and scoped. E2 establishes which repository invariants may be checked mechanically. E3 adds the missing identity layer required to answer:

- which exact bytes or external object did an evidence record concern;
- which exact inputs and procedure produced an artifact;
- which environment facts are material to replay;
- whether a later replay reproduced the expected outputs;
- under which equivalence relation a replay was judged;
- which parts of a provenance statement are mechanically verifiable;
- which origin or authenticity assertions remain outside digest identity.

E3 is deliberately narrower than a general software-supply-chain framework. It does not require a transparency log, public-key infrastructure, package ecosystem, build service, or network authority. Those may be layered on top.

The central rule is:

```text
identity != provenance != reproducibility != authenticity
```

A conforming project MUST NOT silently substitute one for another.

---

## 2. Normative terms

In addition to EIGIIB and E1 terminology:

- **artifact**: a finite object used or produced by engineering work, such as a source file, archive, executable, proof object, dataset, report, generated manifest, or external immutable object;
- **artifact instance**: one concretely identified occurrence or byte representation of an artifact;
- **byte identity**: identity established for a finite byte string by an accepted digest record plus size under the declared cryptographic assumptions;
- **logical role**: the semantic slot occupied by an artifact in a procedure, such as `source-tree`, `compiler`, `input-dataset`, or `result`;
- **procedure**: the declared transformation, check, observation, or proof-validation process associated with an event;
- **production event**: an observed event that consumed declared inputs under a declared procedure/environment and produced declared outputs;
- **provenance**: the recorded relation between an artifact and the event(s), inputs, procedure, environment, and revision associated with its production or acquisition;
- **replay**: a later execution intended to reproduce or re-evaluate a recorded production event;
- **equivalence policy**: the authoritative relation under which expected and replayed outputs may be considered equivalent;
- **exact replay**: a replay whose output artifacts satisfy byte identity with the expected outputs;
- **canonical replay**: a replay whose outputs differ at the byte level but become equal under a declared deterministic canonicalization policy;
- **semantic replay**: a replay whose outputs satisfy a declared domain-specific equivalence relation without claiming byte equality;
- **independence claim**: an assertion that a replay was executed by a meaningfully independent producer, environment, operator, or implementation;
- **material input**: an input whose change may affect the property or output being claimed;
- **provenance closure**: the set of artifact and event identities needed to audit or replay a result to the boundary selected by project policy.

---

## 3. Separation theorem for E3 claims

### 3.1 Four independent questions

For an artifact `a`, the following are separate propositions:

```text
I(a): the artifact instance is byte-identified
P(a): the artifact has recorded provenance
R(a): the production relation has been replayed successfully
A(a): the asserted producer/origin is authenticated
```

No generic implication is permitted between them except where an explicit policy provides one.

In particular:

```text
I(a) does not imply P(a)
P(a) does not imply R(a)
R(a) does not imply A(a)
A(a) does not imply byte reproducibility
```

A cryptographic digest is therefore an identity primitive, not an origin statement.

### 3.2 E1 integration

An E1 evidence record MAY be strengthened by E3 bindings. E3 does not replace the E1 evidence result or policy.

The E1 question remains:

```text
Does this evidence satisfy the claim policy?
```

The E3 question is:

```text
Which exact artifacts and production/replay events does that evidence refer to?
```

A project MUST NOT mark an E1 claim `established` merely because all referenced artifacts have valid E3 digests.

---

## 4. Artifact identity

### 4.1 Canonical artifact record

An E3 artifact record is modeled as:

```text
Artifact = (
    id,
    role,
    kind,
    locator,
    size,
    digests,
    revision,
    availability,
    identity_state
)
```

`locator` MAY be repository-local, external, generated, or intentionally absent.

### 4.2 Stable artifact identifiers

`artifact.id` is a stable registry identifier. It is not itself proof of byte identity.

Changing the bytes represented by an artifact record MUST NOT preserve an artifact ID whose documented semantics mean an immutable instance. A project MAY instead define a stable logical subject separately from immutable artifact instances.

Good:

```text
logical subject: reference-checker
artifact id: reference-checker@sha256:...
```

Also conformant:

```text
artifact id: checker-source-2026-07-31-a
digest: ...
```

provided the registry treats the artifact ID as immutable.

### 4.3 Byte identity record

For a finite local byte artifact, the canonical E3-1.0 byte identity consists of:

```text
algorithm = sha256
digest = 64 lowercase hexadecimal characters
size = exact byte count
```

E3-1.0 requires SHA-256 support in the reference checker because it is widely available in the Python standard library.

Projects MAY record additional digest algorithms. A checker MUST NOT treat an unsupported algorithm as verified.

The operational identity tuple is:

```text
B(a) = (algorithm, digest, size)
```

Two artifact records may be treated as byte-identical under E3-1.0 when the accepted identity policy establishes equality of the required tuples and the cryptographic assumptions of that policy are accepted.

E3 deliberately does not claim mathematical injectivity of a hash function.

### 4.4 Local verification

When an artifact has a repository-local path, an E3 checker MUST recompute:

- byte count;
- every digest algorithm it claims to support.

A mismatch is an error.

A registry MUST NOT be allowed to establish the identity of its own bytes by storing its own digest as a normative self-claim. Self-referential identity requires an external envelope or parent artifact and is outside E3-1.0.

### 4.5 External artifacts

An external artifact MAY be recorded without a local path.

Such a record MUST distinguish:

```text
declared
verified
unavailable
```

A generic offline repository checker may validate the syntax of a declared external digest, but MUST NOT report the external artifact as locally verified unless the bytes are actually available to the checker.

### 4.6 Directory and tree identities

A filesystem directory is not a byte string.

A project that needs directory identity MUST define an authoritative serialization or tree-digest procedure specifying at least:

- path normalization;
- ordering;
- file types included;
- symlink treatment;
- metadata included or excluded;
- byte encoding;
- digest construction.

The resulting tree digest identifies the declared serialization/model, not an abstract directory independent of that policy.

---

## 5. Procedure identity

### 5.1 Procedure object

A procedure is modeled as:

```text
Procedure = (
    id,
    authority,
    implementation_artifacts,
    interface,
    determinism,
    material_environment,
    equivalence_policy
)
```

A procedure ID MUST be stable within its authority domain.

### 5.2 Commands are not sufficient identity

A shell command or CLI string alone is generally insufficient procedure identity because behavior may depend on:

- executable bytes;
- imported modules;
- compiler/runtime version;
- configuration;
- environment variables;
- locale;
- working directory;
- dependency versions;
- hardware behavior;
- network or clock state.

A procedure MAY record a command for replay convenience, but the command MUST NOT silently stand in for these material dependencies.

### 5.3 Materiality boundary

E3 does not require capturing every process property.

A procedure MUST identify the environment dimensions believed material to its output or evidential meaning. Unknown materiality MUST be represented as an uncertainty or manual boundary rather than silently treated as irrelevant.

This is an application of minimal sufficient explicitness: capture what can change the claim, not an indiscriminate dump of the host.

### 5.4 Determinism declaration

The canonical values are:

```text
deterministic
conditionally-deterministic
nondeterministic
unknown
```

A declaration of `deterministic` is a claim about the procedure contract. It is not established merely by one identical replay.

---

## 6. Environment capture

### 6.1 Structured environment

An environment record SHOULD be structured:

```text
Environment = (
    id,
    platform,
    architecture,
    runtime,
    toolchain,
    dependencies,
    configuration,
    locale,
    time_basis,
    hardware,
    notes
)
```

Only material fields are required.

### 6.2 Environment identity versus description

An environment description is not necessarily an environment identity.

Where a toolchain, dependency bundle, container image, VM image, or lockfile is available as a finite artifact, projects SHOULD bind the environment field to its artifact identity rather than restating versions manually.

### 6.3 Secrets and sensitive values

Secrets MUST NOT be captured merely for reproducibility.

A procedure SHOULD record:

- the fact that a secret class was required;
- the authority/provider category;
- any non-secret version or policy identifier relevant to behavior.

It MUST NOT record secret bytes in a public provenance registry.

---

## 7. Production events

### 7.1 Canonical event

A production event `d` is modeled as:

```text
d = (
    id,
    subject,
    source_revision,
    procedure,
    environment,
    inputs,
    outputs,
    result,
    observed_at,
    executor
)
```

### 7.2 Input and output binding

Every material input and every claimed output SHOULD be referenced by artifact ID.

A production event MUST NOT use the same immutable artifact instance as both an input and a newly produced output. In-place mutation must be modeled as distinct pre-state and post-state artifact instances.

### 7.3 Result states

The canonical event result vocabulary is:

```text
success
failure
inconclusive
not-run
unavailable
```

`success` means the declared procedure completed according to its procedure contract. It does not imply the output satisfies an E1 claim.

### 7.4 Provenance graph

Treat artifact instances and production events as a bipartite directed graph:

```text
artifact input -> production event -> artifact output
```

For immutable artifact instances, a provenance graph SHOULD be acyclic.

If a cycle appears, the project MUST determine whether:

- mutable logical subjects were mistaken for immutable artifact instances;
- a bootstrap chain requires distinct versioned artifacts;
- the provenance relation was modeled incorrectly.

The E3 reference checker rejects cycles in the finite artifact/event graph.

### 7.5 Multiple producers

Byte-identical artifacts MAY have multiple production events.

The registry MUST preserve those events separately because provenance is a relation about production history, not merely output bytes.

---

## 8. Replay model

### 8.1 Replay record

A replay `r` is modeled as:

```text
r = (
    id,
    target_event,
    procedure,
    environment,
    input_bindings,
    observed_outputs,
    relation,
    equivalence_policy,
    result,
    observed_at,
    independence
)
```

### 8.2 Output relations

The canonical replay relation is one of:

```text
byte-exact
canonical-equivalent
semantic-equivalent
observation-only
```

### 8.3 Replay results

The canonical replay result is:

```text
match
mismatch
inconclusive
not-run
unavailable
not-applicable
```

### 8.4 Exact replay rule

For `relation = byte-exact`, a replay may be `match` only if each expected output role is paired with an observed artifact whose accepted byte identity equals the expected artifact identity.

The observed output MUST be represented by a distinct artifact instance from the expected output. Reusing the expected artifact ID would only reassert its stored identity and would not record a replay.

Formally, for expected outputs `O` and replay outputs `O'` with role pairing `ρ`:

```text
exact_match(r) iff
    roles(O) = roles(O')
    and for every role q:
        B(O[q]) = B(O'[ρ(q)])
```

under the selected byte-identity policy.

### 8.5 Canonical equivalence

For `canonical-equivalent`, the registry MUST name an equivalence policy and the canonicalizer/procedure needed to justify the comparison.

A generic E3 checker MUST NOT infer canonical equivalence from similar filenames, archive listings, JSON object order, timestamps, or text normalization.

### 8.6 Semantic equivalence

For `semantic-equivalent`, the equivalence policy MUST be domain-specific or manually attested unless a mechanically checkable comparator has an explicit authoritative contract.

Semantic equivalence MUST NOT be relabeled byte reproducibility.

### 8.7 Observation-only replay

Some evidence can be meaningfully repeated without deterministic outputs, such as:

- performance samples;
- live-service observations;
- randomized fuzzing;
- distributed-system behavior.

These use `observation-only`. The replay establishes that a procedure was repeated under a declared environment. It does not imply deterministic output identity.

---

## 9. Independence

### 9.1 Independence is a separate dimension

A replay performed twice by the same CI job definition is not automatically an independent reproduction.

The canonical independence values are:

```text
same-executor
separate-run
separate-environment
separate-implementation
external-party
unknown
```

These are descriptive classes, not a total strength order.

### 9.2 Independence policy

A claim such as `independently-reproduced` MUST name an evidence policy defining which independence dimensions are required.

A generic checker MAY verify that the declared field exists. It MUST NOT infer organizational or epistemic independence from repository metadata alone.

---

## 10. Reproducibility qualification

### 10.1 No universal reproducibility level

E3 forbids replacing the replay tuple with a single optimistic scalar such as:

```text
R0 < R1 < R2 < R3
```

unless a local domain standard explicitly owns such a mapping.

Reproducibility SHOULD instead be reported as:

```text
(
    input_identity,
    procedure_identity,
    environment_capture,
    output_relation,
    independence,
    replay_result
)
```

### 10.2 Exact reproducibility claim

A claim of exact reproducibility requires at least:

- identified material inputs;
- identified procedure implementation or authoritative procedure revision;
- material environment capture;
- expected output identities;
- a later replay record;
- `relation = byte-exact`;
- `result = match`.

A project MAY require stronger independence by policy.

### 10.3 Reproducibility does not prove correctness

A perfectly reproducible defect is reproducible.

Therefore:

```text
reproducible != correct
```

An E1 claim about correctness still requires its own evidence policy.

---

## 11. Evidence bindings

### 11.1 E1 evidence binding

E3 adds an optional overlay:

```text
EvidenceBinding = (
    evidence_id,
    artifacts,
    production_events,
    replays
)
```

`evidence_id` refers to an E1 evidence record.

### 11.2 Binding validity

A binding is mechanically valid when all referenced IDs resolve.

A binding MAY strengthen auditability by identifying exact objects used by evidence. It MUST NOT alter the E1 evidence `result`.

### 11.3 Reproducibility evidence kind

An E1 record of kind `reproducibility-replay` SHOULD reference at least one E3 replay record when E3 is adopted.

The replay relation and result determine what reproducibility statement may be made.

---

## 12. Provenance closure and retention

### 12.1 Closure boundary

A project MUST choose a provenance closure appropriate to the claim.

Examples:

- source file -> generated document;
- source tree + compiler + lockfile -> executable;
- theorem source + prover + proof kernel -> proof object;
- dataset + analysis code + runtime -> report.

The closure SHOULD end where additional identity would not materially change audit or replay confidence under the declared policy.

### 12.2 Non-closure state

If a material dependency is known but unavailable or unidentified, the provenance record MUST preserve that fact.

The event may remain useful, but exact reproducibility MUST NOT be claimed when its required closure is incomplete.

### 12.3 Retention

E3 does not require permanent retention of every intermediate artifact.

A retention policy MAY preserve:

- digests only;
- digests plus reproducible source inputs;
- full artifact bytes;
- external immutable object references.

The registry MUST distinguish what is retained from what is merely identified.

---

## 13. Artifact acquisition

### 13.1 Acquired artifacts

An artifact may enter the provenance graph without being produced by the project.

Its acquisition record SHOULD identify:

- locator;
- observed digest and size;
- acquisition time when relevant;
- transport/source label;
- verification state.

### 13.2 Source label is not authenticity

Recording:

```text
source = "release-server"
```

does not authenticate the server or publisher.

If authenticity is required, a separate mechanism such as a signature, trusted transparency record, authenticated channel, or external attestation policy must establish it.

E3 MAY reference such evidence but does not define a PKI.

---

## 14. Mutability and supersession

### 14.1 Immutable event history

Production and replay records SHOULD be append-only.

If a record was malformed, a correcting record SHOULD identify:

```text
supersedes = old-record-id
reason = ...
```

### 14.2 Artifact replacement

When bytes change, create a new immutable artifact instance or revision-bound identity record.

Do not edit an existing immutable artifact record so that its digest silently changes while evidence continues to reference the same ID.

### 14.3 Locator mutation

A locator may change without changing artifact identity.

Artifact identity MUST therefore not depend solely on a path, URL, object key, package name, or human filename.

---

## 15. Mechanical E3 obligations

An E3-aware checker MUST support the following minimum mechanical checks.

### 15.1 `M-E3-REGISTRY`

Verify:

- supported E3 registry version;
- required collections and primitive types;
- unique IDs within each collection;
- references resolve.

### 15.2 `M-E3-ARTIFACT`

For every local artifact:

- path confinement;
- regular-file requirement;
- exact size;
- supported digest recomputation;
- digest equality.

For external/unavailable artifacts, verify declaration syntax without claiming local verification.

### 15.3 `M-E3-PROCEDURE`

Verify:

- stable IDs;
- authority references;
- implementation artifact references;
- known determinism vocabulary;
- equivalence policy references when required.

### 15.4 `M-E3-EVENT`

Verify:

- procedure/environment/input/output references;
- no input/output identity alias within one event;
- declared result vocabulary;
- finite provenance graph acyclicity.

### 15.5 `M-E3-REPLAY`

For `byte-exact + match`, verify:

- target event resolves;
- expected and observed output roles align;
- artifact identity tuples match by role;
- every referenced artifact is structurally valid.

For canonical or semantic equivalence, verify that an explicit equivalence policy is named. A generic checker MUST NOT pretend to validate domain semantics unless the comparator is itself part of the trusted checker implementation.

### 15.6 `M-E3-BINDING`

Verify E1 evidence bindings resolve when an E1 registry is available.

### 15.7 `M-E3-CYCLE`

Reject a cycle in the finite immutable artifact/event provenance graph.

---

## 16. Checker trust boundary

### 16.1 Static checker

The E3 reference checker is static.

It:

- reads repository-local profile/registry files;
- hashes declared local artifacts;
- validates graph/reference invariants;
- compares declared byte identities.

It does not:

- execute build commands;
- download external artifacts;
- invoke package managers;
- run containers;
- validate signatures;
- infer producer identity;
- infer semantic equivalence;
- infer independence.

### 16.2 Replay execution belongs elsewhere

CI, a build system, proof system, or dedicated reproduction harness MAY execute procedures and produce E3 records.

The static checker consumes those records afterward.

This preserves the E2 rule that repository conformance checking does not execute untrusted repository commands.

---

## 17. Registry authority

The canonical repository registry SHOULD be a machine-readable artifact such as:

```text
conformance/provenance.json
```

A project MUST have exactly one authoritative registry for a given E3 provenance domain.

Generated views, reports, graphs, and dashboards MUST derive from that registry or clearly declare another non-overlapping authority domain.

---

## 18. Recommended registry structure

A registry SHOULD contain:

```json
{
  "standard": "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0",
  "revision": "...",
  "artifacts": [],
  "environments": [],
  "equivalence_policies": [],
  "procedures": [],
  "events": [],
  "replays": [],
  "evidence_bindings": []
}
```

The companion JSON Schema owns the concrete interchange shape. This document owns the semantics.

---

## 19. Claim boundaries

An E3 conformance statement MUST preserve at least the following distinctions:

```text
digest syntax valid != artifact bytes verified
artifact bytes verified != artifact origin authenticated
provenance recorded != provenance independently corroborated
production success != E1 claim correctness
replay executed != replay matched
byte match != semantic correctness
semantic equivalence != byte identity
same output != independent reproduction
complete local graph != universal dependency closure
```

---

## 20. Conformance declaration

A project adopting E3 SHOULD report:

```text
EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0
```

A repository may separately report:

```text
E2 mechanical conformance: conformant
E3 provenance structure: conformant
E3 local artifact identity: verified
E3 replay status: as recorded per replay
manual/domain gates: ...
```

It MUST NOT collapse these into a single stronger statement whose entailment has not been defined.

---

## 21. Minimal example

```json
{
  "standard": "EIGIIB-1.0+E1-1.0+E2-1.0+E3-1.0",
  "revision": "example-r1",
  "artifacts": [
    {
      "id": "input",
      "role": "source",
      "kind": "file",
      "path": "src/input.txt",
      "size": 12,
      "digests": {
        "sha256": "..."
      },
      "availability": "local",
      "identity_state": "verified"
    },
    {
      "id": "output",
      "role": "result",
      "kind": "file",
      "path": "out/result.bin",
      "size": 42,
      "digests": {
        "sha256": "..."
      },
      "availability": "local",
      "identity_state": "verified"
    }
  ],
  "environments": [
    {
      "id": "python-3.13-linux",
      "properties": {
        "runtime": "CPython 3.13",
        "os": "Linux"
      }
    }
  ],
  "equivalence_policies": [],
  "procedures": [
    {
      "id": "build-result",
      "authority": "build",
      "implementation_artifacts": [],
      "determinism": "deterministic"
    }
  ],
  "events": [
    {
      "id": "build-001",
      "subject": "result",
      "source_revision": "example-r1",
      "procedure": "build-result",
      "environment": "python-3.13-linux",
      "inputs": [{"role": "source", "artifact": "input"}],
      "outputs": [{"role": "result", "artifact": "output"}],
      "result": "success"
    }
  ],
  "replays": [],
  "evidence_bindings": []
}
```

The example records provenance and local artifact identity. It does not claim that an independent replay occurred.

---

## 22. Adoption rule

E3 SHOULD be adopted when evidence or release claims materially depend on exact artifact identity or replayability.

Projects SHOULD NOT create provenance records for every trivial temporary object. The retained graph should be the minimum sufficient closure needed to:

- disambiguate the evidence;
- reproduce the material transformation where promised;
- detect stale or substituted artifacts;
- audit the claim boundary.

This preserves the EIGIIB rule: explicit where identity crosses a material boundary; implicit where routine mechanics add no durable information.
