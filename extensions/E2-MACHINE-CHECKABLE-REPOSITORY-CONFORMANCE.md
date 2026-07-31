# EIGIIB-E2 — Machine-Checkable Repository Conformance

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0 and EIGIIB-E1 1.0  
**Reference implementation:** `tools/eigiib_check.py`

---

## 1. Purpose

EIGIIB-E2 defines the subset of EIGIIB conformance that a repository-local tool may check mechanically without inventing semantic certainty.

E2 has two equally important goals:

1. make high-value structural and evidential obligations executable;
2. prevent automation from claiming more than static repository evidence can establish.

The second goal is normative. A checker that reports full semantic conformance from filenames, comment ratios, document counts, keywords, or schema validity alone is non-conformant.

E2 therefore distinguishes:

```text
repository validity
mechanical conformance
manual gate completion
overall declared conformance
```

A machine can establish the first two directly. It can verify the presence and declared status of manual attestations, but it cannot independently prove their semantic correctness.

---

## 2. Checker trust boundary

### 2.1 Inputs

The reference checker treats the following as untrusted repository input:

- `EIGIIB.toml`;
- authority paths;
- ownership registries;
- claim/evidence registries;
- referenced local artifacts;
- Markdown files when local-link checking is enabled.

### 2.2 No repository code execution

A generic E2 static checker MUST NOT execute arbitrary commands obtained from the repository configuration.

In particular, it MUST NOT automatically execute:

- build commands;
- generators;
- shell fragments;
- test commands;
- package-manager hooks;
- user-provided scripts.

Execution evidence is consumed as evidence records. Producing that evidence belongs to CI/build systems with their own trust policy.

### 2.3 Filesystem confinement

Every repository-relative path consumed by the checker MUST:

- be relative;
- normalize without `..` escape;
- resolve within the repository root;
- be checked as the expected file type before content is interpreted.

Symlink handling MUST NOT permit escape from the repository root.

---

## 3. Repository profile

### 3.1 Canonical filename

The default project profile is:

```text
EIGIIB.toml
```

A checker MAY accept another path through an explicit CLI option.

### 3.2 Minimal profile

A minimal E2 profile is:

```toml
standard = "EIGIIB-1.0"
extensions = ["E1-1.0", "E2-1.0"]
conformance_target = "EIGIIB-C2"
revision = "git-or-release-revision"
registry = "conformance/e1-registry.json"
ownership_registry = "conformance/ownership.json"

[authorities]
scope = "README.md"
evidence = "conformance/e1-registry.json"

[checks]
markdown_links = true

[[manual_gates]]
id = "semantic-authority-review"
status = "complete"
authority = "scope"
attestation = "conformance/MANUAL-REVIEW.md"
```

### 3.3 Profile keys

The canonical keys are:

- `standard` — required; currently `EIGIIB-1.0`;
- `extensions` — required for E2; MUST contain `E1-1.0` and `E2-1.0`;
- `conformance_target` — one of `EIGIIB-C1`, `EIGIIB-C2`, `EIGIIB-C3`;
- `revision` — non-empty revision identifier;
- `registry` — optional E1 claim/evidence registry path; required for C2/C3 when material validation claims are present;
- `ownership_registry` — optional durable-fact ownership registry;
- `authorities` — map from project-local authority role to repository-relative path;
- `required_authorities` — optional explicit list of authority roles required by the local profile;
- `checks` — mechanical check options;
- `manual_gates` — declared non-mechanical obligations and attestations.

A project MAY extend the profile with namespaced tables. The reference checker rejects unknown top-level keys by default so accidental typos do not silently disable checks.

---

## 4. Mechanical obligation classes

E2 defines the following generic classes.

### 4.1 `M-PROFILE` — profile validity

The checker MUST verify:

- supported standard identifier;
- required extension identifiers;
- valid conformance target;
- non-empty revision;
- known top-level keys;
- correct primitive types.

### 4.2 `M-PATH` — path confinement and existence

The checker MUST verify every configured local path is confined to the repository and exists with the expected file type.

A path escape is a conformance error.

### 4.3 `M-AUTH` — declared authority integrity

The checker MUST verify:

- authority role identifiers are unique by construction;
- every authority path resolves;
- every role named in `required_authorities` exists;
- claim authority identifiers resolve to a declared authority.

The checker MUST NOT infer that two prose documents semantically duplicate one fact. That remains a manual/domain-specific audit unless a machine-readable ownership registry exposes the duplication.

### 4.4 `M-OWN` — ownership registry uniqueness

When `ownership_registry` is present, each durable fact identifier MUST appear exactly once.

Each ownership record MUST resolve to one declared authority role.

This check establishes **registry uniqueness**, not semantic completeness of the registry.

### 4.5 `M-E1` — typed registry integrity

When an E1 registry is present, the checker MUST verify at least:

- standard/revision fields;
- unique policy, claim, and evidence identifiers;
- policy references resolve;
- claim evidence references resolve;
- claim authority references resolve;
- evidence subject/revision identity matches the claim when used to establish it;
- scope values are non-empty finite sets;
- evidence results use the E1 vocabulary;
- established claims satisfy their declared mechanical evidence policy;
- established claims have no explicitly referenced failing evidence in overlapping scope;
- repository-relative evidence artifact paths are confined and exist.

### 4.6 `M-SCOPE` — finite scope coverage

For the reference scope rules:

- `exact`: evidence and claim scopes MUST be exactly equal;
- `evidence-superset`: the evidence scope MUST contain every claim dimension and every claim value in that dimension; extra evidence dimensions make the evidence narrower and therefore do **not** satisfy the claim unless the policy explicitly ignores those dimensions;
- `manual`: no generic mechanical coverage decision is made.

The reference checker intentionally uses conservative finite-set semantics.

### 4.7 `M-STATE` — state consistency

The checker MUST reject at least the following:

- `established` with unsatisfied required evidence kinds;
- `established` with referenced `fail` evidence overlapping the claim;
- `established` under a `manual` scope rule without a completed manual gate declared by policy;
- duplicate IDs;
- dangling references.

It MAY warn, rather than fail, when a weaker state appears conservative despite sufficient evidence.

### 4.8 `M-LINK` — local Markdown links

When enabled, the checker SHOULD verify repository-local Markdown file links resolve.

It MUST ignore:

- `http://` and `https://` URLs;
- `mailto:` links;
- fragment-only links;
- image/data URI payloads.

Anchor validity within Markdown documents is not required by E2-1.0.

### 4.9 `M-MANUAL` — manual gate declaration

For each manual gate, the checker MUST verify:

- stable gate identifier;
- status in `complete`, `pending`, `not-applicable`;
- authority role resolves;
- a `complete` gate has a confined attestation file that exists.

The checker MUST report that it verified **attestation presence and declaration**, not semantic correctness.

---

## 5. Mechanical result model

### 5.1 Finding severity

A finding has severity:

```text
error
warning
info
```

- `error`: a mechanical invariant is violated;
- `warning`: a conservative or incomplete condition deserves review but does not violate the selected mechanical profile;
- `info`: an explicit boundary or pending manual gate is reported.

### 5.2 Mechanical result

The machine-computed mechanical result is:

```text
conformant
non-conformant
unavailable
```

`unavailable` is used when the checker cannot evaluate mandatory mechanical input because the tool/runtime or required input is inaccessible for reasons not attributable to repository invalidity.

A missing configured repository file is normally `non-conformant`, not `unavailable`.

### 5.3 Manual result

Manual gate result is:

```text
complete
pending
not-applicable
```

If several gates exist, any `pending` gate keeps the aggregate manual result `pending`.

### 5.4 Overall result

The reference derivation is:

```text
if mechanical = non-conformant:
    overall = non-conformant
elif mechanical = unavailable:
    overall = unavailable
elif manual = pending:
    overall = partially-evaluated
else:
    overall = conformant
```

A checker MUST label this final value as a result **under the declared profile and trusted attestations**. It is not an independent proof that human attestations are true.

---

## 6. Exit codes

The reference CLI uses stable exit codes:

```text
0  mechanical checks passed; overall conformant under declared attestations
1  mechanical non-conformance
2  mechanically valid but manual gates remain pending / partially evaluated
3  checker unavailable or internal/tooling error
64 profile/CLI usage error
```

Automation MUST NOT map exit code `2` to success when the workflow requires full declared conformance.

A workflow interested only in mechanical validity MAY explicitly permit `2`.

---

## 7. Determinism

For identical repository bytes, configuration, and checker version, normalized JSON output MUST be deterministic except for explicitly excluded observational metadata such as wall-clock invocation time.

The reference checker therefore MUST:

- sort findings by stable keys;
- sort enumerated file paths;
- avoid filesystem traversal order as semantic input;
- avoid randomized identifiers;
- avoid network access;
- avoid environment-dependent implicit configuration discovery beyond the explicit repository root and config path.

---

## 8. Report format

A machine report SHOULD contain:

```json
{
  "tool": "eigiib-check",
  "tool_version": "0.1.0",
  "standard": "EIGIIB-1.0+E1-1.0+E2-1.0",
  "target": "EIGIIB-C2",
  "revision": "...",
  "mechanical_result": "conformant",
  "manual_result": "pending",
  "overall_result": "partially-evaluated",
  "findings": []
}
```

The report MUST distinguish the three result dimensions.

---

## 9. No verbosity heuristics

An E2 implementation MUST NOT use the following as conformance metrics:

- source line count;
- documentation line count;
- number of Markdown files;
- number or percentage of comments;
- average comment length;
- function count;
- module count;
- prose similarity score as a normative duplicate detector;
- generic documentation “coverage percentage”.

These metrics cannot determine whether explicit information is necessary or redundant.

---

## 10. Safe automation boundary

### 10.1 What E2 can establish

E2 can establish facts such as:

- configured authorities exist;
- references are confined and resolve;
- registry identifiers are unique;
- a claim points to evidence of the required type;
- finite scope coverage satisfies a declared policy;
- a declared established state is inconsistent with its evidence;
- a manual gate is still pending;
- a local Markdown link is broken.

### 10.2 What E2 cannot establish generically

E2 cannot generically establish:

- that architecture prose is conceptually complete;
- that a threat model covers all threats;
- that two different sentences are truly duplicate normative authorities;
- that names are maximally clear;
- that an abstraction is premature;
- that code is maintainable;
- that a public contract includes every domain-specific obligation;
- that a manual attestation is truthful.

A checker MUST surface these as manual gates or leave them outside its mechanical claim boundary.

---

## 11. Reference implementation requirements

The E2-1.0 reference checker MUST:

1. use only the Python standard library;
2. require Python 3.11+ for `tomllib`;
3. perform no network access;
4. execute no repository commands;
5. never import repository Python modules;
6. open only configured or scanned documentation files;
7. confine all paths;
8. emit human-readable and JSON results;
9. use the exit codes in §6;
10. include deterministic unit tests with valid and invalid fixtures.

The reference implementation is a conformance aid, not the normative source. This document owns E2 semantics.

---

## 12. CI integration

A repository targeting C3 SHOULD run, at minimum:

```text
python -m unittest discover -s tests -p 'test_*.py'
python tools/eigiib_check.py . --json
```

A CI workflow SHOULD pin or record the checker revision used for the result.

CI MAY separately build, test, fuzz, prove, or benchmark the project and emit E1 evidence records. The static E2 checker then validates the resulting claim/evidence relationships.

CI SHOULD NOT grant the checker authority to execute commands declared inside untrusted pull-request configuration.

---

## 13. Ownership registry

### 13.1 Format

The canonical E2 ownership registry is JSON:

```json
{
  "standard": "EIGIIB-1.0+E2-1.0",
  "facts": [
    {
      "id": "project.scope",
      "authority": "scope"
    }
  ]
}
```

### 13.2 Semantics

A fact ID MUST occur at most once.

If a project intentionally splits one broad concept into separately owned sub-facts, it MUST assign distinct fact identifiers.

Example:

```text
transport.authentication
transport.authorization
```

is preferable to two owners both claiming the vague fact `transport.security`.

---

## 14. Manual gate attestations

An attestation file SHOULD be short and should identify:

- gate ID;
- reviewed revision;
- reviewing authority or role;
- decision;
- material deviations or exclusions.

It SHOULD NOT reproduce the standard or narrate mechanically checkable results.

---

## 15. Conformance levels under E2

### 15.1 C1

E2 mechanical C1 SHOULD validate:

- profile integrity;
- required authority presence;
- path confinement;
- ownership registry uniqueness when present;
- enabled local-link checks.

### 15.2 C2

C2 includes C1 and SHOULD additionally validate:

- typed E1 registry integrity;
- claim/evidence reference integrity;
- evidence-policy satisfaction for established claims;
- state/scope consistency;
- explicit pending manual gates.

### 15.3 C3

C3 includes C2 and SHOULD additionally require a project-local profile that identifies authorities for operational/trust/capability state relevant to that project and a CI/review gate invoking E2.

E2 does not prescribe universal filenames for those authorities.

---

## 16. E2 invariant set

```text
E2-I1  The checker never executes repository-provided commands.
E2-I2  All consumed local paths are repository-confined.
E2-I3  Fixed input produces deterministic normalized decisions.
E2-I4  Registry references resolve and IDs are unique.
E2-I5  Established claims satisfy declared mechanical evidence policy.
E2-I6  Finite scope coverage is conservative; narrow evidence never broadens claims.
E2-I7  Manual gates remain explicitly manual.
E2-I8  Machine validity is not silently promoted to semantic certainty.
E2-I9  No verbosity or comment-density heuristic is normative.
E2-I10 Non-conformance, partial evaluation and unavailability remain distinguishable.
```

---

## 17. Extension boundary

E2 intentionally stops before:

- executing build/test commands;
- validating external URLs;
- semantic natural-language duplicate detection;
- cryptographic signing of evidence;
- distributed provenance or transparency logs;
- cross-repository authority resolution;
- policy-specific theorem proving.

Those functions require separate trust and lifecycle contracts and MAY be introduced by later EIGIIB extensions.
