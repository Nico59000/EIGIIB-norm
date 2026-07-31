# EIGIIB — External Interoperability Roadmap

**Status:** Draft, explanatory and non-normative  
**Intended location:** `docs/EXTERNAL-INTEROPERABILITY-ROADMAP.md`  
**Applies to:** EIGIIB Core through E11  
**Purpose:** Define how EIGIIB may interoperate with external standards without importing, duplicating, or silently redefining their semantics.

---

## 1. Purpose

EIGIIB has reached a point where several concerns already have mature external standards:

- software-supply-chain provenance;
- authenticated attestations;
- transparency services;
- software bills of materials;
- workload identity;
- update security;
- policy evaluation;
- trusted or authenticated time.

EIGIIB SHOULD NOT reproduce those standards merely to make their mechanisms locally explicit.

The purpose of interoperability is instead to preserve the separation:

\[
\boxed{
\text{EIGIIB semantic authority}
\neq
\text{external representation or transport authority}
}
\]

EIGIIB defines what a repository claim means, which evidence supports it, what its boundary is, and which conclusions are mechanically justified.

An external standard MAY provide:

- a portable representation;
- a signature envelope;
- a provenance vocabulary;
- an identity mechanism;
- a transparency service;
- a software inventory;
- an update protocol;
- a policy-evaluation backend;
- a temporal or timestamping evidence mechanism.

External adoption MUST NOT silently strengthen an EIGIIB conclusion.

For example:

\[
\boxed{
\text{EIGIIB claim in signed attestation}
\neq
\text{claim semantically established}
}
\]

and:

\[
\boxed{
\text{transparent publication}
\neq
\text{semantic correctness}.
}
\]

---

## 2. Relationship to the EIGIIB functional architecture

The current EIGIIB architecture is best understood as:

```text
Core
  ↓
(E1, E2)              epistemology + conformance
  ↓
E3 → E4 → E5 → E6    artifact + trust + transparency
  ↓
E7 → E8 → E9         resilience + adoption + degraded operation
  ↓
E10 → E11            decision + time
```

The extension numbers form the versioned progression of the standard.

The diagram above represents its functional structure.

External interoperability SHOULD attach to the smallest appropriate functional layer rather than being inserted as a new EIGIIB extension merely because an external technology exists.

Examples:

```text
SLSA / in-toto
       ↓
     E1/E3

Sigstore / transparency service
       ↓
     E4/E5

SPIFFE
       ↓
     E4/E10

TUF
       ↓
E4/E7/E8/E11

OPA / Cedar
       ↓
     E10

NTS / timestamp evidence
       ↓
     E11
```

These arrows mean **semantic adapter**, not semantic equivalence.

---

## 3. Interoperability principle

For any external standard or system \(X\), an EIGIIB integration SHOULD be represented by an adapter:

\[
A_X:
X
\longrightarrow
E_X
\]

where \(E_X\) is a typed EIGIIB evidence representation.

The adapter MUST state:

1. the external specification identity;
2. the external version or profile actually consumed;
3. the input artifact identity;
4. the EIGIIB claims the adapter may support;
5. the EIGIIB claims it explicitly cannot establish;
6. parsing and validation requirements;
7. external assumptions;
8. failure and unavailable states.

The adapter MUST NOT make the relation symmetric unless equivalence is actually proven.

Normally:

\[
X \rightarrow E_X
\]

does **not** imply:

\[
E_X \rightarrow X.
\]

---

## 4. External facts are typed evidence, not imported truth

An external result SHOULD enter EIGIIB as typed evidence.

For example, an external provenance document might become:

```text
external evidence
    type: slsa-provenance
    artifact: <identity>
    result: parsed-and-verified
    scope: build provenance
    external-spec: SLSA
    external-profile: <version>
```

This MUST remain distinct from an EIGIIB claim such as:

```text
claim:
    artifact build provenance established
```

The normal E1 relation remains:

\[
E \models_P C
\]

under an explicitly selected policy \(P\).

No external format bypasses E1 claim evaluation.

---

## 5. External-version discipline

External standards evolve independently from EIGIIB.

An adapter MUST therefore distinguish:

```text
standard family
specification version
profile/version
adapter version
observed implementation version
```

For example:

```text
family: in-toto Attestation Framework
specification: 1.2
adapter: eigiib-in-toto-v1
```

An adapter MUST NOT use an unqualified value such as:

```text
"in-toto": true
```

when version differences may materially affect interpretation.

External-version updates SHOULD normally change the adapter or its accepted profile set rather than changing the semantics of the receiving EIGIIB extension.

---

## 6. Interoperability maturity classes

EIGIIB SHOULD classify external adapters separately from extension conformance.

Recommended states are:

```text
experimental
structural
verified
interoperable
production-observed
```

Their meanings are:

### experimental

Mapping design exists but is not stable.

### structural

Schemas and boundary rules exist and pass static tests.

### verified

Reference fixtures and negative tests demonstrate the mapping.

### interoperable

At least one independent external implementation has exchanged artifacts successfully with the adapter.

### production-observed

The adapter has been exercised in a declared production environment.

These values MUST NOT be collapsed.

In particular:

\[
\boxed{
\text{structural}
\neq
\text{interoperable}
\neq
\text{production-observed}.
}
\]

---

## 7. in-toto Attestation Framework

### Role

The in-toto Attestation Framework is a strong candidate for the portable envelope of EIGIIB evidence.

The framework separates:

```text
Predicate
Statement
Envelope
Bundle
```

This aligns naturally with EIGIIB's separation between:

- evidence payload;
- artifact subject;
- authentication;
- grouping.

### Recommended mapping

An EIGIIB checker report MAY be represented as an in-toto Predicate.

Conceptually:

```text
in-toto Statement
├── subject
│   └── EIGIIB artifact identity
└── predicate
    └── EIGIIB typed checker report
```

A future predicate identity MAY be defined for EIGIIB.

Example conceptual name:

```text
EIGIIB Conformance Result
```

The predicate SHOULD include:

```text
eigiib_revision
checker
checker_version
claim_boundary
structural_result
capability_results
evidence_references
environment
```

### Boundary

\[
\boxed{
\text{valid in-toto structure}
\neq
\text{valid EIGIIB conclusion}.
}
\]

The EIGIIB checker result remains authoritative for EIGIIB semantics.

### Priority

**Priority: high.**

This is the preferred first portable evidence format for EIGIIB.

---

## 8. SLSA

### Role

SLSA is a supply-chain security specification rather than a general EIGIIB replacement.

EIGIIB SHOULD consume SLSA evidence primarily through E1 and E3.

### Useful mappings

```text
SLSA provenance
    → E3 provenance evidence

SLSA build properties
    → E1 typed evidence

SLSA source properties
    → E1/E3 source-lineage evidence

SLSA verification result
    → E1 evidence record
```

A SLSA level MUST remain externally qualified.

### Boundary

\[
\boxed{
\text{SLSA conformance}
\neq
\text{complete EIGIIB conformance}.
}
\]

SLSA does not replace EIGIIB ownership semantics, general claim boundaries, E7 recovery, E8 convergence, E9 degraded operation, E10 general decision authorization, or E11 temporal semantics.

### Priority

**Priority: high.**

Recommended after the in-toto envelope adapter.

---

## 9. Sigstore

### Role

Sigstore is a candidate external mechanism for authenticating portable EIGIIB evidence and carrying associated verification material.

### Recommended mapping

```text
EIGIIB checker result
        ↓
in-toto Statement
        ↓
signature
        ↓
Sigstore Bundle
```

EIGIIB MAY consume the resulting cryptographic verification as E4 evidence.

If transparency evidence is present, it MAY additionally feed E5.

Temporal material MAY feed E11 only under an explicit E11 adapter.

### Boundary

\[
\begin{aligned}
\text{signature verifies}
&\not\Rightarrow \text{claim true},\\
\text{certificate valid}
&\not\Rightarrow \text{principal authorized},\\
\text{transparency evidence present}
&\not\Rightarrow \text{global uniqueness}.
\end{aligned}
\]

### Priority

**Priority: high.**

Recommended as the authentication layer for the first portable EIGIIB attestation prototype.

---

## 10. Transparency: Rekor-compatible services and SCITT

### Role

EIGIIB E5 and E6 define abstract transparency and multi-view semantics.

External systems can provide concrete storage and receipt formats.

Two useful families are:

```text
Sigstore transparency infrastructure
SCITT-compatible transparency services
```

### Mapping

```text
SCITT signed statement
    → E4 authenticated statement evidence

SCITT receipt
    → E5 inclusion/publication evidence

multiple SCITT views
    → E6 comparison evidence
```

### Boundary

\[
\boxed{
\text{receipt}
\neq
\text{truth}.
}
\]

A transparency service proves properties about publication or registration.

It does not establish semantic correctness of the registered statement.

### Priority

**Priority: medium-high.**

Implement after the first in-toto/Sigstore capsule so that the E5/E6 requirements are already exercised by one concrete representation.

---

## 11. The Update Framework — TUF

### Role

TUF is highly relevant to EIGIIB because it operationalizes several concerns that cross:

```text
E4  trust and delegation
E7  recovery and replacement
E8  migration
E11 temporal expiration
```

### Important architectural rule

EIGIIB MUST NOT reimplement TUF as another update protocol.

Instead, a TUF interoperability profile SHOULD map concrete TUF state transitions into EIGIIB evidence.

Examples:

```text
root metadata transition
    → E4 trust-state evidence
    → possibly E7 transition evidence

role expiration
    → E11 temporal evidence

metadata version progression
    → rollback-resistance evidence

target verification
    → E3/E4 artifact evidence
```

### Boundary

\[
\boxed{
\text{TUF update accepted}
\neq
\text{general EIGIIB authorization}.
}
\]

TUF authority applies to its update-security domain.

It MUST NOT silently become E10 authority for arbitrary actions.

### Priority

**Priority: medium-high.**

Useful especially after E12 introduces atomic consumption and commit-time revalidation.

---

## 12. SPIFFE

### Role

SPIFFE is a strong candidate for assigning concrete external identities to EIGIIB principals.

### Mapping to EIGIIB

```text
SPIFFE ID
    → external principal identifier

SVID verification
    → E4 authentication evidence

SPIFFE trust domain
    → declared E4/E10 administrative boundary

SPIFFE federation relation
    → external trust relationship evidence
```

### Critical boundary

\[
\boxed{
\text{SPIFFE-authenticated}
\neq
\text{E10-authorized}.
}
\]

An E10 policy still decides whether the authenticated principal may perform an action.

### Priority

**Priority: medium.**

Particularly valuable when EIGIIB is applied to services, agents, CI workers or distributed infrastructure.

---

## 13. SPDX

### Role

SPDX is a candidate external inventory and relationship vocabulary for artifact and supply-chain evidence.

### Mapping

```text
SPDX package
    → E3 artifact subject

SPDX relationships
    → E3 dependency/provenance edges

SPDX creation information
    → E1/E3 metadata evidence
```

### Boundary

An SPDX document does not automatically establish:

- artifact authenticity;
- build provenance;
- dependency trustworthiness;
- absence of vulnerabilities;
- runtime presence.

Thus:

\[
\boxed{
\text{listed}
\neq
\text{present}
\neq
\text{verified}
\neq
\text{trusted}.
}
\]

### Priority

**Priority: medium-high** for software projects using EIGIIB.

---

## 14. CycloneDX

### Role

CycloneDX provides another mature supply-chain representation and BOM ecosystem.

EIGIIB SHOULD support CycloneDX through an adapter parallel to SPDX rather than declaring one format globally preferred.

### Mapping

Possible evidence sources include:

```text
components
services
dependencies
cryptographic assets
operational configuration
```

These MAY feed E1/E3 evidence.

### Avoiding artificial unification

Prefer:

```text
SPDX adapter ─┐
              ├→ typed EIGIIB evidence
CycloneDX ────┘
```

over a large EIGIIB universal BOM model unless the middle model closes an actual ambiguity.

### Priority

**Priority: medium-high.**

Develop together with SPDX interoperability fixtures.

---

## 15. Open Policy Agent / Rego

### Role

OPA is a general-purpose policy engine and aligns naturally with E10.

### Recommended mapping

```text
E10 normalized request
      ↓
OPA adapter
      ↓
OPA/Rego evaluation
      ↓
normalized E10 policy-result evidence
```

The adapter SHOULD bind at least:

```text
policy identity
policy revision/digest
input identity
data revision where applicable
query
result
engine identity/version
evaluation evidence
```

### Boundary

\[
\boxed{
\text{OPA allow}
\neq
\text{E10 authorized}
}
\]

until the relevant E10 policy explicitly declares that OPA result authoritative for the selected boundary.

### Priority

**Priority: medium.**

Implement as an E10 backend adapter rather than an EIGIIB extension.

---

## 16. Cedar

### Role

Cedar is specifically designed as an authorization policy language and evaluation model.

It therefore provides a useful second independent policy backend for testing whether E10 is genuinely backend-neutral.

### Recommended use

```text
                 ┌→ OPA/Rego
E10 request ─────┤
                 └→ Cedar

both
 ↓
normalized E10 evaluation result
```

If the normalized model works only for one engine, E10 is probably leaking backend-specific assumptions.

### Boundary

Cedar authorization semantics remain Cedar's authority.

EIGIIB owns only:

- how the external result is identified;
- how it is bound to E10 inputs;
- what EIGIIB conclusion it may support.

### Priority

**Priority: medium.**

Best developed together with the OPA profile as a backend-independence test.

---

## 17. External time mechanisms

E11 deliberately defines no implicit trusted wall clock.

External temporal technologies SHOULD therefore enter through explicit adapters.

At least three distinct categories must remain separate:

```text
clock synchronization
authenticated approximate time
timestamp evidence
```

They MUST NOT all map to:

```text
trusted_time = true
```

### Network time synchronization

A network time protocol may support an E11 observation source.

The adapter must state:

- time domain;
- authentication mode;
- uncertainty/error bound;
- observation time;
- source;
- evidence.

### Authenticated approximate time

An authenticated time statement can support an observation interval but may have substantially different precision or trust semantics from synchronized wall-clock time.

It SHOULD therefore produce an E11 observation with explicit uncertainty.

### Timestamp authority evidence

A timestamp token normally establishes a proposition closer to:

```text
data existed no later than declared timestamp
```

than:

```text
this host's current time equals t
```

These MUST remain distinct E11 evidence types.

### Boundary

\[
\boxed{
\text{timestamp evidence}
\neq
\text{current trusted clock}.
}
\]

### Priority

**Priority: high after E12**, because commit-time revalidation will make temporal evidence operationally more important.

---

## 18. Recommended portable EIGIIB evidence capsule

The first external interoperability prototype SHOULD follow:

```text
EIGIIB checker
      ↓
EIGIIB normalized result
      ↓
in-toto Predicate / Statement
      ↓
authenticated envelope or Sigstore Bundle
      ↓
optional transparency registration
      ↓
portable evidence capsule
```

Formally:

\[
\boxed{
R_{\mathrm{EIGIIB}}
\rightarrow
A_{\mathrm{in\text{-}toto}}
\rightarrow
B_{\mathrm{signature}}
\rightarrow
T_{\mathrm{transparency}}
}
\]

while preserving:

\[
R
\neq A
\neq B
\neq T.
\]

Each stage adds one type of property.

No stage promotes the previous stage into semantic truth.

---

## 19. Proposed interoperability capsule structure

A future EIGIIB portable capsule MAY use:

```text
eigiib-capsule/
├── manifest.json
├── statement.json
├── bundle.json
├── evidence/
│   ├── checker-report.json
│   └── external/
└── receipts/
```

The manifest SHOULD own only capsule composition.

It SHOULD NOT copy the complete checker report.

Possible manifest fields:

```text
format
format_version
eigiib_revision
subject
statement
authentication_bundle
evidence
receipts
```

Artifact identities SHOULD use immutable identifiers.

---

## 20. External interoperability registry

A future machine-readable registry SHOULD track adapters.

Recommended conceptual schema:

```json
{
  "id": "in-toto-attestation",
  "family": "in-toto Attestation Framework",
  "external_specification": "1.2",
  "adapter_version": "0.1",
  "status": "experimental",
  "eigiib_layers": ["E1", "E3", "E4"],
  "direction": "external-to-eigiib-and-export",
  "authority": "interop profile document",
  "checker": "adapter checker",
  "fixtures": [],
  "boundaries": []
}
```

This registry SHOULD become the authoritative source for generated interoperability documentation.

---

## 21. Adapter conformance requirements

Every EIGIIB external adapter SHOULD provide:

1. a profile document;
2. a machine-readable schema where applicable;
3. a deterministic adapter or checker;
4. positive fixtures;
5. negative fixtures;
6. external-version fixtures;
7. claim-boundary tests;
8. malformed-input tests;
9. unsupported-version tests;
10. evidence describing the executed tests.

An adapter MUST reject or explicitly mark `unsupported` when it receives an external version whose semantics it does not understand.

Silent best-effort reinterpretation is prohibited.

---

## 22. Unknown external state

Adapters MUST preserve unknown states.

Recommended states include:

```text
unsupported-version
unavailable
not-evaluated
invalid
inconclusive
verified
```

For example:

```text
cannot verify Sigstore bundle
```

MUST NOT become:

```text
bundle invalid
```

when the verifier or trust material is unavailable.

Likewise:

```text
external service unavailable
```

MUST NOT become evidence that the external statement is false.

---

## 23. Authentication material and semantic claims

External cryptographic verification MUST feed the correct EIGIIB layer.

For example:

```text
signature verification
    → E4 evidence
```

not:

```text
signature verification
    → arbitrary E1 claim established
```

The correct chain is:

\[
\text{signature evidence}
\rightarrow
E4\text{ authentication decision}
\rightarrow
E1\text{ policy evaluation}
\rightarrow
\text{bounded claim}.
\]

---

## 24. Supply-chain artifact identity

When SPDX, CycloneDX, SLSA or in-toto identify the same artifact, EIGIIB SHOULD avoid creating parallel identities without an explicit relation.

Possible relation:

```text
external subject identifier
        ↓
E3 artifact identity binding
```

If two systems identify artifacts through different schemes, an EIGIIB adapter MUST distinguish:

```text
same bytes
same named artifact
same package release
same build output
same logical component
```

These are not equivalent relations.

---

## 25. Cross-standard composition

A realistic software artifact may have:

```text
SPDX / CycloneDX inventory
        +
SLSA provenance
        +
in-toto Statement
        +
Sigstore signature
        +
transparency receipt
```

The EIGIIB interpretation should remain factored:

```text
inventory evidence
provenance evidence
subject binding
authentication evidence
publication evidence
```

rather than collapsing the combination into:

```text
trusted artifact = true
```

---

## 26. No universal trust score

EIGIIB SHOULD NOT introduce a numeric aggregate such as:

```text
trust_score = 97
```

for external evidence.

SLSA level, signature verification, transparency registration, SBOM completeness and policy approval are different axes.

If a project needs a release decision, that decision belongs to an explicit policy:

\[
P(E_1,E_2,\ldots,E_n)\rightarrow D.
\]

The decision is an E10 policy result, not an intrinsic property of the evidence set.

---

## 27. No implicit preference for one ecosystem

EIGIIB SHOULD remain interoperable with multiple implementations.

Examples:

```text
SPDX OR CycloneDX
OPA OR Cedar
Sigstore OR another compatible signature envelope
SCITT service A OR service B
```

An EIGIIB profile MAY select one external mechanism for a given repository.

The core standard SHOULD NOT make that mechanism universally mandatory unless EIGIIB itself fundamentally depends on its semantics.

---

## 28. Relationship with future E12

The anticipated E12 concern is:

```text
atomic authorization consumption
commit-time revalidation
TOCTOU closure
```

External interoperability should prepare for E12 without prematurely defining it.

Adapters SHOULD preserve identifiers capable of binding:

```text
E10 decision
E11 temporal decision
target artifact
policy revision
context revision
operation
```

A future E12 commit record can then reference those identities exactly.

TUF, policy engines and external temporal evidence become particularly relevant after that layer exists.

---

## 29. Initial implementation phases

### Phase P0 — Registry and documentation

Create:

```text
interop/
docs/EXTERNAL-INTEROPERABILITY-ROADMAP.md
```

and a machine-readable interoperability registry.

No external execution is required.

### Exit condition

External families and claim boundaries are structurally represented.

---

### Phase P1 — in-toto export profile

Implement:

```text
EIGIIB checker report
    → in-toto Statement
```

with deterministic fixtures.

Required tests:

- valid export;
- wrong subject digest;
- unsupported predicate version;
- missing EIGIIB boundary;
- changed checker report;
- unknown external field handling.

### Exit condition

Portable EIGIIB evidence can be represented without semantic loss.

---

### Phase P2 — Sigstore authentication profile

Add authentication of the portable statement.

Required tests:

- valid bundle;
- invalid signature;
- unavailable verifier;
- unsupported bundle version;
- valid signature from unauthorized identity;
- temporal verification-material boundary.

### Exit condition

Authentication is demonstrably separate from EIGIIB semantic validation.

---

### Phase P3 — Transparency profile

Add a concrete E5/E6 external transparency adapter.

Possible first targets:

```text
Sigstore-compatible transparency evidence
SCITT experimental profile
```

### Exit condition

Publication/inclusion evidence can be consumed without promoting it to truth or global uniqueness.

---

### Phase P4 — Supply-chain evidence

Implement independent adapters for:

```text
SLSA
SPDX
CycloneDX
```

### Exit condition

EIGIIB can consume provenance and inventory evidence without defining a duplicate supply-chain schema.

---

### Phase P5 — Identity and policy backends

Implement:

```text
SPIFFE → E4/E10 identity adapter
OPA    → E10 policy backend
Cedar  → E10 policy backend
```

### Exit condition

E10 demonstrates backend-neutral authorization input/output binding.

---

### Phase P6 — Temporal interoperability

Implement selected external E11 temporal profiles.

### Exit condition

External time or timestamp evidence is represented as explicit observations with bounded semantics rather than as an untyped trusted-clock Boolean.

---

## 30. Proposed repository structure

```text
interop/
├── registry.json
├── in-toto/
│   ├── PROFILE.md
│   ├── schemas/
│   └── fixtures/
├── slsa/
├── sigstore/
├── scitt/
├── tuf/
├── spiffe/
├── spdx/
├── cyclonedx/
├── opa/
├── cedar/
└── temporal/
```

Adapter executables SHOULD remain under:

```text
tools/
```

if they participate in repository conformance.

Schemas SHOULD remain under:

```text
schemas/
```

unless the schema belongs exclusively to an external fixture.

---

## 31. External references should not be manually duplicated

This roadmap intentionally describes external specifications at a high semantic level.

Detailed external field inventories SHOULD NOT be copied into EIGIIB documents.

Instead, a future interoperability registry SHOULD own:

```text
family
specification version
profile
status
reference identifier
last compatibility review
```

Generated documentation MAY display those values.

This prevents version drift.

---

## 32. Version-review policy

Each external profile SHOULD declare:

```text
last_reviewed_external_version
accepted_versions
rejected_versions
next_review_trigger
```

A review SHOULD be triggered when:

- a new major external specification is published;
- an accepted external profile is retired;
- security semantics materially change;
- a field used in an EIGIIB mapping changes meaning;
- an external algorithm or identity model is deprecated.

---

## 33. Security boundary

External interoperability expands the parsing and trust surface.

Therefore every adapter MUST treat external content as untrusted input until the relevant validation layer succeeds.

At minimum:

```text
parsed
!=
schema-valid
!=
cryptographically verified
!=
trusted
!=
authorized
!=
semantically sufficient
```

Adapters SHOULD use bounded parsing and explicit resource ceilings where the external format permits attacker-controlled size or graph complexity.

---

## 34. Privacy boundary

Transparency and provenance may disclose information.

An adapter MUST NOT assume that information acceptable inside an EIGIIB repository is safe to publish externally.

Before external publication, the system SHOULD distinguish:

```text
repository-visible
attestation-visible
transparency-public
recipient-confidential
```

This area is deliberately incomplete before a future EIGIIB confidentiality/selective-disclosure extension.

Until then, adapters SHOULD default to minimal disclosure.

---

## 35. Long-term cryptographic boundary

External signature verification can remain technically valid after algorithms, keys, identities or trust policies become obsolete.

The interoperability layer SHOULD preserve enough information to permit future re-evaluation.

It SHOULD NOT claim permanent validity solely because verification succeeded once.

---

## 36. Non-goals

This roadmap does not:

- replace SLSA;
- replace in-toto;
- define a new signature format;
- replace Sigstore;
- define a transparency ledger;
- replace TUF;
- define workload identity;
- replace SPIFFE;
- define a new SBOM;
- replace SPDX or CycloneDX;
- define a policy language;
- replace OPA or Cedar;
- define a wall-clock synchronization protocol;
- establish malicious intent from replay evidence;
- declare external certifications equivalent to EIGIIB conformance.

---

## 37. Priority matrix

| External family | Primary EIGIIB layer | Initial priority | Recommended form |
|---|---|---:|---|
| in-toto Attestation Framework | E1 / E3 / E4 | P1 | portable evidence envelope |
| Sigstore | E4 / E5 / E11 | P2 | authentication bundle |
| SLSA | E1 / E3 | P4 | provenance/source evidence |
| SCITT | E4 / E5 / E6 | P3 | transparency profile |
| TUF | E4 / E7 / E8 / E11 / future E12 | P4+ | composite validation fixture |
| SPIFFE | E4 / E10 | P5 | principal/authentication adapter |
| SPDX | E1 / E3 | P4 | artifact/inventory adapter |
| CycloneDX | E1 / E3 | P4 | artifact/inventory adapter |
| OPA / Rego | E10 | P5 | policy backend |
| Cedar | E10 | P5 | policy backend |
| external time/timestamp mechanisms | E11 / future E12 | P6 | temporal evidence adapters |

---

## 38. Recommended first interoperability milestone

The first concrete interoperability milestone SHOULD be deliberately narrow:

\[
\boxed{
\texttt{M0-P1 — Portable EIGIIB Attestation Capsule}
}
\]

Its only objectives are:

1. select one existing EIGIIB checker report;
2. bind it to its artifact subject;
3. encode it in an in-toto Statement;
4. preserve all EIGIIB claim boundaries;
5. round-trip the representation without information loss;
6. authenticate it through a Sigstore-compatible bundle;
7. keep authentication distinct from semantic validation.

A successful P1 SHOULD establish:

```text
portable       = yes
subject-bound  = yes
authenticated  = yes
EIGIIB-valid   = separately evaluated
```

It MUST NOT claim:

```text
globally trusted = yes
```

or:

```text
semantically true because signed = yes
```

---

## 39. Architectural target

```text
                     ┌────────────────────┐
                     │   External systems │
                     └─────────┬──────────┘
                               │
                    explicit adapter/profile
                               │
                               ▼
┌─────────────────────────────────────────────────┐
│              EIGIIB evidence boundary           │
│                                                 │
│ E1 claims/evidence                              │
│ E3 artifact/provenance                          │
│ E4 authentication                               │
│ E5 transparency                                 │
│ E6 multi-view accountability                    │
│ E7–E9 lifecycle/resilience                      │
│ E10 authorization                               │
│ E11 temporal admissibility                      │
└──────────────────────┬──────────────────────────┘
                       │
                 explicit policy
                       │
                       ▼
                bounded conclusion
```

No external input crosses directly to a conclusion.

The adapter and the receiving EIGIIB policy are explicit boundaries.

---

## 40. Final design rule

\[
\boxed{
\text{Reuse external mechanism;}
\quad
\text{retain EIGIIB semantics;}
\quad
\text{duplicate neither.}
}
\]

Operationally:

```text
external standard
    owns its protocol and data semantics

EIGIIB adapter
    owns the mapping boundary

EIGIIB extension
    owns the receiving EIGIIB semantics

EIGIIB policy
    owns the resulting bounded conclusion
```

This division is the intended stable architecture for future interoperability work.

---

# Appendix A — External specification snapshot

This appendix records the external landscape observed when this roadmap draft was prepared.

It is informative only and MUST NOT be treated as a permanent dependency lock.

A future interoperability registry SHOULD own the exact accepted versions and last compatibility review.

---

# Appendix B — Candidate future profiles

Possible profile identifiers, intentionally provisional:

```text
EIGIIB-INTEROP-IN-TOTO-0.1
EIGIIB-INTEROP-SIGSTORE-0.1
EIGIIB-INTEROP-SLSA-0.1
EIGIIB-INTEROP-SCITT-0.1
EIGIIB-INTEROP-TUF-0.1
EIGIIB-INTEROP-SPIFFE-0.1
EIGIIB-INTEROP-SPDX-0.1
EIGIIB-INTEROP-CYCLONEDX-0.1
EIGIIB-INTEROP-OPA-0.1
EIGIIB-INTEROP-CEDAR-0.1
EIGIIB-INTEROP-TEMPORAL-0.1
```

These identifiers SHOULD NOT be declared normative until an actual profile, checker and fixture set exist.

---

# Appendix C — Relationship to E12

The next proposed EIGIIB semantic extension remains:

```text
EIGIIB-E12
Atomic Authorization Consumption,
Commit-Time Revalidation
and TOCTOU Closure
```

The interoperability roadmap SHOULD prepare for E12 but MUST NOT preemptively define its normative semantics.

Portable evidence SHOULD preserve immutable bindings for:

```text
decision identity
decision revision
policy identity
policy revision
context revision
temporal decision
target artifact
operation identity
replay/idempotency material
```

so that a future E12 commit record can consume those facts without reconstructing them from ambiguous external state.

---

**End of explanatory interoperability roadmap.**
