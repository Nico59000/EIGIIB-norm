# EIGIIB M0-A3 — External Interoperability Profiles

Status: repository infrastructure contract. M0-A3 is not a numbered EIGIIB extension and does not import external standards as EIGIIB authorities.

## Purpose

M0-A3 defines how EIGIIB may reference, consume, transport, or export information through an external standard without copying that standard into EIGIIB and without strengthening an EIGIIB claim merely because an external format is present.

The mechanism has two authorities:

1. an exact external-specification catalog entry;
2. a bounded interoperability profile that describes the relationship between external elements and existing EIGIIB authorities.

## Core separations

```text
external compatibility != EIGIIB conformance
external format validity != semantic truth
transport != authentication
authentication != authorization
transparency inclusion != semantic correctness
external identity != EIGIIB authority
profile specification != adapter implementation
adapter implementation != validated interoperability
versioned external reference != byte-immutable specification snapshot
declared observation date != trusted freshness
```

An external standard remains authoritative for its own syntax and semantics. EIGIIB remains authoritative for the meaning and boundary of EIGIIB claims.

## External specification references

Each external specification entry records:

- stable local id;
- external name;
- exact version or exact draft revision;
- publication status;
- domain;
- canonical HTTPS URI;
- reference mode;
- observation date;
- optionally, a byte-exact external snapshot identity.

M0-A3 forbids the tokens `latest`, `main`, and `master` as the declared `version`.

Reference modes are:

- `versioned-reference` — URI identifies a versioned release/specification, without claiming byte immutability;
- `exact-draft` — URI identifies an exact draft revision;
- `moving-reference` — URI may change while the catalog still records the observed version.

A `moving-reference` MAY be catalogued for research or implementation, but a profile using it MUST NOT claim `validated` interoperability.

A byte-exact external identity, when present, is:

```text
algorithm = sha256
digest = 64 lowercase hexadecimal characters
bytes = positive integer
```

This identity is distinct from the external URI and version. A profile cannot enter `validated` state without such an identity for its referenced external specification. The digest binds bytes only; authenticity and provenance still require their own evidence.

## Freshness boundary

The registry MUST declare:

```text
freshness_basis = declared-observation-date-only
```

`as_of` and `observed_on` are therefore historical registry data. The offline checker verifies date syntax and ordering only. These dates MUST NOT be interpreted as network freshness, trusted time, or proof that the reference is still the newest external revision.

## Profile lifecycle

Profiles use four states:

```text
research -> specified -> implemented -> validated
```

These states are not automatically monotone. A later external revision can invalidate an earlier mapping and require a new profile revision.

- `research`: candidate relationship only;
- `specified`: mapping and claim boundaries are defined;
- `implemented`: an adapter exists and evidence paths are declared;
- `validated`: the declared adapter/profile has executable evidence for the byte-identified external reference.

`implemented` and `validated` profiles require repository-confined evidence paths. `validated` additionally requires a byte-exact external specification identity. An `exact-semantic` mapping is permitted only in a `validated` profile with evidence.

## Mapping strengths

A mapping names one external element and one EIGIIB element and classifies its relationship.

Relations include:

```text
transports
represents
supplies-evidence
authenticates
time-binds
indexes
identifies
policy-evaluates
```

Strength is one of:

- `transport-only` — bytes/fields are carried without semantic equivalence;
- `bounded-semantic` — the profile documents a limited semantic correspondence;
- `exact-semantic` — semantic equivalence is asserted for the stated boundary and therefore requires a validated profile with evidence.

M0-A3 does not infer an exact mapping from matching names.

## Negative implication boundary

Every profile declares a non-empty `does_not_imply` set. This is normative profile data, not explanatory decoration.

Examples include:

```text
format-validity-does-not-imply-claim-truth
authenticated-envelope-does-not-imply-authorized-claim
transparency-inclusion-does-not-imply-global-consistency
timestamp-presence-does-not-imply-trusted-time
external-identity-does-not-imply-eigiib-authority
```

A profile without an explicit negative boundary is non-conformant.

## Catalog scope

The catalog currently includes:

- SLSA v1.2;
- in-toto Attestation Framework v1.2.0;
- Sigstore Bundle Format observed as v0.3.2 through a moving documentation reference;
- SPDX v3.0.1;
- the historical SCITT architecture `draft-ietf-scitt-architecture-22` research reference;
- RFC 9943, the published SCITT Architecture used by P1-A3;
- RFC 9942, the published COSE Receipts specification used by P1-A3;
- `draft-ietf-scitt-scrapi-11`, used only for the bounded P1-A3 registration transcript profile.

The draft-22 entry is retained as historical registry state and is not silently rewritten into RFC 9943. This preserves the distinction between an earlier research reference and the later published standard.

Other candidates such as TUF, SPIFFE, CycloneDX, OPA and Cedar remain eligible for later catalog/profile additions. They are not implicitly covered by the current registry.

## Profile implementation state

P1 now contains three implemented capsule stages while preserving historical and unrelated profile states.

Current bounded relationships include:

- `in-toto-aggregate-export-v1` — **implemented** by P1-A1: exports exact M0-A2 aggregate-report bytes in an in-toto `Statement/v1` while preserving the aggregate result and negative implication boundary, with no authentication envelope;
- `sigstore-p1-a1-dsse-bundle-v1` — **implemented** by P1-A2: authenticates the exact deterministic P1-A1 Statement bytes in a Sigstore Bundle v0.3 DSSE carrier against one supplied Ed25519 public key while keeping trust, authorization, transparency and trusted time separate;
- `scitt-p1-a2-registration-v1` — **implemented** by P1-A3 against RFC 9943: binds the exact P1-A2 carrier identity into a SCITT Signed Statement and consumes a Receipt as bounded registration evidence;
- `cose-receipt-rfc9162-inclusion-v1` — **implemented** by P1-A3 against RFC 9942: recomputes the RFC9162_SHA256 inclusion relation and verifies the Receipt signature relative to one supplied Transparency Service public key;
- `scrapi-registration-transcript-v1` — **implemented** by P1-A3 against exact draft SCRAPI-11: represents only the offline `POST /entries` / status / `Location` transcript and does not make the HTTP exchange the source of registration truth;
- `slsa-provenance-evidence-import-v1` — **specified**;
- `spdx-context-import-v1` — **specified**;
- `scitt-transparency-research-v1` — **research**, retained against historical draft-22.

No P1 profile is declared `validated`.

P1-A1 lacks a byte-exact in-toto external-specification snapshot in M0-A3. P1-A2 uses a Sigstore moving reference. P1-A3 uses versioned RFC references and an exact API draft reference but does not vendor byte-identical external specification snapshots into the registry. The implementation evidence therefore remains `implemented`, not `validated`.

## P1-A3 result boundary

P1-A3 intentionally keeps these conclusions separate:

```text
Signed Statement signature valid
!= trusted Issuer

Receipt signature valid
!= trusted Transparency Service

RFC9162 inclusion verified
!= global append-only consistency

receipt-bound registration evidence
!= E6 cross-view convergence
!= E11 trusted time
!= EIGIIB claim truth
```

P1-A3-H0.2 additionally requires full upstream P1-A2 authentication revalidation before the P1-A3 baseline can be accepted as a hardened positive result. This reuses the P1-A2 checker rather than reimplementing DSSE verification.

## Checker boundary

`tools/eigiib_interop_profiles_check.py` is static and offline.

It checks repository-local profile structure and boundaries, including:

- exact ids and unique references;
- version/reference-mode hygiene;
- HTTPS canonical references;
- exact-draft URI/revision coherence;
- optional SHA-256/byte-length external identities;
- validated-profile requirement for external byte identity;
- declared-observation-date-only freshness semantics;
- EIGIIB authority references against `EIGIIB.toml`;
- profile-to-spec resolution;
- profile state/evidence requirements;
- mapping vocabulary and exact-semantic evidence guard;
- non-empty negative implication boundaries;
- repository confinement for evidence paths.

It does not fetch external specifications, verify external signatures, evaluate SLSA levels, validate SPDX documents, submit SCITT statements, execute adapters, or infer external conformance.

P1-A1, P1-A2 and P1-A3 have their own executable adapter/self-checks. P1-A3 verifies its local COSE Signed Statement, RFC9162 inclusion proof and Receipt signature without contacting a Transparency Service; H0.2 composes the existing P1-A2 and P1-A3 checkers for authenticated-carrier handoff. None of these checks independently promotes an `implemented` profile to `validated`.

## External-reference freshness

The registry is a dated snapshot, not an automated assertion that each listed external version remains the newest version. Updating an external specification is an explicit repository change with review and replay.

This preserves:

```text
observed-current-at-date != permanently-latest
```
