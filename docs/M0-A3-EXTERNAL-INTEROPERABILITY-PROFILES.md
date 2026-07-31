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
moving external reference != immutable specification snapshot
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
- observation date.

M0-A3 forbids the tokens `latest`, `main`, and `master` as the declared `version`.

Reference modes are:

- `immutable-version` — URI identifies a versioned release/specification;
- `exact-draft` — URI identifies an exact draft revision;
- `moving-reference` — URI may change while the catalog still records the observed version.

A `moving-reference` MAY be catalogued for research, but a profile using it MUST NOT claim `validated` interoperability.

## Profile lifecycle

Profiles use four states:

```text
research -> specified -> implemented -> validated
```

These states are not automatically monotone. A later external revision can invalidate an earlier mapping and require a new profile revision.

- `research`: candidate relationship only;
- `specified`: mapping and claim boundaries are defined;
- `implemented`: an adapter exists and evidence paths are declared;
- `validated`: the declared adapter/profile has executable evidence for the pinned external reference.

`implemented` and `validated` profiles require repository-confined evidence paths. `validated` additionally requires every mapping to avoid an unvalidated `exact-semantic` assertion.

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

## Initial catalog scope

The initial M0-A3 catalog intentionally starts with external references whose current revision can be represented explicitly:

- SLSA v1.2;
- in-toto Attestation Framework v1.2;
- SPDX v3.0.1;
- SCITT architecture draft-ietf-scitt-architecture-22.

Other candidates such as Sigstore, TUF, SPIFFE, CycloneDX, OPA and Cedar remain eligible for later catalog/profile additions. They are not implicitly covered by the first M0-A3 registry.

## Initial profiles

The first registry is declarative only. It specifies bounded relationships for:

- exporting an M0-A2 aggregate report as an in-toto-attestation predicate payload;
- consuming SLSA provenance as typed external evidence without promoting it to an EIGIIB truth claim;
- consuming SPDX 3.0.1 data as artifact/context metadata without making SPDX the E3 provenance authority;
- studying SCITT draft-22 as a transparency transport for signed statements without replacing E5/E6 semantics.

No adapter implementation or external verification is claimed by these initial profile states.

## Checker boundary

`tools/eigiib_interop_profiles_check.py` is static and offline.

It checks repository-local profile structure and boundaries, including:

- exact ids and unique references;
- version/reference-mode hygiene;
- HTTPS canonical references;
- exact-draft URI/revision coherence;
- EIGIIB authority references against `EIGIIB.toml`;
- profile-to-spec resolution;
- profile state/evidence requirements;
- mapping vocabulary and exact-semantic evidence guard;
- non-empty negative implication boundaries;
- repository confinement for evidence paths.

It does not fetch external specifications, verify external signatures, evaluate SLSA levels, validate SPDX documents, submit SCITT statements, execute adapters, or infer external conformance.

## External-reference freshness

The registry is a dated snapshot, not an automated assertion that each listed external version remains the newest version. Updating an external specification is an explicit repository change with review and replay.

This preserves:

```text
observed-current-at-date != permanently-latest
```
