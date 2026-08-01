# P1-A15 — Live GitHub Release, Immutable Asset Identity and API Readback Replay

## 1. Purpose

P1-A15 crosses the repository boundary for the first time with a real public GitHub Release. It does not replace the internal fixed-release identity established by P1-A14. It exports that exact identity into a bounded external carrier, then imports the observable result through two readback channels.

The slice establishes:

- one explicit lightweight Git tag on the exact P1-A14 commit;
- one public GitHub prerelease attached to that tag;
- a closed set of three release assets;
- exact asset identity through GitHub API digests and recomputed SHA-256 values;
- authenticated REST readback and unauthenticated public download readback;
- an evidence packet and a signed registrar capsule binding the external observation back to the internal source.

## 2. Perimeter map

The relevant carriers are distinct.

| Perimeter | Carrier | Authority inside the carrier | P1-A15 status |
|---|---|---|---|
| Internal normative core | P1-A14 report, capsule, fixed archive and descriptor | registered P1-A14 evidence | inherited and hash-bound |
| Repository control | exact commit, workflow and branch state | repository Git objects and CI | controlled publisher route |
| GitHub publication | tag, Release object, asset metadata and API response | GitHub repository service | live fixture established |
| Public consumer | browser download URLs and returned bytes | unauthenticated public endpoint | independently replayed |
| External registry | package or artifact registry outside GitHub Releases | external registry operator | not established |
| Durability | retention, replication, restore and long-term availability | storage and recovery operators | not established |

No row is identified with another row merely because it contains the same release name or digest.

## 3. Inter-relations of P1-A7 through P1-A15

The slices form a dependency chain, not a single undifferentiated claim.

| Slice | Closed object | What it does not imply by itself |
|---|---|---|
| P1-A7 | frozen authority corpus | live publication |
| P1-A8 | exact distribution bundle | authenticated release governance |
| P1-A9 | authenticated release and supersession | delegated authorization |
| P1-A10 | delegated threshold authorization and revocation | trusted effective time |
| P1-A11 | trusted timestamp and validity windows | transparency consistency |
| P1-A12 | transparency trust, witness quorum and equivocation replay | content withdrawal |
| P1-A13 | content revocation, two-channel withdrawal and anti-rollback | fixed successor correctness |
| P1-A14 | advisory binding, remediation lineage and fixed-release identity | live GitHub publication |
| P1-A15 | live GitHub Release and exact readback | external registry publication or durable retention |

The P1-A15 positive result therefore has the form

```text
P1-A14 exact fixed identity
  + explicit Git tag at the exact A14 commit
  + published GitHub Release
  + closed asset set
  + authenticated API readback
  + public byte readback
  = bounded live GitHub publication closure
```

## 4. Controlled outgoing crossing

Let `c14` be the exact P1-A14 commit, `t15` the canonical tag, `G15` the GitHub Release, and `A15` its asset set.

The outgoing transition is ordered:

```text
validate(c14)
  -> create-tag(t15, c14)
  -> create-draft(G15, t15)
  -> upload(fixed archive)
  -> upload(fixed descriptor)
  -> upload(binding manifest)
  -> verify API digests
  -> publish(G15)
```

The draft is a transaction boundary. Publication is forbidden before the complete asset set and its manifest are present.

## 5. Controlled incoming crossings

Two incoming routes are required after publication.

### Authenticated route

The repository token reads:

- the Release by stable repository API identity;
- the exact tag reference;
- each asset metadata object;
- each asset byte stream through the asset API endpoint.

### Public route

An unauthenticated consumer reads:

- the published Release by tag;
- each asset through its public browser download URL.

The two channels are not interchangeable. Their equality is a tested conclusion for the exact fixture, not a presupposition.

## 6. Exact invariants

For every asset `x` in the declared closed set:

```text
GitHubAPI.digest(x)
  = SHA256(authenticated-download(x))
  = SHA256(public-download(x))
  = manifest.digest(x)
```

The tag invariant is:

```text
peel(t15) = c14
```

The asset-set invariant is:

```text
Assets(G15) = {
  eigiib-p1-a14-fixed-1.1.archive.txt,
  eigiib-p1-a14-fixed-1.1.descriptor.json,
  eigiib-p1-a15-live-release-manifest.json
}
```

A matching release name, tag spelling, asset filename or version string is insufficient if any identifier, size, digest or byte stream differs.

## 7. Immutable identity versus platform immutability

P1-A15 uses two separate predicates.

1. **Immutable asset identity** is content-addressed: an asset is the declared object only when its SHA-256 digest and byte stream match the manifest and both readback channels.
2. **Platform immutability enforcement** is a GitHub repository feature reported by the Release API. It prevents edits or deletion only when enabled by the platform.

The first predicate can be conformant while the second is false or unavailable. P1-A15 records the API field without promoting it into a stronger claim.

## 8. Transition termination and replay stability

The publication protocol has a finite ordered phase index. Every successful nonterminal transition strictly increases the phase and no transition returns to an earlier phase. A failure stops the route and leaves no conformant result.

The readback phase is idempotent: repeated successful reads do not alter the accepted history. A later API response is accepted only if the portable projection remains identical to the frozen evidence.

## 9. Three routes

The final replay uses:

```text
reference-python-urllib
independent-go-stdlib
external-gh-cli
```

All routes must emit the same portable projection over:

- repository and exact P1-A14 commit;
- release id, tag and name;
- peeled tag commit;
- publication flags and platform immutable field;
- closed asset names, ids, sizes and digests;
- contextual decisions and final boundary.

## 10. Negative coverage

The mutation suite rejects at least:

- source P1-A14 commit, report or capsule substitution;
- release id, tag or name substitution;
- draft or wrong prerelease state;
- tag target or tag type substitution;
- missing, extra or renamed asset;
- API, authenticated-download or public-download digest divergence;
- manifest target or source-asset substitution;
- platform immutable decision inconsistent with the API field;
- production-authorization claim expansion;
- boundary or registrar-signature substitution.

## 11. Claim boundary

P1-A15 establishes a real public GitHub Release for the exact fixture and exact current readback. It does not establish:

- production release authorization;
- an external package or artifact registry publication;
- platform immutability unless the GitHub API reports it for this Release;
- durable retention, replication or restore;
- global availability;
- real-world identity of every repository operator;
- universal interoperability.

The portable closure is:

```text
canonical-live-github-release-asset-identity-api-readback-closure
```

## 12. Next boundary

The next natural slice is **P1-A16 — External Registry Publication, Cross-Registry Digest Binding and Readback Replay**.
