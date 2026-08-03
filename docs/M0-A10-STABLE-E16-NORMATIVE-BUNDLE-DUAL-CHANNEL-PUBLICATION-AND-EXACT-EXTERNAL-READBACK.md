# M0-A10 — Stable E16 Normative Bundle, Dual-Channel Publication and Exact External Readback

## 1. Purpose

M0-A10 performs the bounded promotion authorized by M0-A9. It constructs one deterministic archive from the exact stable E16 source, binds that archive to a signed manifest, publishes the same four-object set through GitHub Release and one named OCI repository, and restores every object through authenticated and public routes.

The positive state is:

```text
bounded-external-publication-and-readback-verified
```

This state is an observation about the named objects and routes at the captured operation. It is not a claim about future availability or indefinite durability.

## 2. Exact inherited authority

The operation consumes two exact heads without rewriting either one:

```text
M0-A9 governance head:
af028b4b99c216cffb7764571e3e97db29d76635

stable E16 branch:
stable/eigiib-e16-1.0

stable E16 head:
fc3f8402bfbe447227f5777bad92b620c7bcb350

profile:
EIGIIB-E16-1.0
```

M0-A9 remains the owner of promotion readiness. E16-A5 remains the owner of stable E16 closure. M0-A10 owns only the new bundle construction, publication, readback and restore evidence.

## 3. Deterministic bundle

The bundle recipe is:

```text
git archive --format=tar --prefix=eigiib-e16-1.0/ <exact-commit>
  | gzip -n -9
```

For the exact stable E16 head, the resulting object is:

```text
name:    eigiib-e16-1.0-stable-bundle.tar.gz
bytes:   985664
sha256:  96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde
```

The recipe excludes wall-clock gzip metadata. Its determinism is bounded to the exact Git tree, Git implementation behavior and declared recipe.

## 4. Signed manifest boundary

The canonical manifest is 1,058 bytes with SHA-256:

```text
25c04438df49d7261cf9814142dc0dd575b278ba65e05bc244b13b35d16407a9
```

It binds the bundle identity, exact source head, stable branch and profile revision. It is signed with Ed25519. The corresponding public key is published with the bundle.

The key boundary is explicit:

```text
ephemeral-publication-integrity-key-not-production-release-authority
```

Signature validity proves integrity under that captured public key. It does not establish a trusted production release signer, threshold release authorization or organizational identity.

## 5. GitHub Release channel

The named Release is:

```text
repository: Nico59000/EIGIIB-norm
release id: 364532554
tag:        eigiib-m0-a10-e16-stable-v1
draft:      false
prerelease: true
assets:     4
immutable:  false
```

The four assets are the bundle, signed manifest, signature and public key. Authenticated API readback and unauthenticated public download readback returned the same bytes for all four assets.

The Release is a bounded publication carrier. Its existence does not imply administrative immutability or future retention.

## 6. OCI channel

The named OCI object is:

```text
repository:      ghcr.io/nico59000/eigiib-norm-p1-a16
tag:             m0-a10-e16-stable-v1
manifest digest: sha256:8d3fba5d596d668ea000a768d524e35003e08f95162b633d8af7922449b13c88
manifest bytes:  1557
```

The manifest contains exactly four layers corresponding to the four Release assets. Authenticated and public registry routes returned the same manifest and layer bytes.

The tag is a discovery reference. The manifest digest is the captured OCI content identity. Future tag stability and future blob availability are not inferred.

## 7. Four-route restore closure

The required routes are:

1. GitHub Release authenticated;
2. GitHub Release public;
3. OCI registry authenticated;
4. OCI registry public.

For each route and each object:

```text
observed bytes = canonical bytes
observed SHA-256 = canonical SHA-256
```

Cross-channel closure requires equality for the bundle, manifest, signature and public key. A positive result is denied if any route is unavailable, any asset is missing, any byte count differs or any digest differs.

## 8. Operational cleanup record

The two M0-A9 cleanup names were technical branches, not pull requests. Their branch refs had already been deleted, which makes a compare URL containing those refs return HTTP 404 by design.

M0-A10 completed the remaining purge by deleting their retained Actions runs:

```text
ops/m0-a9-actions-cleanup-once  -> run 30858788022
ops/m0-a9-actions-cleanup-exact -> run 30858972197
```

The recorded method is:

```text
branch ref:
DELETE /repos/{owner}/{repo}/git/refs/heads/{encoded-ref}

workflow run:
DELETE /repos/{owner}/{repo}/actions/runs/{run_id}

PR verification:
GET /search/issues with is:pr and exact branch names
```

No matching pull request existed. After ref deletion, a 404 from the compare endpoint is the expected proof that the compared ref no longer exists; GitHub has no separate compare object to delete.

## 9. Claim boundary

M0-A10 establishes only:

- current publication through the two named channels;
- current authenticated and public readback;
- exact restore through the four named routes;
- cross-channel byte identity;
- exact binding to stable E16 head `fc3f8402...`.

M0-A10 does not establish:

- production release authorization;
- future availability;
- continuous retention;
- indefinite durability;
- provider independence;
- correlated-failure resistance;
- administrative deletion prevention;
- universal interoperability;
- E17 adoption.

E17 remains `not-ready-for-adoption` until the external evidence classes identified by M0-A9 are obtained.
