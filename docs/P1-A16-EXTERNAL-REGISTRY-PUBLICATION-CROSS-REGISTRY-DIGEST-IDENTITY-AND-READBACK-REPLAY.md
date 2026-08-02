# P1-A16 — External Registry Publication, Cross-Registry Digest Identity and Readback Replay

## 1. Scope

P1-A16 extends the exact P1-A15 GitHub Release closure into one named OCI registry repository:

```text
source commit:
461412075d97d9b8a8202e89fc3a9da3b6743f1b

source GitHub Release:
Nico59000/EIGIIB-norm
release id 363652216
tag eigiib-p1-a15-live-fixture-v2

external registry:
ghcr.io/nico59000/eigiib-norm-p1-a16
tag p1-a16-fixture-v1
```

The slice proves publication and readback only for this closed repository, tag, manifest and three-layer set. It does not assert administrative immutability, retention duration, cross-provider replication, production authorization or universal interoperability.

## 2. Exact inherited P1-A15 authority

The registry publication is accepted only when it preserves all of the following exact identities:

```text
P1-A15 commit:
461412075d97d9b8a8202e89fc3a9da3b6743f1b

P1-A15 report SHA-256:
89a4fcda3b0ad8a90803b58a53c2eba485a5f8afbfe99d7c370c5b6ab248403c

P1-A15 capsule SHA-256:
f954f2fbdab0f20f18ad4d3c03a5cd23156b40e0c5c6f21bcbb2aeb776de7785

GitHub Release id:
363652216

GitHub Release tag:
eigiib-p1-a15-live-fixture-v2
```

Matching only an asset name, release tag or version string is insufficient.

## 3. OCI artifact identity

The registry object is one OCI image manifest used as a generic artifact carrier:

```text
manifest media type:
application/vnd.oci.image.manifest.v1+json

artifact type:
application/vnd.eigiib.cross-registry-release-set.v1

manifest bytes:
1493

manifest digest:
sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8
```

Its configuration descriptor is the fixed empty JSON object:

```text
media type: application/vnd.oci.empty.v1+json
size:       2
digest:     sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
```

The tag is a discoverability reference. The manifest digest is the content identity.

## 4. Closed layer set

| Layer | Bytes | OCI digest |
|---|---:|---|
| `eigiib-p1-a14-fixed-1.1.archive.txt` | 190 | `sha256:14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682` |
| `eigiib-p1-a14-fixed-1.1.descriptor.json` | 776 | `sha256:762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1` |
| `eigiib-p1-a15-live-release-manifest.json` | 1421 | `sha256:82e61dcf91be3cac21d93349e22829f27b1bdca057e813e584a1593c5a7d604b` |

For each layer `L`, conformance requires:

```text
GitHub Release API digest(L)
= SHA-256(GitHub authenticated download(L))
= SHA-256(GitHub public download(L))
= OCI descriptor digest(L)
= SHA-256(GHCR authenticated readback(L))
= SHA-256(GHCR anonymous readback(L))
= SHA-256(repository fixture(L))
```

An absent `Docker-Content-Digest` header on a blob response is not replaced by invented evidence. The verifier recomputes the digest from the returned bytes.

## 5. Publication transaction

The live probe used the OCI Distribution order:

```text
validate P1-A15 source assets
  -> upload the configuration blob
  -> upload the three content blobs
  -> publish the OCI manifest under the registered tag
  -> read manifest by tag
  -> read manifest by digest
  -> read every blob by digest
  -> list public tags
```

A manifest is not accepted before all referenced blobs exist.

## 6. Incoming readback

Two registry access contexts were captured:

```text
authenticated registry readback
anonymous public registry readback
```

Both returned the registered manifest bytes and all registered layer bytes. Anonymous tag listing contained `p1-a16-fixture-v1`.

The captured observation time is:

```text
2026-08-02T00:23:59Z
```

This timestamp records the observation. It is not a retention guarantee.

## 7. Tag and digest separation

The following statements are deliberately distinct:

```text
tag-to-manifest binding at capture time      conformant
manifest content identity by digest          conformant
future tag immutability                      not claimed
future manifest availability                 not claimed
administrative deletion prevention           not claimed
```

A later tag mutation would be detected because the tag route would no longer return the registered manifest digest. The digest route remains the canonical identity check, subject to current registry availability.

## 8. Independent verifier routes

The required routes are:

```text
reference-python-urllib
independent-go-stdlib
external-oras-cli
```

The Python and Go routes implement anonymous OCI Distribution readback independently. The external route uses ORAS CLI `v1.3.2` to fetch the manifest by tag and digest, fetch each blob by digest and enumerate repository tags.

Portable equality excludes route-specific diagnostics and executable paths. It includes the inherited A15 identities, registry coordinates, manifest identity, configuration, layer set, public tag set, decisions and final boundary.

## 9. Adversarial replay

The Python suite rejects mutations of:

- source A15 commit, Release id and Release tag;
- source asset membership, id and digest;
- registry host, repository and tag;
- OCI manifest digest, size, media type and artifact type;
- configuration digest;
- layer membership, order, media type and digest;
- public registry byte identity;
- public tag listing;
- retention, immutability and production claim expansion;
- final boundary;
- capsule signature.

Rejected observations do not replace the frozen evidence.

## 10. Signed capsule

The Ed25519 capsule binds:

```text
sequence 60
P1-A15 commit, report and capsule
GitHub Release id and tag
registry repository and tag
evidence SHA-256
OCI manifest SHA-256
portable final boundary
```

Only the public key is stored in the repository.

## 11. Closure decision

```text
exact_p1_a15_binding                  conformant
external_registry_publication         conformant-for-named-ghcr-oci-repository-scope
authenticated_registry_readback       conformant
public_registry_readback              conformant
cross_registry_digest_identity        conformant-for-closed-three-asset-set
tag_to_manifest_binding               conformant-at-capture-time
three_route_equivalence               conformant

registry_administrative_immutability  not-claimed
durable_retention                     not-claimed
cross_provider_replication            not-claimed
production_authorization              not-claimed
universal_interoperability            not-claimed

overall_result                        conformant
```

Portable final boundary:

```text
named-ghcr-oci-publication-cross-registry-digest-readback-closure
```

## 12. Next boundary

P1-A17 must add independently testable replication, retention intervals, loss simulation and restore replay. Current public availability cannot substitute for that future durability proof.
