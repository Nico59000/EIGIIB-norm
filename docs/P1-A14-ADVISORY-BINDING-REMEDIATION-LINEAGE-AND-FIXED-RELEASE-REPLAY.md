# P1-A14 — Advisory Binding, Remediation Lineage and Fixed-Release Replay

## 1. Scope

P1-A14 consumes the exact P1-A13 revocation result. It closes four linked but distinct questions in one registered fixture context:

1. whether an advisory binds the exact release content revoked by P1-A13;
2. whether a registered remediation authority binds that advisory and revoked predecessor to one exact successor;
3. whether the supplied successor descriptor, archive and change-set identities agree with the signed lineage;
4. whether replay accepts only the exact fixed release while preserving rejection of the revoked predecessor and every substituted lineage.

An advisory, a signed remediation lineage, a fixed artifact identity and independent proof that a real-world defect has disappeared are not interchangeable facts. P1-A14 establishes the registered fixture chain and its replay behavior. It does not claim production release authorization, live publication or an external vulnerability assignment.

## 2. Exact P1-A13 source authority

The capsule binds the exact P1-A13 head and outputs:

```text
source commit:
077634971f2c16f3f74eb4c6c5b75aa7099bee55

P1-A13 report SHA-256:
7cbae1b7b686149b91bcea58d365e0700155185e78ac213913a0f3f07943e70b

P1-A13 capsule SHA-256:
fb596478e6cad8fe4c8db9e95d54f138cb37f9452a32d938e3d2796ab49240f5

P1-A13 revocation envelope SHA-256:
f15badfb9b3c36468f2f8af72be9fa8263731d334b8a55526079cccfe94ea9ed

source boundary:
registered-content-revocation-distribution-withdrawal-anti-rollback-closure
```

The exact predecessor remains:

```text
release id:
eigiib-p1-a7-authority-1.0

release descriptor SHA-256:
1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec

archive SHA-256:
0e3ce06e9ef4f9299ad5ade9182d3924704248230d924bec656562d58287960e

revocation id:
eigiib-p1-a13-revocation-1

revocation sequence:
31
```

The full accepted P1-A13 history is inherited as an ordered prefix. Equality of a release id or version label without the exact descriptor and archive digests is insufficient.

## 3. Registered remediation policy

A supplied remediation-control root registers three non-substitutable roles:

```text
remediation-control root SPKI SHA-256:
627ad5f7cb03945da559d9d11a4a5eda4f9589a39340bc1757f7dff1885a1746

advisory authority:
eigiib-p1-a14-advisory-issuer-1
SPKI SHA-256:
a1cde5f4584bd967d17e0ecaf39348673cb86e50424e6a31f423e7c13a1b3b55

remediation authority:
eigiib-p1-a14-remediator-1
SPKI SHA-256:
d479ba9e95360bdea9f75540263ae69ba3b362214277b5aefab2bb88bed6f2db

fixed-release signer:
eigiib-p1-a14-fixed-release-signer-1
SPKI SHA-256:
764d61c07d9ee011abfd615593bfeb387eca87ef261696ad70a94ce6cbb26f19
```

The root-signed policy fixes sequence `40` and requires:

- exact advisory binding to the P1-A13 revoked content;
- exact advisory and remediation envelope bindings in every fixed-release candidate;
- fixed-release sequence floor `43`;
- continued rejection of the revoked predecessor;
- exact descriptor and archive equality for a reused release id;
- no accepted-history advance from an exact idempotent replay.

```text
policy payload SHA-256:
dc5e3f1083d2f8f4a5583f7306a86fa61b71e1daa51635442622fec8609e9f62

policy COSE envelope SHA-256:
9c56c9e91a6f47da10b2a4c53a3b339dbb5cf8f33d2e3fcbc6c7f391c238fdf0
```

## 4. Advisory binding

The registered advisory authority signs:

```text
advisory id:
EIGIIB-SA-FIXTURE-2026-0001

advisory sequence:
41

vulnerability id:
EIGIIB-FIXTURE-VULN-2026-0001

status:
confirmed-for-fixture-scope

severity:
high
```

Its affected-content carrier is the exact P1-A13 revoked predecessor and its source-revocation field is the exact P1-A13 revocation envelope identity.

```text
advisory payload SHA-256:
d4c7f9778ac6f8a655f0627dcad9aea4422571a696117928552f7e2c9539c70f

advisory COSE envelope SHA-256:
623be5875f96555baf849d4ffa69d0cff531920b18262165d4f3e271a4eca084
```

The vulnerability identifier belongs to the closed fixture namespace. P1-A14 does not present it as an externally assigned CVE or other public advisory identifier.

## 5. Exact remediation lineage

The registered remediation authority signs sequence `42` and binds simultaneously:

- the exact advisory envelope;
- the exact P1-A13 revocation envelope;
- the exact revoked predecessor content;
- the exact fixed successor content;
- the supplied fixed-release descriptor;
- the supplied change-set artifact.

```text
remediation id:
eigiib-p1-a14-remediation-1

remediation class:
replacement-release

change-set SHA-256:
f8e224101e1cd2b732986d4db4feb083f049c5b59375d55ca94152ea042937ea

remediation payload SHA-256:
80461abbf3fb39caa8679663d059ffcbace1ba44f82abcd18899400f35075520

remediation COSE envelope SHA-256:
3400bae849ae524f2dc1c6356806bc1292545c44960f02b4d6d424829cee7acf
```

The lineage is contextual evidence for the registered fixture. The signature and exact artifact identities do not independently prove semantic defect removal in every execution environment.

## 6. Fixed release

The fixed-release signer binds sequence `43` to:

```text
fixed release id:
eigiib-p1-a14-fixed-1.1

version:
1.1.0

fixed descriptor SHA-256:
762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1

fixed archive SHA-256:
14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682
```

The descriptor itself binds the archive, change-set, advisory id and exact predecessor.

```text
fixed-release payload SHA-256:
891ee2f675a27553b25ee7ce91bdd53bb369638f0193d60d294317d4be86549d

fixed-release COSE envelope SHA-256:
2cc4d3308628ac77b66c26620cdc31c22c2cbccd8712e188ba3ea359ecec9c5e
```

Acceptance of this fixture release does not confer production release authorization and does not imply live publication.

## 7. Fixed-release replay

Five validly signed candidates are replayed:

| Replay | Sequence | Decision | History effect |
|---|---:|---|---|
| `idempotent-fixed-release` | 43 | `accepted-idempotent-fixed-release-replay` | none |
| `revoked-predecessor` | 44 | `rejected-revoked-predecessor` | none |
| `same-id-altered-archive` | 45 | `rejected-fixed-release-content-substitution` | none |
| `wrong-advisory-lineage` | 46 | `rejected-advisory-lineage-mismatch` | none |
| `below-fixed-release-floor` | 42 | `rejected-below-fixed-release-floor` | none |

The exact fixed release is accepted idempotently without adding a duplicate history node. A greater sequence cannot rehabilitate the revoked predecessor, and a familiar release id cannot conceal a different archive digest.

Accepted history is therefore exactly:

```text
policy-sequence-30
  -> revocation-sequence-31
  -> fixture-primary-withdrawal-sequence-32
  -> fixture-mirror-withdrawal-sequence-33
  -> remediation-policy-sequence-40
  -> advisory-sequence-41
  -> remediation-sequence-42
  -> fixed-release-sequence-43
```

## 8. Three verification routes

Portable equality is required across:

```text
reference-python-openssl
independent-go-stdlib
external-go-cose
```

The independent route implements strict JSON, deterministic CBOR, COSE_Sign1 and Ed25519 verification with the Go standard library. The external route verifies every signed carrier through the locked `fxamacker/cbor v2.5.0` and `go-cose v1.3.0` libraries.

Portable equality includes all inherited identities, signed envelope hashes, predecessor and successor content, accepted history, five replay decisions, contextual results and the final boundary.

## 9. Adversarial coverage

The Python suite contains sixteen tests. It rejects mutations of:

- the P1-A13 report or capsule identity;
- the remediation policy signature;
- advisory affected content or signature;
- remediation predecessor, successor or signature;
- fixed descriptor binding or fixed-release signature;
- replay decisions, signed candidates or idempotent sequence;
- the claim boundary;
- registered authority-key identity.

The positive capsule already contains independently signed negative candidates for revoked-predecessor replay, same-id archive substitution, wrong advisory lineage and a below-floor fixed release.

The dedicated workflow additionally validates three closed schemas and scans the complete P1-A14 artifact scope for private keys.

## 10. Claim boundary

P1-A14 does not establish:

- an external vulnerability or advisory assignment;
- independent semantic proof that the defect is absent from all executions;
- production release authorization;
- live GitHub Release publication;
- external-registry publication;
- global availability or persistence;
- real-world identity or organizational control of supplied fixture keys;
- universal interoperability.

It also does not un-revoke the predecessor. The P1-A13 content remains rejected even after the fixed successor is accepted.

The final portable boundary is:

```text
registered-advisory-remediation-lineage-fixed-release-replay-closure
```

## 11. Next natural slice

**P1-A15 — Live GitHub Release, Immutable Asset Identity and API Readback Replay**.
