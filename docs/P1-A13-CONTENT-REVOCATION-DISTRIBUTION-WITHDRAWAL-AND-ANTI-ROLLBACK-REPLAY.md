# P1-A13 — Content Revocation, Distribution Withdrawal and Anti-Rollback Replay

## 1. Scope

P1-A13 consumes the exact P1-A12 transparency result and the exact release authority inherited from P1-A10 and P1-A11. It closes three distinct questions:

1. whether one exact release content identity is revoked by a registered authority;
2. whether that exact content is withdrawn from every channel in a closed registered fixture set;
3. whether validly signed stale or later-sequence observations can reintroduce the revoked content into accepted history.

Revocation, withdrawal, observation and remediation remain separate facts. A revoked digest is not erased, a withdrawn channel is not proof of global unavailability, and rejection of rollback does not establish that every unregistered mirror has stopped serving the bytes.

## 2. Exact inherited authority

The capsule binds the exact P1-A12 head:

```text
source commit:
286c17db08911ae22202aa30c90cac10dc3c61b8

P1-A12 report SHA-256:
7613429f8d3b771812433f5b57d64accb8148550ed9f8b71a38a97b23a45343c

P1-A12 capsule SHA-256:
12b3ca6c0ca260b3357993d65a8b4595f6cc23d4b8b26ca67dcee94e06148046

accepted transparency checkpoint root:
cbaa2980c0c57054a161f77c34a1300d86f4cd4c04a06fbcdde35ef5d4628641

trusted effective time:
1785603600
```

It also binds the exact release and authorization identities:

```text
release id:
eigiib-p1-a7-authority-1.0

release descriptor SHA-256:
1551056d0b903f3f74b0c4834c7dd60720ea651f3608c2ee3ea9b302a2b9f5ec

release archive SHA-256:
0e3ce06e9ef4f9299ad5ade9182d3924704248230d924bec656562d58287960e

recovered authorization SHA-256:
d185060877ac9f63cfb1ae93f1b56aea16307ce090977bbc3e997036ae4a5d01
```

Equality of release id, sequence or channel label alone is insufficient. Every positive or rejected observation is bound to the exact release descriptor and archive digest.

## 3. Registered content-control policy

A supplied content-control root registers one revocation authority and two fixture channels.

```text
content-control root SPKI SHA-256:
b6bfae43acb46ac6a8819634050ec024a553ea1557185d0800152398c22df5b6

revocation authority:
eigiib-p1-a13-revoker-1
SPKI SHA-256:
c2ee45e8cf01a252a5552098134a5645651326fc2b0a91d2aa951c5a070f5d1b

fixture-primary operator SPKI SHA-256:
423c0fae7cead3d40cfd6cd207f0567a510d1ac52d2e361b7f86c68a8b113233

fixture-mirror operator SPKI SHA-256:
5e6bb171b7ece2392abe944662becc9cd0ea4ac7d2a87490129118b41d2113ae
```

The root-signed policy fixes:

- policy sequence `30`;
- revocation-sequence-inclusive anti-rollback;
- continued rejection of a revoked digest even above the sequence floor;
- no accepted-history advance from a rejected observation;
- the closed channel set `fixture-primary`, `fixture-mirror`.

```text
policy payload SHA-256:
44e5ed7a899baab4a0c9e0c85c20b18e753efa12968ee84a8e357bc5cb30d0a2

policy COSE envelope SHA-256:
4943cfe4604d14d5d19bccfc06d79b7fe63d7f85663711e344dc01d0091920c2
```

## 4. Exact content revocation

The registered authority signs:

```text
revocation id:       eigiib-p1-a13-revocation-1
revocation sequence: 31
effective time:      1785607200
reason code:         security-withdrawal
replacement:         none
```

The absence of a replacement is intentional. P1-A13 does not fabricate a fixed release and does not claim vulnerability remediation.

```text
revocation payload SHA-256:
b1f3cc550cc8e808a8962d68e93efa3182b76a4da4344d9b19d73c13e606ddae

revocation COSE envelope SHA-256:
f15badfb9b3c36468f2f8af72be9fa8263731d334b8a55526079cccfe94ea9ed
```

## 5. Registered-channel withdrawal

Each registered operator signs its own withdrawal observation for the exact revoked content.

| Channel | Sequence | State | Envelope SHA-256 |
|---|---:|---|---|
| `fixture-primary` | 32 | `withdrawn-from-registered-channel` | `1d2d554a0e4fb446e3d61948fa492c4b28d4851ed83f0b894697e87cd64d56c8` |
| `fixture-mirror` | 33 | `withdrawn-from-registered-channel` | `92244495e7b5c8362ab3af31e9f74b8b78bcc6ae64caf8d784458b44b7aa03be` |

A withdrawal statement from one channel cannot substitute for another channel. Both channel identity and operator-key identity are mandatory.

## 6. Anti-rollback replay

Three observations carry valid channel-operator signatures and the exact revoked content identity. All are rejected by policy.

| Replay | Channel | Distribution sequence | Decision |
|---|---|---:|---|
| `pre-revocation-sequence` | `fixture-primary` | 30 | `rejected-below-revocation-floor` |
| `at-revocation-floor` | `fixture-mirror` | 31 | `rejected-revoked-content` |
| `newer-sequence-same-content` | `fixture-primary` | 34 | `rejected-revoked-content` |

The third case is decisive: sequence advancement does not rehabilitate a revoked digest. None of the rejected observations advances accepted history.

Accepted history remains:

```text
policy-sequence-30
  -> revocation-sequence-31
  -> fixture-primary-withdrawal-sequence-32
  -> fixture-mirror-withdrawal-sequence-33
```

## 7. Three routes

The portable replay requires equality across:

```text
reference-python-openssl
independent-go-stdlib
external-go-cose
```

The independent route implements strict JSON, deterministic CBOR, COSE_Sign1 and Ed25519 verification using the Go standard library. The external route executes the same closed semantic contract while every signed carrier is verified through `fxamacker/cbor v2.5.0` and `go-cose v1.3.0`.

Portable equality includes the exact inherited authority, content identity, policy and revocation envelopes, accepted history, registered and withdrawn channel sets, all three replay decisions, contextual results and final boundary.

## 8. Adversarial coverage

The Python mutation suite rejects changes to:

- P1-A12 source-report identity;
- release-descriptor identity;
- policy signature;
- revocation payload or signature;
- withdrawal channel or signature;
- replay decision or signed observation;
- claim boundary;
- registered channel key.

The dedicated workflow also validates the three registered schemas using a closed standard-library validator and scans the complete A13 scope for private keys.

## 9. Claim boundary

P1-A13 does not establish:

- erasure of previously published bytes;
- global unavailability across unregistered channels or mirrors;
- durable purge or retention expiry;
- vulnerability remediation or correctness of a future fixed release;
- live GitHub Release withdrawal;
- external-registry deletion;
- real-world identity or organizational control of the supplied keys;
- production release governance;
- universal interoperability.

The final portable boundary is:

```text
registered-content-revocation-distribution-withdrawal-anti-rollback-closure
```

## 10. Next natural slice

**P1-A14 — Advisory Binding, Remediation Lineage and Fixed-Release Replay**.
