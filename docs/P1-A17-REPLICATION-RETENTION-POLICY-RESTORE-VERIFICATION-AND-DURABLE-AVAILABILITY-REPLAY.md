# P1-A17 — Replication, Retention Policy, Restore Verification and Durable Availability Replay

## 1. Scope

P1-A17 extends the exact P1-A16 OCI publication into a named two-location recovery arrangement. The primary location is the P1-A16 GHCR manifest by digest. The recovery location is GitHub Release id `363675194` tagged `eigiib-p1-a17-recovery-v1` and targeted at exact P1-A16 commit `020cbfc29aaeccb51606021669b7f381f2ec00f6`.

The slice proves a closed object set, a signed retention-policy declaration, successful restoration from either named location at capture time, and byte identity across those restorations. It does not prove future platform enforcement, administrative deletion prevention, provider independence, resistance to correlated GitHub failure, or universal durability.

## 2. Protected object set

The protected set contains five objects: the OCI manifest, its empty configuration and the three P1-A16 content layers. Its canonical descriptor-set SHA-256 is `29811e4cbd30ff12fef18c12c61068f83de8d3c61a2be93ae8faf37f2f11b466`. Names, sizes and digests are closed; set membership by filename alone is insufficient.

## 3. Named locations

Primary: `ghcr.io/nico59000/eigiib-norm-p1-a16@sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8`.

Recovery: Release `363675194`, node `RE_kwDOTpS9_M4VrT46`, tag `eigiib-p1-a17-recovery-v1`, nine assets, prerelease true, API `immutable=false`.

Two services under one platform account are distinct readback locations but not independent providers. The conformance vocabulary therefore says `named-cross-service-two-location`, never independent replication.

## 4. Retention policy

The canonical policy has SHA-256 `63dc542b090e27dfac33961aaf81b41c95070a3969a117625e0c9d77573cb983` and is signed with Ed25519. It declares:

- minimum retention: 90 days;
- restore audit interval: 7 days;
- required location count: 2;
- deletion only after the window, a successful restore from the other location, and a revocation or supersession record.

This is an authenticated policy obligation. It is not evidence that GitHub technically prevents deletion for 90 days.

## 5. Restore replay

The primary-only route obtains an anonymous GHCR token, reads the manifest by digest and reads every blob by digest. The recovery-only route resolves the public Release and downloads each protected asset. Both routes independently reconstruct the same five descriptors and the same object-set hash.

The replay rejects missing objects, extra protected objects, size changes, digest changes, release retargeting, altered policy thresholds and any attempt to upgrade an unclaimed property.

## 6. Durable availability decision

The decision `conformant-for-observed-two-location-policy-bound-restore-window` is deliberately bounded. It records that, at `2026-08-02T02:07:24Z`, both named locations were readable, each could restore the complete set, and the signed policy described a future retention window. It does not turn the policy duration into an observed duration and does not assert that either service will remain available.

## 7. Independent routes

Four routes are required:

1. reference Python GHCR readback;
2. reference Python GitHub Release readback;
3. independent Go standard-library double readback;
4. external ORAS 1.3.2 plus GitHub CLI readback.

Route-specific diagnostics are excluded from portable equality. Bound identities, protected objects, policy, decisions and boundary are included.

## 8. Exact authorities

- P1-A16 report: `da7f10bf5055b4e965792f02bfdf4b4add32767214208ad3d05e095fa67c91f5`
- P1-A16 capsule: `4e19c204fa557e993d9357cd4e6b1bf7fbd0710ebceaf8aea8f54562cd067406`
- evidence: `ae48cd09b18f5ddad99fb6eb92a5b663fdabc39b541fcb94a7c46c33fdccf825`
- restore manifest: `dc51cf8a23fa731b3b7375a36e82d2fd1a530b52cb4711cc3b92d181fd20d13e`
- retention capsule: `5a0e738238cea382b2d1d5c4a94f3c9bc0be085fbe6dfcd4592966895854eb29`
- final capsule: `bd0e55bb7ad0e44ab7adcc7538b7718dd6f7ab938ebb0752accaf40dff379340`

## 9. Non-claims

The following remain outside the slice: platform-enforced retention, a future availability guarantee, administrative deletion prevention, independent cloud-provider replication, correlated-provider failure resistance, production release governance and universal interoperability.
