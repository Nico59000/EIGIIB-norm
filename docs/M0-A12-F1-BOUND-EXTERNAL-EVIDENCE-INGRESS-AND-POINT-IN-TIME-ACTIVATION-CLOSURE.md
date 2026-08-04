# M0-A12-F1 — Bound External Evidence Ingress and Point-in-Time Activation Closure

## 1. Purpose

M0-A12-F1 defines the only admissible route by which live external evidence may
cross from separately administered provider and observer domains into the M0-A12
authority tree. It closes the gap between evidence acquisition and a repository
claim by binding an exact signed package, replaying the inherited verifier and
issuing a derived point-in-time closure certificate.

The tranche is additive and fail-closed. It does not create cloud accounts,
credentials, buckets, retention locks, observer schedules or signatures. Those
remain external acts performed by independent authorities.

## 2. Exact source authority

The ingress protocol is bound to M0-A12 head
`e6661993924aed4d0185df48cf0b8587b2e0abf3` and its M0-A11 ancestor
`148e3e9d06ce791b90e2816d77f5045ebeac0793`.

A package bound to another source head is rejected even when its files are
otherwise well formed.

## 3. Closed package model

The package is a tar-family archive rooted at `m0-a12-f1-package/` with exactly:

```text
m0-a12-f1-package/
├── manifest.json
├── manifest.json.sig
└── payload/
    └── evidence/
        ├── m0-a12/...
        └── m0-a12-f1/
            ├── operator-approval.json
            ├── operator-approval.json.primary.sig
            ├── operator-approval.json.secondary.sig
            └── operator-approval.json.observer.sig
```

The manifest lists every payload file exactly once in lexicographic order. Each
entry binds path, byte count, SHA-256, role and media type. Unlisted members and
missing listed members are both rejected.

The manifest carries two independent inventory digests:

- `payloadSetDigest`, covering every payload entry;
- `evidenceSetDigest`, covering only `payload/evidence/m0-a12/**`.

The manifest is signed by the independent observer under the domain-separated
namespace `eigiib-m0-a12-f1-ingress@eigiib.example`.

## 4. Three-domain approval

The operator approval binds the exact M0-A12 source head and evidence-set digest.
It records the decision
`approve-exact-binding-and-point-in-time-closure-attempt` and an explicit
acknowledgement that irreversible provider actions were performed outside this
repository.

The same approval bytes must be signed independently by:

1. `external-preservation-primary`;
2. `external-preservation-secondary`;
3. `independent-observer-primary`.

These signatures use the namespace
`eigiib-m0-a12-f1-approval@eigiib.example` and the M0-A12 allowed-signers record.

## 5. Archive safety

The ingress implementation never invokes `extractall`. It preflights every tar
member and writes accepted regular files itself. It rejects:

- absolute, empty, dotted, parent-escaping or backslash paths;
- symbolic links and hard links;
- devices, FIFOs and other non-regular members;
- duplicate member names;
- members outside the package root;
- excessive member counts or expanded sizes;
- destination collisions and races.

The default limits are 512 members, 128 MiB per member and 512 MiB expanded.

## 6. Binding receipt

`verify` proves the package without mutation. `stage` writes the payload into an
isolated destination and emits a `verified-and-staged-not-bound` receipt.

`bind` requires the exact confirmation string
`BIND-M0-A12-F1-EXTERNAL-EVIDENCE`, an M0-A12 authority tree, and absent target
evidence roots. It writes the payload, preserves the signed package manifest and
emits a `verified-and-bound` receipt. Overwrite is forbidden.

The receipt binds:

- archive SHA-256;
- manifest digest;
- payload-set digest;
- evidence-set digest;
- entry count;
- verification time;
- receipt digest.

## 7. Closure replay

After binding, the F1 checker:

1. revalidates the static F1 authorities and self-excluding freeze;
2. verifies the preserved manifest and observer signature;
3. proves the bound tree is the closed manifest inventory;
4. verifies the bound receipt;
5. verifies all three approval signatures;
6. invokes the inherited M0-A12 evaluator on the bound tree;
7. requires M0-A12 result `T`, no findings and the exact point-in-time activation result.

When these gates are satisfied but no closure certificate exists, the dynamic
state is `NT`: external evidence is valid, but local closure certification is
unfinished.

The certificate generator then binds the receipt, manifest, evidence set and
canonical M0-A12 report. A subsequent replay reaches `T` only if the certificate
is exact.

## 8. HT+NT interpretation

The carrier remains the fixed square:

```text
F  = local gate invalid, no admissible external validation
NF = local gate valid, signed bound package absent
NT = external evidence bound and valid, local closure certificate incomplete
T  = bound evidence valid, inherited M0-A12 is T, closure certificate valid
```

No off-diagonal state may be collapsed into binary success.

## 9. Claim boundary

M0-A12-F1 closure states only that, at the certificate time, the exact external
evidence set was bound and M0-A12 verified the first signed observation across
the two immutable channels.

It does not establish:

- future observation continuity;
- future absence of lapse;
- survival after account termination;
- universal control-domain independence;
- long-horizon preservation;
- E17 readiness or adoption.

## 10. Current state

No external package, bound evidence, receipt or certificate is present in the
initial tranche. Its correct state is therefore `NF` with closure result
`external-evidence-pack-absent`.
