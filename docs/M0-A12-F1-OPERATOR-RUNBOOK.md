# M0-A12-F1 operator runbook

## Preconditions

Do not assemble or bind a package until the complete M0-A12 evidence tree has
been produced by the independent custodians and observer. Provider-side lock
operations must already be complete and independently reviewed.

For Amazon S3, deletion evidence must target the protected version ID. A simple
object delete can create a delete marker and is not a permanent version-deletion
test. For Cloud Storage, the locked bucket-retention policy is irreversible and
must have been approved before locking.

## 1. Assemble the payload

Create the exact payload tree:

```text
payload/evidence/m0-a12/...
payload/evidence/m0-a12-f1/operator-approval.json
```

The M0-A12 subtree must contain all required attestations, channel records,
diversity matrix, campaign anchor, allowed signers and sequence-1 observation.

## 2. Approve the evidence set

Compute the canonical evidence-set inventory digest. Insert it into
`operator-approval.json`, then sign the same approval bytes three times under the
F1 approval namespace:

```text
operator-approval.json.primary.sig
operator-approval.json.secondary.sig
operator-approval.json.observer.sig
```

Private keys remain outside the package.

## 3. Build and sign the manifest

List every payload file exactly once, sorted by path. Compute `payloadSetDigest`,
`evidenceSetDigest` and `manifestDigest`. Sign `manifest.json` as
`independent-observer-primary` under the F1 ingress namespace.

The signature envelope must record `signedPayloadPath = "manifest.json"`.
Approval envelopes must record
`signedPayloadPath = "operator-approval.json"`.

## 4. Verify without mutation

```bash
python tools/eigiib_m0_a12_f1_ingress.py verify evidence-package.tar
```

A successful result is `verified-exact-closed-package`.

## 5. Stage in isolation

```bash
python tools/eigiib_m0_a12_f1_ingress.py stage \
  evidence-package.tar /secure/staging/m0-a12-f1 \
  --verified-at 2026-08-04T12:00:00Z
```

Review the staged tree and receipt. Staging is not repository binding.

## 6. Bind with exact confirmation

From a clean worktree at the exact F1 authority head:

```bash
python tools/eigiib_m0_a12_f1_ingress.py bind \
  evidence-package.tar . \
  --confirm BIND-M0-A12-F1-EXTERNAL-EVIDENCE \
  --verified-at 2026-08-04T12:00:00Z
```

The command refuses pre-existing evidence roots and never overwrites files.

## 7. Replay preclosure

```bash
python tools/eigiib_m0_a12_f1_check.py . \
  --output m0-a12-f1-preclosure-report.json
```

Expected state after valid binding and before certification:

```text
structural_result = conformant-preclosure
closure_result = external-evidence-bound-closure-certificate-pending
htntLabel = NT
```

Any finding requires quarantine and investigation. Do not generate a certificate.

## 8. Generate the point-in-time certificate

After manual review of the bound evidence and preclosure report:

```bash
python tools/eigiib_m0_a12_f1_check.py . \
  --write-closure-certificate \
  --closed-at 2026-08-04T12:15:00Z
```

Then require closure:

```bash
python tools/eigiib_m0_a12_f1_check.py . --require-closed
```

A zero exit status is necessary but not sufficient. The exact evidence commit
must also close every workflow successfully and remain under review.

## Abort and quarantine

Abort binding or closure when any path is unsafe, any digest differs, any
signature fails, any approval signer is missing, any target exists, M0-A12 is
not `T`, or an evidence reference cannot be independently resolved.

Quarantine the original archive byte-for-byte. Do not repair it in place.
