# M0-A12 — External Immutable Channel Activation, Independent Attestation and First Signed Observation

## 1. Authority and scope

M0-A12 is an additive successor to M0-A11 at exact head
`148e3e9d06ce791b90e2816d77f5045ebeac0793`. It consumes the stable E16 bundle identity already fixed by
M0-A10 and does not rewrite any historical branch, tag, release, registry
object or preservation authority.

The slice has two distinct deliverables:

1. a complete activation and verification harness that can be reviewed and
   replayed without external credentials;
2. a point-in-time activation authority that may exist only after real
   external evidence has been supplied and independently verified.

The present baseline establishes the first deliverable. It intentionally
retains the second as pending.

## 2. Typed internal/external decision protocol

The operational decision carrier is the fixed Boolean square `S4` with
coordinates:

- internal coordinate: local harness, schema, digest, signature and transition
  validation;
- external coordinate: live evidence originating from the bound external
  custodians and observer.

The labels are:

| Label | Internal | External | M0-A12 meaning |
|---|---:|---:|---|
| `F` | 0 | 0 | local authority invalid and external evidence absent or invalid |
| `NF` | 1 | 0 | harness valid; live external evidence absent |
| `NT` | 0 | 1 | external material present but local validation fails |
| `T` | 1 | 1 | both local and external validation succeed |

Only `T` authorizes point-in-time closure. `NF` and `NT` are suspended states
and may not be collapsed into a binary success. The evaluation context is
fixed for the complete run; switching between incompatible decision orders is
forbidden.

The transition measure is the finite set of missing obligations. Every
successful transition must remove at least one obligation without reintroducing
a previously discharged obligation. This provides an explicit termination
measure. Critical transition pairs are tested by mutation vectors.

## 3. Selected implementation profiles

The profiles are selected as implementation targets, not as account bindings.

### 3.1 Primary preservation profile

`aws-s3-object-lock-compliance` requires:

- a general-purpose S3 bucket with Object Lock enabled;
- versioning and a version-specific object identity;
- `COMPLIANCE` retention;
- retention-mode and retain-until readback;
- deletion denial for an authorized deleter and a privileged administrator;
- exact version-specific object readback;
- an exported audit trail.

The adapter refuses execution unless the operator supplies an explicit
irreversible-lock confirmation.

### 3.2 Secondary preservation profile

`gcp-cloud-storage-bucket-lock` requires:

- a Cloud Storage bucket with a retention policy;
- irreversible locking of that policy;
- a generation-specific object identity;
- bucket lock and object retention-expiration readback;
- deletion denial attributable to retention;
- exact generation-specific object readback;
- an exported audit trail.

The adapter refuses execution unless the operator supplies an explicit
irreversible-lock confirmation.

### 3.3 Independent observer profile

`external-gitlab-scheduled-runner` requires:

- a separately administered GitLab project or instance;
- a schedule owner identified independently of GitHub and both custodians;
- a runner execution plane, identity root and credential store distinct from
  those domains;
- read-only credentials for the two preservation channels;
- a dedicated observer signing key;
- no custodian or publication-authority role.

A GitLab pipeline template is supplied, but its existence is not evidence that
an observer has been bound.

## 4. Control-domain attestations

Three signed attestations are required:

- `external-preservation-primary`;
- `external-preservation-secondary`;
- `independent-observer-primary`.

Each attestation binds:

- provider operator and service;
- tenant or account identifier;
- identity root;
- privileged administrator set;
- billing authority;
- credential store;
- execution plane;
- region or failure domain;
- audit-log custody;
- evidence references;
- signing-key identity;
- canonical payload digest.

Attestations use detached Ed25519 signatures with namespace
`eigiib-m0-a12@eigiib.example`. The private signing keys remain outside the
repository.

## 5. Diversity matrix

The matrix covers four domains:

1. the existing GitHub publication domain;
2. primary external preservation;
3. secondary external preservation;
4. independent observation.

It evaluates every unordered domain pair over nine control dimensions. The
closed matrix therefore contains `6 × 9 = 54` cells.

For this point-in-time activation profile every cell must be `distinct`.
Unknown and shared cells deny closure. This is deliberately stronger than a
marketing-level assertion that two endpoints or regions are different.

## 6. Immutable channel evidence

Each channel evidence record must contain:

- provider resource identity;
- endpoint;
- immutable object-version or generation identity;
- exact stable-bundle identity;
- applied retention mode;
- lock effective time and retain-until time;
- minimum retention window;
- retention readback reference;
- two deletion-denial records;
- audit references;
- independent exact readback;
- canonical payload digest.

A deletion denied only because of an ACL, missing permission, malformed
request or network failure is not accepted as retention evidence. The captured
failure must be attributable to the active retention mechanism and followed by
a successful version-specific presence check.

## 7. Campaign activation and first observation

The campaign retains the M0-A11 schedule:

- cadence: 86,400 seconds;
- grace: 21,600 seconds;
- lapse threshold: 172,800 seconds;
- clock: UTC RFC 3339;
- first sequence: 1.

The activation anchor binds:

- the M0-A12 source head;
- observer domain and key;
- both channel identifiers;
- initial immutable object versions;
- schedule;
- approval evidence.

The first observation must:

- have sequence `1`;
- have a null previous digest;
- be produced after campaign activation;
- cover both channel identities;
- verify exact bytes and SHA-256;
- verify retention readback;
- use the bound observer key;
- carry a canonical observation digest;
- have a valid detached Ed25519 signature.

One signed envelope may cover both channels only when failure of either channel
invalidates the complete observation.

## 8. Evidence ingress

Live evidence is admitted only below `evidence/m0-a12/` using the closed path
set enforced by the checker. Partial evidence moves the decision label from
`NF` to `NT`: external material is present, but closure is denied until every
obligation validates.

The repository baseline contains no live evidence and no private key. Synthetic
evidence is generated only in temporary test directories. It demonstrates the
validator, not an external fact.

## 9. State transitions

The permitted success path is:

```text
external-bindings-pending
→ domains-attested
→ channels-provisioned-and-locked
→ observer-bound
→ campaign-anchored
→ first-observation-verified
→ point-in-time-external-activation-and-first-signed-observation-verified
```

Any conflicting signature, digest, identity, retention state, time relation,
diversity cell or observation field transitions to
`invalid-or-conflicting-evidence`.

## 10. Closure theorem

M0-A12 may close positively if and only if all of the following hold:

- the M0-A11 source head is exact;
- all three domain attestations and detached signatures verify;
- all 54 diversity cells are present and distinct;
- both channels have immutable version identities;
- both retention locks are applied and read back;
- both required deletion attempts are retention-denied;
- both exact independent readbacks match the stable bundle;
- the campaign anchor is valid;
- observation sequence 1 is canonical and signed;
- the self-excluding authority freeze is exact;
- all workflows on the final head succeed.

The current baseline proves only the internal coordinate. Therefore its formal
label is `NF`, its activation result is `external-evidence-pending`, and E17
remains `not-ready-for-adoption`.

## 11. Nonclaims

This slice does not claim:

- that any AWS, Google Cloud or GitLab account currently exists;
- that any external resource is provisioned;
- that retention is currently active;
- that an independent observer currently operates;
- that the first live observation has occurred;
- that long-horizon preservation has been observed;
- that all future correlated failures are excluded;
- that E17 is ready for adoption.

## 12. External semantic references

The provider adapters are typed against the official semantics of:

- Amazon S3 Object Lock and `COMPLIANCE` retention;
- Google Cloud Storage Bucket Lock and irreversible retention-policy locking;
- GitLab scheduled pipelines;
- Ed25519 detached signatures with a dedicated domain separator.

These references constrain the adapters but do not replace live evidence.
