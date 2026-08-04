# M0-A12 controlled activation runbook

## Preconditions

Do not execute an irreversible provider adapter until:

1. the exact M0-A11 head `148e3e9d06ce791b90e2816d77f5045ebeac0793` has been verified;
2. the stable bundle has been restored and checked against SHA-256
   `96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde`;
3. three independently administered control domains have been identified;
4. the 54-cell diversity matrix can be completed without `unknown`;
5. retention duration and cost have been approved;
6. deletion-test principals have been provisioned;
7. audit export destinations are operational;
8. the observer key and revocation path have been bound.

## Local structural replay

```bash
python -m unittest -v tests/test_eigiib_m0_a12.py
python tools/eigiib_m0_a12_check.py . --output m0-a12-preactivation-report.json
```

Expected baseline:

```text
structural_result = conformant-preactivation
activation_result = external-evidence-pending
htntLabel = NF
```

`--require-activated` must return exit code `2` while live evidence is absent.

## Primary channel plan

```bash
M0_A12_MODE=plan \
  tools/m0_a12/aws_s3_object_lock_activate.sh
```

Execution requires distinct AWS CLI profiles for the authorized deleter and
privileged administrator, plus the exact irreversible confirmation string.
Raw output is not yet an attestation.

## Secondary channel plan

```bash
M0_A12_MODE=plan \
  tools/m0_a12/gcs_bucket_lock_activate.sh
```

Execution requires distinct gcloud configurations and the exact irreversible
confirmation string. Raw output is not yet an attestation.

## Observer deployment

Deploy `external/gitlab/m0-a12-observer.gitlab-ci.yml` in a separately
administered GitLab project. The observer configuration contains resource
identities only. Credentials and the private signing key must be protected
GitLab variables or external secret-store references.

A scheduled or manual first run produces:

- provider readback records;
- sequence-1 observation JSON;
- detached Ed25519 signature;
- allowed-signers public record;
- activation report.

## Evidence assembly

The final ingress tree is:

```text
evidence/m0-a12/
├── control-domains/
│   ├── external-preservation-primary.json
│   ├── external-preservation-primary.json.sig
│   ├── external-preservation-secondary.json
│   ├── external-preservation-secondary.json.sig
│   ├── independent-observer-primary.json
│   └── independent-observer-primary.json.sig
├── keys/
│   └── allowed_signers.json
├── channels/
│   ├── immutable-channel-primary.json
│   └── immutable-channel-secondary.json
├── diversity-matrix.json
├── campaign-anchor.json
└── observations/
    ├── 000001.json
    └── 000001.json.sig
```

Provider logs referenced by these records may be stored in an evidence bundle
or external immutable audit channel. Every reference must be resolvable during
review.

## Final verification

```bash
python tools/eigiib_m0_a12_check.py . \
  --require-activated \
  --output m0-a12-activation-report.json
```

A zero exit status is necessary but not sufficient. Manual review must confirm
that account and administrative identities are real, evidence references are
independent, and no secret has entered the repository.

## Abort conditions

Abort without attempting promotion when:

- either irreversible-lock confirmation is absent;
- provider or account identity is ambiguous;
- any diversity cell is shared or unknown;
- deletion succeeds;
- delete denial is not attributable to retention;
- object identity differs;
- observer credentials overlap with a custodian;
- detached signature verification fails;
- the campaign anchor precedes a required binding;
- evidence is partial or internally conflicting.

An abort leaves the branch in `NF` or `NT`; it never implies E17 readiness.
