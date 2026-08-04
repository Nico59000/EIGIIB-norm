# M0-A12-F1 manual review authority

## Exact lineage

- base branch: `agent/m0-a12-external-immutable-channel-activation-independent-attestation-first-signed-observation`;
- exact base head: `e6661993924aed4d0185df48cf0b8587b2e0abf3`;
- exact M0-A11 ancestor: `148e3e9d06ce791b90e2816d77f5045ebeac0793`;
- no historical E14, E15, E16, P1 or M0 head may be moved or rewritten.

## Baseline review

The initial F1 tranche is valid only when:

1. no `evidence/m0-a12` or `evidence/m0-a12-f1` tree is committed;
2. the closure ledger is empty and `not-closed`;
3. the canonical report is `NF` and `external-evidence-pack-absent`;
4. `--require-closed` exits with code `2`;
5. archive ingress rejects traversal, links, devices, duplicates, unlisted files and digest substitution;
6. no private key, token or provider credential is committed;
7. the full F1 suite and the inherited M0-A12 suite pass on Ubuntu, macOS and Windows.

## Bound-ingress review

Before accepting a future evidence commit, reviewers must independently confirm:

1. the package source authority is exactly the M0-A12 head above;
2. the archive manifest is signed by `independent-observer-primary`;
3. every payload file is listed exactly once and matches its byte count and SHA-256;
4. all M0-A12 required evidence files are present;
5. the primary custodian, secondary custodian and observer have each signed the same approval record;
6. the approval binds the exact evidence-set digest and acknowledges irreversible provider actions;
7. the ingress receipt is `verified-and-bound` and matches the archive, manifest and evidence digests;
8. no target path was overwritten or followed through a link;
9. the bound tree contains no undeclared M0-A12 evidence file;
10. the original external evidence references remain resolvable.

## Point-in-time closure review

Closure additionally requires:

1. the inherited M0-A12 verifier returns `T` with no findings;
2. the generated closure certificate binds the ingress receipt, manifest, evidence set and M0-A12 report;
3. the certificate records the transition `NF -> T`;
4. all workflows on one exact final head are successful;
5. the PR remains draft and unmerged unless a separate merge decision is made.

## Prohibited interpretation

A verified package that is not bound, a bound package without a closure certificate,
a synthetic package, a manually copied evidence directory, or a successful archive
hash alone is not point-in-time activation closure.

A valid M0-A12-F1 closure remains point-in-time only. It does not establish future
observation continuity, absence of lapse, long-horizon durability or E17 readiness.
