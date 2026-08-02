# P1-A18 — Deployed Release Governance, Separation of Duties and Emergency Override Replay

## 1. Scope

P1-A18 extends exact P1-A17 commit `2e2ea29ac61787cb62c22f7db828766257af4c01` with a workflow-executed governance fixture for the named environment `p1-a18-fixture-production`. The slice binds the P1-A17 report, capsule and protected object set to a signed release request, threshold approvals, publisher action, emergency override and post-emergency review.

The word *deployed* is bounded to execution of the governance mechanism in GitHub Actions against the named fixture environment. The slice does not claim a live product deployment, configured GitHub environment protection rules, organization-wide identity assurance, platform-enforced separation of duties or universal release governance.

## 2. Cryptographic role separation

Seven Ed25519 public keys are frozen:

- governance registrar;
- release requester;
- two release approvers;
- release publisher;
- emergency controller;
- release auditor.

Every role has a distinct SPKI digest. A role label alone is insufficient: each signed record binds its key identifier, canonical payload digest, artifact identity, environment and validity window.

## 3. Normal promotion path

The normal path requires:

1. a requester-signed release request;
2. two distinct approver signatures;
3. no requester or publisher in the approval set;
4. exact agreement on the P1-A17 artifact and fixture environment;
5. unexpired and non-revoked authorization identifiers;
6. a publisher-signed promotion record referencing the complete authorization set.

The accepted fixture promotion is `P1-A18-PROM-0001`.

## 4. Emergency override path

The emergency controller may bypass only `approval-threshold-only`. The override cannot bypass artifact integrity, environment binding, publisher identity or signature verification. It requires an incident identifier, a non-empty justification, exact scope and a maximum duration of 1,800 seconds.

The accepted fixture override is `P1-A18-OVR-0001`. It authorizes publisher-signed promotion `P1-A18-PROM-EMG-0001`. Auditor-signed review `P1-A18-REVIEW-0001` closes the path within 86,400 seconds and records no scope expansion.

## 5. Replay and mutation closure

The reference Python route and independent Go route verify all Ed25519 signatures and converge on one exact report. Nineteen mutations are rejected, including duplicate or forbidden approvers, altered artifact or environment, expired or revoked authority, wrong authorization references, missing emergency incident or justification, excessive override duration, forbidden bypasses, promotion after expiry and deficient post-emergency review.

## 6. Exact authorities

- P1-A17 commit: `2e2ea29ac61787cb62c22f7db828766257af4c01`
- P1-A17 report SHA-256: `4e8473256a6e857d4826e2c2a1eb484d45d023cd648136a9ff0149a3f5931433`
- P1-A17 capsule SHA-256: `bd0e55bb7ad0e44ab7adcc7538b7718dd6f7ab938ebb0752accaf40dff379340`
- protected object set SHA-256: `29811e4cbd30ff12fef18c12c61068f83de8d3c61a2be93ae8faf37f2f11b466`
- governance policy SHA-256: `70122a5d2a2ab69aef84d2fc17e45c85a8a32520b24d80faa5317f0c5d384cdc`
- governance bundle SHA-256: `43be84f951ed566a0c9b133a63e97f2a2acd0beefe66c6e62a456c7611ffa294`
- signing key set SHA-256: `060d6304c2f815119adf3ca22d703e347387808e8b85c1089882efc9f590abfe`

## 7. Decision boundary

Boundary: `workflow-executed-fixture-production-governance-sod-and-reviewed-emergency-override-closure`.

Conformant inside the boundary:

- exact artifact and environment binding;
- signed distinct-role separation for the fixture;
- normal threshold approval;
- time-bounded emergency threshold bypass;
- publisher identity preservation;
- mandatory signed post-emergency review;
- deterministic Python and Go replay.

Outside the boundary:

- platform-enforced separation of duties;
- GitHub environment protection-rule enforcement;
- real organization identity assurance;
- live production deployment;
- universal release governance.
