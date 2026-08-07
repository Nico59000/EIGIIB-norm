# IDP-A5 — Independent Disclosure Review, Multi-Authority Release Approval, Public Projection Replay and Final Selective-Transparency Freeze

IDP-A5 closes the first selective-transparency sequence above IDP-A4. It separates technical projection safety from release authority: a public projection that satisfies A4 is not publishable merely because it is structurally well formed.

## Exact projection replay

The A5 positive corpus copies `conformance/idp-a4-public-transparency.json` byte-for-byte into `conformance/idp-a5-public-projection.json`. The release package binds both the source and projection to exact SHA-256 and canonical-JSON digests and to the exact IDP-A4 predecessor head. Any byte mutation, predecessor substitution, or path substitution is nonconformant.

## Independent disclosure review

The conformance corpus declares three explicitly synthetic disclosure-review authorities. Independence is structural and requires distinct `principalId`, `controlDomainId`, and `identityRoot` values. The corpus does not claim production identities, production keys, or organizational independence.

Each review is bound to the exact projection SHA-256. Approval is invalid if it targets another projection, appears after the freeze, carries unresolved findings, comes from an unknown authority, or duplicates an authority already counted.

## Multi-authority release approval

The structural threshold is two approvals out of three declared authorities. The final freeze's `approvedBy` set must equal the set of approving reviews exactly; rejected, absent, duplicated, or unknown authorities cannot be counted. The threshold proves only the declared structural policy.

## Final freeze

The freeze is append-only in the sense that it records a post-review structural state without rewriting A4. It is `structural-frozen`, `publicationAuthorized=false`, and `publicationDisposition=not-published`. A5 therefore freezes the reviewable projection and its approval history while refusing to infer operational publication authority.

## Claim boundary

A5 establishes exact projection replay, independent synthetic review, threshold approval, and a post-review structural freeze. It does not establish production reviewer identity or key control, actual publication, an external registry or endpoint, opening-material custody, universal unlinkability, or merger of predecessor pull requests.
