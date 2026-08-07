# EIGIIB-IDP-A1 Human Mastery Guide

## Decision order

1. Identify the information surface before choosing a repository.
2. Classify by disclosure handling, not by prestige or novelty.
3. Treat D0-D2 as public only after an explicit release decision.
4. Treat D3 as controlled engineering; a private GitHub repository is transport/storage, not root authority.
5. Treat D4 as named-audience restricted review; do not publish raw content digests as public metadata.
6. Treat D5 as local-only operational secret material.
7. If the target class differs from the source class, create a new artifact identity and a derivation record.
8. If restriction decreases, require a local disclosure-authority approval and bounded claim statement.
9. Quarantine every return-bridge artifact before local adoption.
10. Never infer deployed bridge confidentiality from structural IDP conformance.

## GO / NO-GO before adding a future bridge

GO requires all of:

- local root endpoint identified and authenticated;
- bridge repositories separated by direction and class;
- no D5 material in bridge history;
- outbound export is capsule/derivative based, not a complete mirror;
- inbound return defaults to quarantine;
- transport identity and endpoint pinning are independently checked;
- secret scanning covers history and generated artifacts;
- public façade receives only separately derived D0-D2 material.

Any missing item is NO-GO for an operational bridge claim.

## Public wording

Preferred:

> The public profile is conformant within its declared disclosure boundary. Restricted modules may exist outside the public payload and are governed by IDP access and derivation policy.

Avoid:

> The system prevents all malicious use.

Preferred:

> The conformant implementation rejects the specified unauthorized transitions inside the verified boundary.

## Open-source wording

Do not call unreleased D3-D5 source code open source. State instead that the public D0-D2 components are distributed under their declared licences and that the project may pursue later release of additional components after disclosure review.
