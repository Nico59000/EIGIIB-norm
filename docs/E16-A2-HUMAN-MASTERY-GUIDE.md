# E16-A2 Human-Mastery Guide

## Read the records in order

1. Confirm that the historical E16-A1 replay is conformant.
2. Resolve the exact E16-A1 replica binding and admissible preservation decision.
3. Resolve the placement request by identifier, revision and commitment.
4. Resolve custody acceptance and verify repeated custodian, replica and content identity.
5. Read the failure-domain declaration as a declaration, not as proof of independence.
6. Resolve the placement observation and its exact evidence references.
7. Recompute all six gates.
8. Apply negative precedence before considering held or unavailable states.
9. Compare the recomputed state with the stored placement decision.
10. Verify the descendant authority freeze.

## Interpretation limits

`placement-observed` means that the repository contains a conformant positive observation bound to the represented request and identities. It does not mean that the bytes will remain available, that another custodian holds an independent copy, that a retention policy was satisfied or that restoration will succeed.

Different provider, region, account or facility labels are insufficient to establish independence. Equal labels can expose a possible shared domain, but labels alone cannot close the physical-separation claim.

## Escalation

A reviewer must hold or reject interpretation when:

- a reference, revision or commitment does not resolve;
- content identity differs across request, acceptance and observation;
- the acceptance is rejected, held or unavailable;
- the failure-domain declaration is retired, contested or unavailable;
- the observation is negative, inconclusive or unavailable;
- the stored decision differs from the derived decision.
