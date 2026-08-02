# E14-A1 Human Mastery Guide

## Operator rule

Identify the source record first, preserve the claim boundary second, and only then consider a projection. A valid E14-A1 projection is still not permission to disclose.

## Three separate questions

1. **What is observed?** Exact artifact bytes, source revision, claim descriptors, revocation state and projection fields.
2. **What is mechanically concluded?** Artifact identity matches, commitments match, every projected claim is equal or weaker, and omissions are complete.
3. **What remains outside the boundary?** Audience authorization, storage secrecy, semantic truth, correlation resistance and actual release.

## Safe projection review

For every projected claim, compare:

```text
source claim id
semantic tuple: type / subject / predicate / object
scope subset
assurance non-increase
evidence-reference subset
```

Then verify that all other source claims appear in `omitted_claims`.

## Stop conditions

Stop and classify the projection as non-conformant when:

- the source commitment or artifact digest differs;
- the source revision is stale;
- the source is revoked, withdrawn or unavailable;
- a claim changes subject, predicate, object or type;
- scope broadens, assurance rises or new evidence is asserted;
- omission accounting is incomplete;
- audience, policy, context or correlation bindings are missing.

## Communication discipline

Use precise statements:

```text
The projection is structurally bound to record R at revision V.
The projected claims do not exceed their source claim boundaries.
E14-A1 did not evaluate whether disclosure is authorized.
```

Do not replace these with “safe to disclose”, “anonymous”, “encrypted” or “approved”.
