# EIGIIB-IDP-A3 — Audience Grants, Institutional Eligibility, Expiry, Revocation and Return-Quarantine Promotion

Status: draft normative structural profile 0.1, additive above IDP-A2 `d2def5458da677fa061e38ed91a6d718b9cc8d2a`.

## 1. Purpose

IDP-A3 separates route authentication from authorization. A2 answers whether a route context is the intended route. A3 answers whether a named subject, through an eligible institution and audience grant, may use that route at an explicit evaluation instant, and whether an inbound quarantined object may be admitted to local review staging.

```text
authenticated route != authorized audience
eligible institution != perpetual entitlement
grant issued != grant currently usable
valid grant != irrevocable grant
signature != merge authority
promotion from quarantine != trust
promotion from quarantine != merge
promotion from quarantine != reclassification
```

## 2. Time model

The verifier MUST receive `--evaluation-at`. Host-clock access is forbidden. Interval semantics are half-open:

```text
notBefore <= t < notAfter
```

A revocation is effective when:

```text
effectiveAt <= t
```

Expiry, not-yet-valid and revoked states are therefore exactly replayable without dependence on the verifier host clock.

## 3. Institutional eligibility

An institution is a separately authorized object with eligible disclosure classes and a bounded validity interval. A grant is unusable unless the subject belongs to that institution, the institution is eligible for the requested class at the relevant instant, and the eligibility statement is issued by the institutional-eligibility authority.

Institutional eligibility is not a statement of scientific merit, public accreditation or legal status. The A3 conformance corpus uses synthetic institutions only.

## 4. Named audiences

An audience binds a channel, a classification, a purpose, a non-empty set of named subjects and a non-empty set of allowed institutions.

The structural purposes are:

- `controlled-engineering` on `private-bridge-out`;
- `return-quarantine-review` on `private-bridge-return`;
- `restricted-review` on `restricted-review`.

Audience membership is necessary but never sufficient by itself.

## 5. Audience grants

A grant binds exactly:

```text
subject
+ institution
+ audience
+ channel
+ classification
+ validity interval
+ issuer authority
```

A grant is usable only if all bindings agree, the issuer is the access-grant authority, the institution is eligible for the class, the grant is active at the evaluation instant, and no effective revocation exists.

D5 grants are forbidden.

## 6. Expiry and not-yet-valid states

A structurally valid grant can still be unusable at an evaluation instant. A3 treats these states fail-closed:

```text
t < notBefore      -> denied
t >= notAfter      -> denied
```

No grace interval is inferred.

## 7. Revocation

Revocation is a separate authority relation. A revocation object binds a grant identifier, an effective instant, a reason code and the revocation authority.

Once `effectiveAt <= t`, the referenced grant is unusable even if its nominal expiry is later.

Grant issuance and grant revocation are deliberately distinct roles.

## 8. Return quarantine

Every object carried by `private-bridge-return` remains `quarantined` on ingress. A record must bind the exact A2 `bridge-return-binding` and cannot silently appear as admitted, trusted or merged.

```text
received != admitted
admitted to local review != trusted
local review != merge
```

## 9. Promotion from quarantine

A3 permits only an explicit local decision to move a specific quarantined record to:

```text
local-review-staging
```

That transition requires:

- the record still has valid return-quarantine provenance;
- a reviewer grant whose audience purpose is `return-quarantine-review`;
- the grant classification matches the quarantined record classification;
- the reviewer grant is usable at `decidedAt`;
- the decision is issued by the `local-promotion-authority`;
- `decidedAt` is not before the return record was received.

## 10. Non-escalation boundary

Every approved promotion explicitly carries:

```text
mergeAuthorityClaim = false
reclassificationClaim = false
```

Therefore local-review staging is not a merge, not content trust, not a classification change and not L0 root authority.

A later local decision may consume a staged object only under another explicitly declared authority relation outside A3.

## 11. Structural-only claim

All institutions, identities, grants, revocations, quarantine records and promotion decisions in the conformance corpus are synthetic.

A3 does not claim:

- proofed real-world institutional identity;
- a production eligibility service;
- a production grant issuer;
- a production revocation service;
- live audience authorization;
- live return-quarantine promotion.

These remain NT until external evidence binds them.

## 12. Machine authority

The structural registry is:

```text
conformance/idp-a3-access-policy.json
```

The closed schema is:

```text
schemas/idp-a3-access-policy.schema.json
```

Reference and independent verifiers are:

```text
tools/eigiib_idp_a3_check.py
tools/eigiib_idp_a3_independent.py
```

The differential replay is:

```text
tools/eigiib_idp_a3_matrix.py
conformance/idp-a3-verifier-matrix.json
```

## 13. Frozen negative families

The A3 matrix covers:

1. wrong grant issuer;
2. institution not eligible for the class;
3. audience subject mismatch;
4. grant expired at evaluation;
5. grant not yet valid at evaluation;
6. wrong revocation authority;
7. wrong return source binding;
8. wrong promotion authority;
9. promotion using a revoked grant;
10. promotion class mismatch;
11. promotion attempting to claim merge authority;
12. D5 grant attempt.

## 14. Adoption boundary

`conformance/idp-a3-adoption-transition.json` records that A3 is additive above the exact A2 head and does not modify A2, A1 or M0-A15-F2 decision relations.

The structural result may be `T_WITHIN_STRUCTURAL_BOUNDARY` while all live institutional and operational claims remain false/NT.

## 15. Successor

Natural successor: **IDP-A4 — Public Transparency Records, Opaque Commitment Construction, Withdrawal and Anti-Correlation Disclosure.**
