# EIGIIB-E4 — Authenticated Attestations, Trust Roots and Provenance Integrity

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0, EIGIIB-E1 1.0, EIGIIB-E2 1.0, and EIGIIB-E3 1.0  
**Reference checker:** `tools/eigiib_trust_check.py`

---

## 1. Purpose

EIGIIB-E4 defines how a project may authenticate engineering attestations and bind them to E1 claims/evidence and E3 artifact/provenance identities without collapsing cryptographic validity, trust, authorization, time validity, or semantic truth into one Boolean.

E4 exists because the following implications are invalid unless an explicit policy supplies the missing premise:

```text
matching digest              != authenticated origin
valid signature              != trusted signer
trusted signer               != authorized signer
key identity                 != human or organizational identity
trusted path                 != true statement
signature time field         != trusted time
unrevoked in local data      != globally unrevoked
authenticated provenance     != complete provenance
authenticated evidence       != correct claim
```

E4 therefore treats authentication as a policy-governed relation over exact statement bytes, cryptographic verification, trust anchors, delegation, scope, purpose, time, and revocation state.

---

## 2. Normative terms

- **principal**: a named trust-domain actor such as a person, team, service, release role, CI identity, or organizational function. A principal identifier is a label, not proof of real-world identity.
- **key**: a cryptographic verification identity represented by a public-key artifact and an algorithm/suite identifier.
- **key fingerprint**: a digest-derived identifier for exact public-key bytes under a declared fingerprint rule.
- **trust root**: an explicitly configured key/principal binding accepted as an authority for one or more purposes and scopes. A root is a policy input, not a cryptographic conclusion.
- **purpose**: the class of authorization for which a key may be trusted, such as `release`, `provenance`, `evidence`, `delegation`, or a project-local purpose.
- **delegation**: a signed authorization by one key allowing another key to act for declared purposes and scope subject to constraints.
- **revocation**: an authenticated statement that invalidates a key, delegation, or attestation according to a declared effective-time rule.
- **attestation**: a signed statement artifact whose exact bytes are bound to one or more signatures.
- **signature record**: the association between a statement artifact, signature artifact, key, and signature suite.
- **trust path**: a sequence from an accepted trust root through zero or more valid delegations to a signing key.
- **authentication policy**: the authoritative rule defining accepted roots, algorithms, purposes, threshold, scope, path length, time, and revocation requirements.
- **evaluation time**: an explicit instant at which validity is evaluated. Wall-clock time MUST NOT be silently substituted when deterministic replay matters.
- **verification provider**: the cryptographic implementation used to check a signature. Provider identity is evidence metadata, not a trust root.

---

## 3. Core separation

For an attestation `a`, E4 distinguishes at least four decisions:

```text
SignatureValidity(a)
TrustPathValidity(a, P)
AuthorizationValidity(a, P)
AttestationAcceptance(a, P)
```

A project MUST NOT encode all four as a single field named `verified`, `trusted`, or `valid`.

### 3.1 Cryptographic validity

A signature is cryptographically valid only when a declared verification suite verifies the signature over the exact statement bytes using the exact public key bytes.

This proves only that the holder of the corresponding signing capability produced the signature, subject to the security assumptions of the suite and verifier.

### 3.2 Trust validity

A cryptographically valid signature is trusted only when its signing key reaches a trust root admitted by the selected policy through a valid path.

### 3.3 Authorization validity

A trusted key is authorized only for purposes and scope granted by the root and every delegation in the path.

### 3.4 Acceptance

An attestation is accepted only when the policy's signature, path, authorization, time, revocation, threshold, and binding requirements are all satisfied.

Acceptance does not prove the semantic truth of the signed statement. It proves that the statement is authenticated under the declared policy.

---

## 4. Statement identity

### 4.1 Exact statement artifact

A material E4 attestation MUST sign an immutable E3 artifact instance or another byte-identical object with an E3-compatible identity.

The signed object SHOULD therefore be represented by:

```text
StatementIdentity = (artifact_id, algorithm, digest, byte_count)
```

E4 prefers detached exact-byte statements over reserialization of an inline object.

### 4.2 No implicit reserialization

A verifier MUST NOT parse JSON/YAML/TOML and then reserialize it before verification unless the signature suite explicitly names a canonicalization algorithm and the signed object identifies that algorithm.

If exact bytes are signed, exact bytes MUST be verified.

### 4.3 Binding to E1 and E3

An attestation MAY bind to:

- an E1 claim id;
- an E1 evidence id;
- an E3 artifact id;
- an E3 production-event id;
- an E3 replay id;
- an E4 delegation/revocation object;
- a project-local immutable subject identifier.

The binding MUST be explicit in the statement or in a separately authenticated binding object.

---

## 5. Key identity

### 5.1 Public-key artifacts

A key record is modeled as:

```text
Key = (
    id,
    principal,
    suite,
    public_key_artifact,
    fingerprint,
    usages,
    status
)
```

The public key MUST be treated as immutable bytes.

### 5.2 Fingerprints

A fingerprint MUST identify:

- digest algorithm;
- digest value;
- exact byte representation to which the digest applies.

A fingerprint is an identifier, not a certificate and not proof of ownership.

### 5.3 Key status

Canonical status values are:

```text
active
retired
revoked
compromised
unknown
```

`retired` MUST NOT be treated as equivalent to `revoked`. Historical signatures MAY remain admissible under policy after retirement.

`compromised` MAY require retrospective invalidation, but only if the policy explicitly defines the temporal effect.

---

## 6. Trust roots

### 6.1 Root object

A trust root is modeled as:

```text
Root = (
    id,
    key,
    principal,
    purposes,
    scope,
    validity,
    policy_authority
)
```

### 6.2 Root introduction is external trust

Adding a trust root is itself a trust decision. A project MUST NOT claim that a key became trustworthy merely because it appears in the repository being evaluated.

The authority that introduces or changes trust roots MUST be explicit.

### 6.3 Test roots

Keys with known, discarded, shared, generated-for-test, or publicly disclosed private material MUST be marked `test-only` and MUST NOT satisfy production authentication policies.

A test root MAY be used to validate checker mechanics and interoperability.

---

## 7. Delegation

### 7.1 Delegation object

A delegation is modeled as:

```text
Delegation = (
    id,
    from_key,
    to_key,
    purposes,
    scope,
    not_before,
    not_after,
    max_remaining_depth,
    statement_artifact,
    signatures
)
```

The delegation statement MUST itself be authenticated by a key authorized to delegate the requested purpose/scope.

### 7.2 Intersection rule

For a trust path `r -> d1 -> ... -> k`, effective authorization is the intersection of every path constraint:

```text
effective_purpose = intersection(all purpose grants)
effective_scope   = intersection(all scope grants)
effective_window  = intersection(all validity windows)
```

A child delegation MUST NOT widen any parent authorization.

### 7.3 Path length

Every policy MUST define either a finite maximum delegation depth or an explicit unbounded rule.

A delegation `max_remaining_depth = 0` authorizes signing but not further delegation.

### 7.4 Cycles

Delegation cycles MUST NOT create authority. A valid trust path is simple with respect to key/delegation identifiers.

---

## 8. Signature suites

### 8.1 Suite registry

Each signature MUST identify a suite. A suite definition MUST specify at least:

- key format;
- signature format;
- message bytes;
- algorithm identifier;
- verification semantics;
- security status (`production`, `deprecated`, `test-only`, `disabled`).

### 8.2 Algorithm agility without ambiguity

A verifier MUST NOT infer an algorithm from key length, file extension, or signature size.

The suite identifier is authoritative.

### 8.3 Disabled/deprecated suites

A policy MUST distinguish:

```text
allowed
deprecated
test-only
disabled
```

A cryptographically valid signature using a disabled suite is not policy-acceptable.

A `test-only` suite or key MUST NOT satisfy a production policy.

---

## 9. Time semantics

### 9.1 Deterministic evaluation time

A trust decision that depends on time MUST record an explicit evaluation time `t_eval`.

A deterministic checker MUST NOT silently use the current wall clock as a normative input.

### 9.2 Self-asserted issuance time

An `issued_at` field inside a signed statement proves only that the signer asserted that value.

It does not independently prove when the signature was created.

### 9.3 Trusted time

A policy that requires historical proof of signing time MUST require independent trusted-time evidence, such as a timestamp authority or equivalent project-approved mechanism.

E4-1.0 defines the requirement but does not standardize a timestamp protocol.

### 9.4 Validity windows

An attestation is time-admissible only if every required key/root/delegation/attestation validity interval includes `t_eval` under the selected policy.

---

## 10. Revocation

### 10.1 Revocation object

A revocation is modeled as:

```text
Revocation = (
    id,
    target_type,
    target_id,
    effective_at,
    reason,
    statement_artifact,
    signatures
)
```

### 10.2 Authorization to revoke

A revocation MUST itself be authenticated by a key or policy authority explicitly authorized to revoke the target.

### 10.3 No absence inference

The absence of a revocation record proves only that the evaluated revocation set contains no applicable record.

It MUST NOT be reported as global proof that no revocation exists.

### 10.4 Retrospective effect

Policies MUST state whether compromise/revocation affects:

- only decisions after `effective_at`;
- all signatures after a trusted compromise time;
- all historical signatures;
- another explicit interval.

A verifier MUST NOT invent retrospective semantics.

---

## 11. Threshold and multi-party trust

### 11.1 Threshold policy

A policy MAY require `m-of-n` authentication.

Threshold counting MUST define the distinctness unit:

```text
key
principal
root-domain
```

Two signatures from two keys owned by one principal do not satisfy a `2 distinct principals` requirement.

### 11.2 Quorum scope

Every counted signature MUST independently satisfy purpose, scope, time, revocation, and suite requirements unless the policy explicitly defines heterogeneous roles.

### 11.3 Role-separated quorum

A policy MAY require role composition, for example:

```text
1 release signer
AND
1 provenance signer
AND
1 independent reviewer
```

Role composition MUST be explicit; it MUST NOT be inferred from signature count.

---

## 12. Authentication relation

Let:

- `a` be an attestation;
- `P` an authentication policy;
- `R` the configured root set;
- `D` the authenticated delegation set;
- `V` the applicable authenticated revocation set;
- `S` the cryptographically verified signature set;
- `t` the evaluation time.

Write:

```text
(R, D, V, S, t) ⊨P auth(a)
```

iff all of the following hold:

1. the statement artifact identity is established;
2. every counted signature verifies cryptographically over the exact statement bytes;
3. every counted signing key reaches an accepted root through a valid simple path;
4. the effective path purposes authorize the attestation purpose;
5. the effective path scope covers the attestation scope;
6. the root/key/delegation/attestation validity rules hold at `t`;
7. no applicable authenticated revocation invalidates a counted path/signature under `P`;
8. the signature suite is permitted by `P`;
9. threshold and role constraints are satisfied;
10. E1/E3 bindings required by `P` resolve to the exact referenced identities.

Only then may the authentication decision be `authenticated`.

---

## 13. Typed decision states

### 13.1 Signature decision

```text
valid
invalid
unsupported-suite
unverified
unavailable
```

### 13.2 Trust-path decision

```text
trusted
untrusted
revoked
expired
not-yet-valid
ambiguous
unavailable
```

### 13.3 Attestation decision

```text
authenticated
cryptographically-valid-untrusted
policy-unsatisfied
revoked
expired
not-yet-valid
invalid-signature
partially-evaluated
unavailable
not-applicable
```

These states MUST NOT be collapsed into a single Boolean when preserved distinction changes engineering action.

---

## 14. E3 provenance integrity binding

### 14.1 Detached authentication of provenance

An E3 provenance registry MAY be authenticated by signing its exact bytes as an E3 artifact instance and storing the E4 signature/attestation outside that signed byte stream.

This avoids self-referential hashing/signing.

### 14.2 No self-signature cycle

A registry MUST NOT include a signature artifact whose bytes are required to compute the identity of the registry bytes being signed.

The signature envelope and signature bytes MUST be detached or otherwise excluded by an explicit canonical envelope rule.

### 14.3 Authenticated provenance is still bounded

Authenticating an E3 registry establishes who authenticated those exact registry bytes under policy. It does not prove that the provenance graph is complete or that every recorded production event actually occurred unless separate evidence/policy establishes those propositions.

---

## 15. E1 evidence binding

An E1 evidence record MAY require an E4 attestation through policy.

For evidence `e`, an E1 policy may require:

```text
identity(e) established by E3
AND
auth(e) established by E4 policy P
```

E4 authentication MUST NOT promote the E1 evidence kind or scope. It only authenticates the declared evidence record/artifact.

A signed failing test remains failing evidence.

---

## 16. Verification-provider boundary

### 16.1 Provider neutrality

The E4 normative model does not require a specific cryptographic library.

A verifier implementation MUST identify:

- provider name;
- provider version when available;
- suite used;
- verification result;
- exact key/statement/signature identities.

### 16.2 No repository-controlled command execution

A generic E4 checker MUST NOT execute arbitrary commands supplied by the target repository.

A checker MAY invoke a fixed, implementation-controlled cryptographic provider with fixed argument construction.

### 16.3 Provider unavailable

If a required provider or algorithm is unavailable, the cryptographic decision is `unavailable` or `unsupported-suite` as applicable.

It MUST NOT be silently treated as invalid signature or accepted signature.

### 16.4 Reference provider

The E4-1.0 reference checker MAY use a locally installed OpenSSL provider for suites it explicitly supports. This is an implementation choice, not normative trust in OpenSSL installations generally.

---

## 17. Registry model

A machine-readable E4 registry SHOULD contain:

```text
standard
revision
principals
keys
roots
policies
delegations
revocations
attestations
signatures
decisions
```

Every durable identifier MUST be unique in its object class.

Repository-relative files MUST obey E2 path-confinement rules.

E3 artifact identities SHOULD be reused rather than recopied when the E3 registry is authoritative and available.

---

## 18. Mechanical E4 checks

A generic E4 structural checker SHOULD verify:

- supported standard/version;
- unique ids;
- key/principal/root references;
- key fingerprint matches local public-key bytes;
- statement/signature paths are confined;
- referenced E3 artifact identities match local bytes where available;
- policy references resolve;
- delegation graph contains no authority-generating cycle;
- child delegation cannot syntactically widen parent purpose/scope when both are finite and mechanically comparable;
- test-only keys/suites cannot satisfy production policies;
- threshold distinctness is mechanically respected;
- authenticated decisions are rejected when required cryptographic verification is unavailable;
- revocation references resolve;
- evaluation time is explicit for time-sensitive acceptance.

A generic checker MUST NOT infer real-world principal identity, semantic truth, completeness of revocation sources, or trust-root legitimacy.

---

## 19. OpenSSL reference verification profile

The reference checker supports an optional fixed OpenSSL verification adapter for testable suites.

For E4-1.0 the required reference-suite interoperability target is:

```text
ed25519-openssl-raw-v1
```

with:

- PEM SubjectPublicKeyInfo public key;
- raw Ed25519 signature bytes;
- exact statement bytes as message;
- OpenSSL `pkeyutl -verify -rawin` semantics.

The suite is permitted for conformance fixtures. Whether it is permitted for a project's production policy is a separate policy decision.

The checker MUST NOT read a private key.

---

## 20. Test-only conformance root

The repository MAY ship a public test key and a fixed signed fixture to demonstrate cryptographic-provider interoperability.

Such a root MUST be labeled:

```text
test_only = true
```

and MUST NOT satisfy any policy whose `environment = production` or equivalent production marker is present.

The corresponding private key MUST NOT be shipped.

A test fixture validates verifier mechanics, not organizational identity.

---

## 21. Fail-closed and typed unavailability

E4 requires fail-closed acceptance with typed diagnostic states.

Examples:

```text
signature bytes unreadable      -> unavailable / input error
algorithm unsupported           -> unsupported-suite
provider missing                -> unavailable
signature mismatch              -> invalid
root absent                     -> untrusted
root present but scope narrow   -> policy-unsatisfied
revocation data unavailable     -> unavailable if policy requires completeness
```

Projects MUST NOT downgrade to a weaker trust rule silently.

---

## 22. Key rotation

Key rotation MUST be modeled as an explicit trust transition.

A new key may become trusted through:

- direct root-set update by the root authority;
- authenticated delegation/rotation statement from an authorized old key;
- another policy-declared process.

The presence of a newer key MUST NOT silently invalidate historical signatures by an older key.

---

## 23. Root rotation and recovery

Root rotation is a governance boundary and SHOULD require stronger policy than ordinary signing-key rotation.

A project SHOULD define recovery semantics for:

- lost root key;
- compromised root key;
- threshold-root member loss;
- repository compromise while trust metadata is being changed.

E4-1.0 does not prescribe one recovery ceremony. It requires the authority and transition rule to be explicit.

---

## 24. Conformance levels

### 24.1 E4-S — structural

Requires:

- E4 registry validity;
- explicit roots/policies or an explicit statement that no authenticated claims are currently made;
- path/reference/fingerprint checks;
- trust and authentication states remain typed.

No cryptographic signature need be verified for structural-only conformance.

### 24.2 E4-V — verified

Requires E4-S plus:

- at least one configured non-test authentication policy;
- cryptographic verification through a declared provider;
- trust-path evaluation;
- explicit evaluation time where required;
- revocation evaluation required by policy.

### 24.3 E4-P — provenance-integrity

Requires E4-V plus authenticated binding of the selected E3 provenance authority artifact under a declared provenance-integrity policy.

E4-P does not imply provenance completeness.

---

## 25. EIGIIB minimal-explicitness rule applied to trust

E4 MUST NOT become a generic PKI encyclopedia inside every adopting project.

A project should expose only:

- roots actually trusted;
- purposes actually used;
- delegations actually needed;
- revocation semantics actually enforced;
- suites actually accepted;
- the claim boundary of authentication decisions.

Implementation detail belongs in the verifier; normative authorization belongs in policy; exact bytes belong in artifacts; evidence belongs in E1/E3 records.

---

## 26. Required claim boundaries

A project claiming E4 authentication MUST state nearby that:

1. cryptographic validity is relative to the selected signature suite/provider;
2. trust is relative to the configured root policy;
3. authorization is limited by purpose/scope/path constraints;
4. revocation conclusions are limited to the evaluated revocation sources;
5. time conclusions are limited to the evidence supporting time;
6. authentication does not prove semantic truth;
7. authenticated provenance does not prove provenance completeness.

---

## 27. Reference checker result

The reference checker reports separate dimensions:

```text
structural_result
crypto_result
authentication_result
overall_result
```

It MUST NOT report `authenticated` when cryptographic verification was not executed for a policy that requires it.

The 0.1 reference checker fully recomputes direct-root Ed25519/OpenSSL fixture paths. Delegated or revocation-sensitive policies remain `partially-evaluated` unless a later verifier version can recompute those semantics soundly.

---

## 28. Non-goals of E4-1.0

E4-1.0 does not standardize:

- certificate enrollment protocols;
- X.509 PKI profiles;
- transparency logs;
- remote key discovery;
- hardware security module APIs;
- key-generation ceremonies;
- timestamp protocols;
- online revocation protocols;
- identity-proofing procedures;
- supply-chain transparency systems.

These may be integrated later through explicit adapters or later EIGIIB extensions.

---

## 29. Summary invariant

The central E4 invariant is:

```text
Authenticated(a, P)
    => exact_statement_identity(a)
    AND cryptographic_signature_valid(a)
    AND trusted_path_exists(a, P)
    AND signer_authorized(a, P)
    AND time_policy_satisfied(a, P)
    AND revocation_policy_satisfied(a, P)
    AND threshold_policy_satisfied(a, P)
```

The reverse implication holds only when every conjunct is evaluated under the authoritative policy.

A digest alone is never an authenticated origin claim. A valid signature alone is never a trust claim. A trusted signer alone is never a truth oracle.
