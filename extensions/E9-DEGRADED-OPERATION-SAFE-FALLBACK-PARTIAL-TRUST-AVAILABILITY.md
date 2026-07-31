# EIGIIB-E9 — Degraded Operation, Safe Fallback and Partial Trust Availability

**Status:** Normative extension, draft 1.0  
**Requires:** EIGIIB 1.0 and EIGIIB-E1 through EIGIIB-E8 1.0  
**Reference checker:** `tools/eigiib_degraded_check.py`

---

## 1. Purpose

EIGIIB-E9 defines how a system may continue operating when trust-relevant dependencies, relying parties, evidence sources, or authority services are only partially available.

E9 does not treat degraded operation as a weaker Boolean form of nominal operation. It requires the system to expose which capabilities remain permitted, which guarantees are preserved, which guarantees are suspended, which fallback path is being used, and which facts remain unknown.

The following implications are invalid unless an explicit policy supplies the missing premise:

```text
service available              != trust fully available
component reachable            != component trustworthy
fallback selected              != fallback effective
fallback effective             != nominal guarantees restored
cached evidence available      != fresh evidence available
partial trust available        != full trust available
read path safe                 != write path safe
old state still accepted       != fallback authorized
one dependency restored        != nominal mode restored
unknown dependency state       != available dependency state
```

---

## 2. Core terms

- **dependency**: a trust-relevant service, authority, witness, registry, signer, verifier, storage path, relying-party population, or other prerequisite.
- **availability observation**: bounded evidence about one dependency at one logical evaluation point.
- **capability**: an operation class whose execution depends on explicit prerequisites.
- **operation mode**: a declared capability/guarantee profile such as nominal, degraded, fallback, isolated, or read-only.
- **fallback route**: an explicit substitution from one dependency to another dependency or alternate path.
- **preserved guarantee**: a guarantee the selected mode still claims within its declared scope.
- **suspended guarantee**: a guarantee explicitly not claimed while the mode is active.
- **partial trust**: a state in which some trust-relevant premises are established while others are degraded, unavailable, unknown, or excluded.
- **nominal restoration**: a separate decision that required nominal prerequisites are again established; it is not inferred from one recovered dependency.

---

## 3. Core separation

E9 distinguishes:

```text
DependencyAvailability
FallbackEligibility
FallbackActivation
CapabilityPermission
PreservedGuarantees
SuspendedGuarantees
PartialTrustAvailability
NominalRestoration
```

A conforming implementation MUST NOT collapse these into one `healthy`, `available`, `fallback`, or `recovered` flag when the distinction changes engineering action.

---

## 4. Dependency observations

Canonical dependency observation states are:

```text
available
degraded
unavailable
unknown
not-applicable
```

`unknown` MUST remain distinct from `available` and `unavailable`.

An observation used to justify a positive E9 decision MUST carry evidence. Evidence may be local, E1/E3-derived, E4-authenticated, E5/E6-observed, E7 recovery evidence, E8 convergence evidence, or another explicitly typed source.

A generic checker MUST NOT probe the dependency itself.

---

## 5. Capabilities

A capability SHOULD declare:

```text
id
kind
required_dependencies
minimum_availability
impact
boundary
```

Reference `impact` values are:

```text
observe
read
write
publish
admin
```

Reference `minimum_availability` values are:

```text
available
degraded
```

A capability may require multiple dependencies. Missing requirements MUST NOT be silently ignored merely because another capability remains usable.

---

## 6. Operation modes

Canonical mode kinds are:

```text
nominal
degraded
fallback
isolated
read-only
```

A mode SHOULD declare:

```text
id
kind
assurance
allowed_capabilities
denied_capabilities
preserved_guarantees
suspended_guarantees
```

Reference assurance values are:

```text
full
partial
minimal
```

Allowed and denied capability sets MUST NOT overlap.

A non-nominal mode MUST expose a material distinction from nominal operation through at least one denied capability, suspended guarantee, reduced assurance, or active fallback dependency.

---

## 7. Fallback routes

A fallback route identifies an unavailable or degraded source dependency and an alternate dependency or path.

Canonical fallback states are:

```text
planned
eligible
active
failed
retired
```

An `active` fallback MUST:

- identify both source and substitute dependency;
- have evidence of activation;
- be selected only when the source is observed degraded or unavailable in the evaluated decision;
- have an available or policy-permitted degraded substitute in the evaluated decision;
- not be treated as proof that the substitute is equivalent to the source beyond the fallback policy.

A fallback is substitution, not identity.

---

## 8. Unknown-state policy

For dependency state `unknown`, E9 requires an explicit policy disposition:

```text
deny
hold
fallback
```

`unknown` MUST NOT be treated as `available` by default.

A profile MAY permit fallback from `unknown` only when an explicit fallback route and policy authorize it.

---

## 9. Degraded-operation policy

A policy SHOULD declare:

```text
id
mode
required_dependencies
allowed_degraded_dependencies
unknown_disposition
allowed_capabilities
require_e8_cutover_for_nominal
```

A positive degraded-operation decision MUST satisfy all required dependencies by either:

1. an acceptable direct observation, or
2. an active fallback explicitly selected by the decision.

Capabilities not authorized by the policy MUST remain denied even if technically executable.

---

## 10. Capability safety

For a capability `c`, each required dependency MUST be satisfied in the evaluated closure.

If a dependency is unavailable, it may satisfy the capability only through a selected active fallback whose substitute meets the applicable minimum availability.

If a dependency is unknown, policy decides whether the capability is denied, held, or routed through an explicit fallback.

An E9 checker MUST NOT infer that a write/admin capability is safe merely because a read/observe capability remains safe.

---

## 11. Partial trust

Partial trust is a typed conclusion, not a confidence percentage.

A partial-trust decision SHOULD identify:

```text
mode
preserved_guarantees
suspended_guarantees
allowed_capabilities
denied_capabilities
observations
fallbacks
policy
boundary
```

A positive `partial-trust-available` result MUST NOT be promoted to full trust or nominal operation.

---

## 12. E8 relationship

E8 remains authoritative for relying-party convergence and cutover.

E9 MAY use incomplete E8 adoption as one reason to enter degraded or fallback operation. It MUST NOT rewrite an E8 `partial`, `stalled`, or `converged-with-exceptions` result as global convergence.

When policy requires E8 cutover before nominal restoration, a referenced E8 cutover decision MUST resolve to a mechanically verified E8 cutover fact.

---

## 13. Nominal restoration

Nominal restoration is distinct from dependency recovery.

A `nominal-restored` decision requires:

- a nominal mode;
- required dependencies observed `available` with evidence;
- no required dependency being satisfied only by an active fallback unless policy explicitly permits that nominal definition;
- required E8 cutover facts when declared by policy;
- no unresolved required dependency state.

Restoration MUST NOT erase the degraded interval or fallback history.

---

## 14. Cached and stale evidence

Cached evidence MAY support a degraded mode only when policy permits its use and its scope is explicit.

Cached or stale evidence MUST NOT be silently described as fresh evidence.

E9-1.0 does not define trusted wall-clock freshness. If freshness matters, it must be supplied by an explicit higher/lower-layer policy with identified evidence.

---

## 15. Fail-open and fail-closed

E9 does not forbid fail-open behavior universally, but fail-open MUST be explicit and scoped.

A generic profile SHOULD prefer `deny`, `hold`, or explicit `fallback` for unknown trust-relevant dependencies.

A policy permitting a capability under unresolved trust state MUST name the capability, the unresolved premise, and the accepted boundary. Generic implicit fail-open is non-conforming.

---

## 16. Typed decisions

Canonical E9 decision states are:

```text
degraded-safe
fallback-verified
partial-trust-available
nominal-restored
unsafe
unavailable
```

These states are not a scalar confidence ladder.

`unsafe` means the evaluated policy premises for the requested mode/capability are not satisfied. It does not by itself identify cause or culpability.

---

## 17. Orthogonal capability results

E9 defines independent capability results:

```text
structural
degraded-operation-verified
fallback-verified
partial-trust-verified
nominal-restoration-verified
```

A structurally conforming repository may have none of the operational results evaluated.

---

## 18. Mechanical checks

A generic E9 checker SHOULD verify:

- supported standard/version and unique ids;
- repository path confinement;
- dependency/capability/mode/policy/fallback references;
- evidence presence for observations used positively;
- non-overlapping allowed/denied capability sets;
- active fallback source/substitute conditions;
- explicit unknown-state disposition;
- capability dependency satisfaction;
- policy/mode capability containment;
- reduced non-nominal profile semantics;
- partial trust is not promoted to nominal restoration;
- nominal restoration requires all nominal prerequisites;
- required E8 cutover facts resolve when declared.

A generic checker MUST NOT contact dependencies, execute fallback commands, change routing, mutate trust configuration, infer global convergence, infer full trust from partial trust, or infer cause/intent from unavailability.

---

## 19. Invariants

E9-I1. Availability is not trust.  
E9-I2. Fallback selection is not fallback effectiveness.  
E9-I3. Unknown is not available.  
E9-I4. Capability permission is prerequisite-scoped.  
E9-I5. Non-nominal modes expose reduced or substituted semantics.  
E9-I6. Fallback substitution does not imply semantic identity.  
E9-I7. Partial trust does not imply full trust.  
E9-I8. Nominal restoration is separately established.  
E9-I9. Degraded history is preserved.  
E9-I10. Degraded operation does not imply cause attribution or global safety.

---

## 20. Non-goals

E9-1.0 does not standardize load balancers, network routing protocols, disaster-recovery orchestration, distributed consensus, retry algorithms, SLO mathematics, wall-clock freshness, secret escrow, HSM failover, automatic fail-open execution, or automatic fallback activation.

---

## 21. Repository adoption

A repository adopting E9 SHOULD declare `conformance/degraded.json` as its E9 authority.

A structurally empty E9 registry is valid when no production degraded-operation claim is being made. A repository MUST NOT invent outages, fallbacks, unavailable dependencies, or successful restoration merely to demonstrate conformance.
