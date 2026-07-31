# EIGIIB-E13 Policy Composition Hardening Profile 0.2

Status: additive hardening above E13 draft 1.0.

This profile closes bounded false-positive gaps found after the first green E13 repository replay. It does not change the explicit composition algorithms and does not introduce a global precedence rule.

## H1. Required member conclusiveness

For an E13 composed decision in state `permitted`, every profile member marked `required` must have exactly one selected E10 decision whose state is conclusive:

```text
authorized
denied
```

A required member in state:

```text
held
unavailable
```

cannot be bypassed by `permit-overrides` or by a higher-priority member under `priority-order`.

This preserves the difference:

```text
required member present != required member conclusively evaluated
```

An explicit `permit-overrides` profile may still resolve `authorized` versus `denied`; H1 does not silently turn it into deny-overrides.

## H2. Consumed E10 state vocabulary

Every E10 decision selected by an E13 request must use one of the E10 states:

```text
authorized
denied
held
unavailable
```

An unknown upstream state cannot participate in a positive composition merely because another member is authorized.

This is a bounded consumption guard, not a re-proof of E10 authorization semantics.

## H3. Waiver context binding

An active `obligation-waiver` must use an E10 authorization bound to the exact composition context:

```text
waiver proposal.context == request.context
waiver decision.context == request.context
waiver decision.context_revision == request.context_revision
E10 context revision == request.context_revision
```

Thus an otherwise authorized waiver from another context or stale context revision cannot silently waive an obligation in the current composition.

## Boundary

E13-H0.2 remains static and offline. It does not establish live policy applicability, trusted time, legal waiver validity, semantic equivalence between policies, or E12 commit safety.
