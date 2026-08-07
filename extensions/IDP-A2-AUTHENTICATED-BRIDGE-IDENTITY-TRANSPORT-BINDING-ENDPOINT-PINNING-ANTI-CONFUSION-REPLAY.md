# EIGIIB-IDP-A2 — Authenticated Bridge Identity, Transport Binding, Endpoint Pinning and Anti-Confusion Replay

Status: draft normative successor slice 0.1, stacked above IDP-A1 head `ec352636690ee22135cfc7a3d3e2067ee323f2cf`.

## 1. Purpose

IDP-A2 closes the structural ambiguity between a permitted IDP-A1 bridge channel and the identity/transport context allowed to carry it.

```text
bridge name != authenticated principal
authenticated principal != root authority
transport encryption != endpoint identity
endpoint identity != route authorization
valid pin != correct direction
valid key != correct role
same bytes on another route != same authorized context
structural pinning model != deployed pin
```

A2 does not create the future local Git server or private GitHub bridge. It defines the exact relation those operational endpoints must later instantiate.

## 2. Source boundary

A2 binds exactly to:

```text
IDP-A1 head       ec352636690ee22135cfc7a3d3e2067ee323f2cf
IDP-A1 policy     conformance/idp-policy.json
IDP-A1 blob       7aac9aa7223eadd3739c0b59d4275eeed58bb3d1
```

A2 does not modify the A1 classification relation and does not modify M0-A15-F2.

## 3. Principal model

Every route participant is an explicit principal with:

- role;
- root-authority bit;
- control-domain identifier;
- identity root;
- operational state;
- asymmetric authenticator identifier and SHA-256 public-key fingerprint.

The current registry is `structural-only`. Its fingerprints are synthetic conformance fixtures, not production keys.

Exactly one principal may assert root authority: `l0-local-authority`.

No bridge or restricted-review principal can inherit root authority by transport, storage, signature, mirroring, or successful authentication.

## 4. Route separation

A2 defines three route bindings:

```text
private-bridge-out     outbound       D0-D3
private-bridge-return  inbound        D0-D3
restricted-review      bidirectional  D4
```

Each route has distinct:

- local principal;
- remote principal;
- local endpoint;
- remote endpoint;
- remote pinset;
- transport profile.

Cross-route reuse is forbidden in A2 to make role confusion fail closed.

## 5. Endpoint binding

An endpoint binds:

```text
channel
side
purpose
expected principal
locator state
locator
pinset
operational state
```

For the structural registry every locator is deliberately `unbound`, every locator value is `null`, and every endpoint is `planned`.

Therefore:

```text
A2 structural endpoint != reachable endpoint
A2 endpoint id != DNS name
A2 endpoint id != SSH host
A2 endpoint id != TLS service
```

Operational promotion requires a later exact locator binding.

## 6. Transport binding

Every route has an exact transport profile binding:

- `private-bridge-out` → outbound SSH family;
- `private-bridge-return` → inbound SSH family;
- `restricted-review` → bidirectional TLS family.

All profiles require:

```text
mutual asymmetric authentication
confidentiality
integrity
endpoint pinning
channel binding
```

These are requirements, not evidence that the current environment satisfies them.

## 7. Pinsets

Every remote endpoint has one route-specific SHA-256 pinset.

A pinset commits canonically to:

```text
pinset id
endpoint id
algorithm
ordered pins
synthetic flag
```

The structural registry uses synthetic fingerprints only. Operational A2 evidence must set `synthetic=false` and bind real endpoint material; this slice does not fabricate it.

## 8. Anti-confusion context commitment

Each route stores a SHA-256 commitment over the exact canonical tuple:

```text
channelId
direction
localPrincipalId
remotePrincipalId
localEndpointId
remoteEndpointId
transportProfileId
expectedPinsetId
allowedClasses
```

This prevents an implementation from treating a valid identity or pin as route-agnostic.

Changing any member without recomputing the context commitment fails immediately. Recomputing the commitment after an unauthorized substitution still fails semantic route checks.

## 9. Required anti-confusion failures

A2 rejects at least:

1. bridge principal asserting root authority;
2. role substitution;
3. endpoint substitution;
4. direction substitution;
5. transport-profile substitution;
6. remote-pinset substitution;
7. D5 bridge overreach;
8. a structural endpoint presented as already bound;
9. cross-route principal reuse.

The frozen matrix contains a positive vector plus each negative family.

## 10. Operational promotion boundary

A future operational registry may only become positive when:

- all required locators are exact and bound;
- principal authenticators are non-synthetic;
- remote pinsets are non-synthetic;
- route bindings are marked operational;
- transport evidence is collected independently;
- actual peer authentication and pin verification succeed.

A2-A1 structural conformance alone never supplies these facts.

## 11. Machine authority

```text
conformance/idp-a2-bridge-binding.json
schemas/idp-a2-bridge-binding.schema.json
tools/eigiib_idp_a2_check.py
tools/eigiib_idp_a2_independent.py
tools/eigiib_idp_a2_matrix.py
conformance/idp-a2-verifier-matrix.json
```

The reference and independent implementations do not import one another.

## 12. Result relation

```text
CONFORMANT
NON_CONFORMANT
```

For the current structural registry, `CONFORMANT` means only that bridge identities, route roles, endpoints, transports, pins and context commitments satisfy A2's structural relation.

It does not mean any route is reachable or secure in production.

## 13. HT+NT boundary

Current intended state:

```text
principal/role model                  T (structural)
route separation                      T (structural)
endpoint/direction binding            T (structural)
transport requirement binding         T (structural)
synthetic pinning relation             T (structural)
anti-confusion replay                 T (structural)

local Git locator                     NT
private GitHub bridge locator         NT
production bridge key                 NT
production endpoint pin               NT
live peer authentication              NT
live transport confidentiality        NT
restricted-review live transport      NT
```

## 14. Successor

The natural successor is:

**IDP-A3 — Audience Grants, Institutional Eligibility, Expiry, Revocation and Return-Quarantine Promotion.**
