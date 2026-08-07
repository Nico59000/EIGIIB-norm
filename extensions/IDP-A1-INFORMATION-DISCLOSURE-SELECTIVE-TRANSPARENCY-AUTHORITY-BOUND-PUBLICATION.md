# EIGIIB-IDP-A1 — Information Disclosure, Selective Transparency and Authority-Bound Publication

Status: draft normative profile 0.1, additive to the EIGIIB-E16 authority line and intentionally outside the unfinished M0-A15-F2 operational closure.

## 1. Purpose

IDP-A1 defines a machine-checkable publication boundary between information that may be public, information that may cross a controlled bridge, information that is restricted to named review audiences, and information that must remain local.

The profile specializes distribution without redefining E14 confidentiality or claiming that publication controls make already-public source code impossible to modify.

```text
transparency != unrestricted disclosure
classification != proof of harmful capability
private repository != local root authority
bridge transport != authority transfer
public commitment != secret payload
policy conformance != transport confidentiality
open-source release != enforceable downstream behavior
```

## 2. Functional position

IDP consumes, but does not replace, existing boundaries:

```text
E14 selective disclosure / release boundary ----\
E15 external publication / readback -------------> IDP publication-class and channel boundary
E16 custody / preservation ----------------------/
```

E14 decides whether an exact disclosure path is admissible and released inside its declared boundary. IDP decides which distribution class and channel may carry an artifact or a derived artifact. E15/E16 remain responsible for external delivery, readback, custody and durability claims.

IDP-A1 changes no E14, E15, E16 or M0-A15-F2 decision relation.

## 3. Classification lattice

Classes are identifiers for disclosure handling, not scientific merit or universal danger levels.

| Class | Name | Visibility | Restriction rank | Default role |
|---|---|---|---:|---|
| D0 | Public News | public | 0 | milestones, public status and bounded announcements |
| D1 | Public Normative | public | 0 | specifications, schemas, interfaces, claim boundaries and threat models |
| D2 | Public Open Implementation | public | 0 | code, SDKs, public tests and synthetic interoperability vectors intentionally released under an applicable repository licence |
| D3 | Controlled Engineering | controlled | 1 | non-public engineering material and advanced implementation details not required for public interoperability |
| D4 | Restricted Critical | restricted | 2 | material whose release may materially lower a capability barrier or expose a restricted scientific/technical domain; named-audience review is required |
| D5 | Operational Secret | secret | 3 | credentials, private keys, recovery secrets, internal security topology and equivalent operational secret material |

D0, D1 and D2 have the same visibility rank. Their distinction is semantic surface, not increasing secrecy.

## 4. Capability-based classification

A D4 decision must be based on a bounded capability review, not on sophistication alone. Relevant questions include whether publication materially changes:

- the expertise required to reproduce a capability;
- the time or resources required to operationalize it;
- the scale or automation available to an operator;
- the ability to bypass safeguards or validation boundaries;
- the exposure of a restricted scientific or technical domain.

A positive answer does not automatically establish D4. It creates a review obligation. The classification authority records the decision and its claim boundary.

D5 is not a capability classification. It is an operational-secret class.

## 5. Repository and channel topology

IDP-A1 defines logical channel kinds. It does not claim that any future local endpoint or private GitHub bridge is already deployed.

```text
L0 local authority
├── public-facade              D0-D2, outbound, non-authoritative
├── private-bridge-out         D0-D3, outbound, non-authoritative
├── private-bridge-return      D0-D3, inbound, quarantined, non-authoritative
└── restricted-review          D4, named audience, quarantined on return

D5: L0 only
```

The local authority is the only complete root. A bridge may transport an authorized capsule; it may not become an authority merely because it stores or forwards that capsule.

## 6. Cross-class repository separation

A classification boundary must not rely only on a subdirectory of one Git history when the more restrictive history could thereby remain recoverable.

Production repositories spanning materially different disclosure classes must use a separation mechanism that prevents lower-class recipients from obtaining higher-class history. Separate repositories or separately generated capsules are the default IDP-A1 model.

## 7. Derived disclosure artifacts

A class change never mutates the identity of the source artifact.

For source artifact `A` and released derivative `B`:

```text
A != B
id(A) != id(B)
derivedFrom(B) = id(A)
```

Any decrease in restriction rank requires:

- a new artifact identity;
- method `minimized-derivation`;
- a non-empty claim boundary;
- an explicit disclosure-authority decision;
- at least one approval identifier;
- target-channel admissibility for the target class.

This is a derivation claim only. It does not prove that omitted information cannot be inferred from the derivative.

## 8. D5 non-exportability

IDP-A1 forbids D5 payloads and per-artifact D5 identifiers from external bridge or public-artifact registries.

D5 may be described only at aggregate policy level outside L0. IDP-A1 therefore does not provide a D5 declassification route.

Future work may refine internal secret rotation and recovery without weakening this external non-export boundary.

## 9. Bridge-out boundary

`private-bridge-out` is an outbound transport surface for D0-D3 only.

A D3 object crossing the bridge must be a specifically authorized transport artifact or derivative. A synchronized mirror of the complete local authority is not conformant merely because the destination repository is private.

The bridge has no merge or reclassification authority over L0.

## 10. Bridge-return boundary

Every artifact arriving through `private-bridge-return` is `quarantined` by default.

```text
received != trusted
valid signature != authorized merge
reviewed patch != local authority
```

Promotion from quarantine to an L0 state is a separate local decision and remains outside IDP-A1 operational claims.

## 11. Restricted review boundary

D4 uses `restricted-review` only. The channel requires a named audience and remains non-root.

IDP-A1 specifies the structural requirement only. It does not establish identity proofing, transport encryption, recipient authorization or institutional eligibility. Those are assigned to later IDP slices and remain `NT` until operationally bound.

## 12. Public façade

A public façade may carry D0-D2 payloads.

For D3-D5, public transparency must be derived and bounded. A public notice may state policy-level status, existence classes or review state only when separately authorized. IDP-A1 does not require publication of per-artifact identifiers for D4 and forbids them for D5.

The public façade is not an authority over withheld artifacts.

## 13. Commitments and metadata minimization

IDP-A1 distinguishes:

```text
content-digest          exact byte commitment suitable for intentionally public or controlled material
opaque-randomized       non-content-addressable commitment mode for restricted review metadata
none                    no externally reusable per-artifact commitment
```

D4 external metadata must not use a raw content digest. D5 external per-artifact commitments are forbidden.

The profile does not prescribe one cryptographic construction for `opaque-randomized`; therefore the presence of that label is not cryptographic proof. A later cryptographic-binding slice must define and verify the construction before operational `T` can be claimed for it.

## 14. Licence boundary

IDP classification does not grant a software licence.

D0-D2 material is open source only when the repository or artifact licence actually grants open-source rights. Material retained in D3-D5 is not open-source merely because the project has an open-source objective.

IDP does not claim that a conformant implementation can prevent a recipient from modifying code after an open-source release.

## 15. Machine authority

The structural machine authority is:

```text
conformance/idp-policy.json
```

Its closed schema is:

```text
schemas/idp-policy.schema.json
```

Reference and independent checkers are:

```text
tools/eigiib_idp_check.py
tools/eigiib_idp_independent.py
```

The frozen vector matrix is:

```text
conformance/idp-a1-verifier-matrix.json
```

## 16. Required invariants

IDP-A1 mechanically enforces:

1. exactly one complete root channel: `local-authority`;
2. public payload classes are exactly D0-D2;
3. D5 cannot appear on an external channel;
4. bridge channels cannot be roots;
5. inbound bridge objects are quarantined;
6. D4 may cross only `restricted-review`, with named-audience metadata and no raw content digest;
7. any class change uses a new artifact identity;
8. any reduction in restriction rank has an approved minimized derivation;
9. D5 has no outward derivation path;
10. publication/bridge status never proves transport confidentiality or recipient authorization.

## 17. Result relation

The checker result is structural:

```text
CONFORMANT
NON_CONFORMANT
```

`CONFORMANT` means only that the supplied IDP registry satisfies this profile.

It does not mean:

- a private bridge exists;
- a local Git server exists;
- a transport is encrypted;
- an institution is eligible;
- an artifact is harmless;
- all sensitive information has been identified;
- an open-source fork must preserve EIGIIB controls.

## 18. Adoption boundary

`conformance/idp-a1-adoption-transition.json` records that IDP-A1 is additive above the M0-A15-F2 head used as its source and does not edit the active F2 authority set.

The current operational states are intentionally:

```text
localGitEndpointBound          = false
privateBridgeOperational       = false
restrictedReviewOperational    = false
publicFacadeOperationalBinding = false
```

These false values are not defects. They prevent architectural intent from being reported as deployed evidence.

## 19. Planned successor slices

The natural successors are:

- **IDP-A2** — authenticated bridge identity, transport binding, endpoint pinning and anti-confusion replay;
- **IDP-A3** — audience grants, institutional eligibility, expiry, revocation and return-quarantine promotion;
- **IDP-A4** — public transparency records, opaque commitment construction, withdrawal and anti-correlation disclosure;
- **IDP-A5** — independent cross-platform verifier matrix, authority freeze and public/private boundary finalization.
