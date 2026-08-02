# M0-A5 — Human Mastery Guide for P1 Authority and E14 Preparation

This guide is for maintainers, reviewers and operators who need to understand what the repository proves before acting on it.

## 1. Start with the authority coordinate

Before reading a result, record four values:

```text
repository
branch
exact commit
slice or extension identifier
```

For the current canonical P1 lineage:

```text
repository: Nico59000/EIGIIB-norm
branch: agent/p1-a20-registered-runner-admission-toolchain-succession-compatibility-rollback
commit: c1983e9f2e95879ee16c162075c8d72bc73d88f9
slice: P1-A20
```

The exact commit is the decisive coordinate. The branch helps locate it but may later move. Pull-request state is workflow metadata, not proof identity.

## 2. Distinguish three questions

A human review must answer these separately:

1. **What is observed?**  
   Which file, digest, signature, receipt, route, runner, policy or external readback was actually evaluated?

2. **What is concluded?**  
   Which bounded result does the owning document permit?

3. **What remains outside the boundary?**  
   Which production, universality, independence, confidentiality or durability claims are not established?

A green workflow answers only the checks that workflow owns.

## 3. Read the lineage by crossing

| Range | Crossing under control | Human question |
|---|---|---|
| P1-A1–A4 | carrier and capsule representation | Did the claim survive transport without strengthening? |
| P1-A5–A7 | implementation and parser diversity | Did independent routes agree inside the frozen corpus? |
| P1-A8–A14 | release lifecycle | Are identity, authorization, time, transparency, revocation and remediation all satisfied for this release state? |
| P1-A15–A16 | live external egress and readback | Was the published external object read back and rebound to the intended identity? |
| P1-A17 | persistence and restoration | Was the declared object recoverable under the tested retention and restore model? |
| P1-A18 | release governance | Were the declared roles, thresholds and emergency conditions satisfied? |
| P1-A19–A20 | profile, runner and toolchain admission | Is the exact profile, runner identity and toolchain version admitted in the declared window? |

Do not skip a crossing because a later file exists. Later slices consume earlier bounded facts; they do not erase their conditions.

## 4. Use a conservative four-state decision

For a required input, use:

- `permit` — every required condition for this crossing is positively satisfied;
- `deny` — an explicit rule rejects the operation;
- `held` — information is present but incomplete, conflicting or awaiting a required obligation;
- `unavailable` — the required observation cannot currently be obtained.

Do not convert `held` or `unavailable` into `permit` for operational convenience.

## 5. Freeze context before evaluation

Record the policy revision, purpose, audience, operation identity and source evidence identity before deciding.

A change to any of these values creates a new evaluation:

```text
policy revision
purpose
audience
operation
source artifact
revocation observation
```

Reusing the previous decision after such a change is not a continuation; it is a new crossing.

## 6. E14 preparation checklist

Before selective disclosure work begins, confirm that all eight handoff inputs have named owners:

- full evidence artifact;
- disclosable projection;
- cryptographic commitment;
- disclosure policy;
- authorized audience;
- evaluation context;
- correlation controls;
- revocation state.

Then ask:

- Can the disclosed view be rebound to the declared source?
- Can the projection accidentally strengthen the source claim?
- Is every omitted field authorized by the policy?
- Does the audience match the evaluated purpose?
- Can identifiers correlate contexts that were intended to remain separate?
- Has any source, policy or authorization been revoked or withdrawn?

A missing answer holds the disclosure decision.

## 7. Claims M0-A5 does not make

M0-A5 does not establish:

- confidentiality of storage;
- anonymity;
- unlinkability;
- zero-knowledge disclosure;
- post-quantum resistance;
- long-term cryptographic validity;
- universal interoperability;
- platform-enforced separation of duties;
- provider-independent durability.

These require later, explicit authorities.

## 8. Change-control rule

When the canonical P1 head changes:

1. do not edit the old commit;
2. add a new lineage revision;
3. identify the exact predecessor and successor;
4. rerun the M0-A5 gate;
5. review every changed crossing;
6. update the E14 handoff only when its source coordinate changes;
7. preserve prior records for audit and rollback.

The safe human posture is: **exact identity first, boundary second, action last**.
