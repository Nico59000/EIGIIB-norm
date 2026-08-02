# P1-A20 — Registered Runner Admission, Toolchain Succession, Compatibility Windows and Rollback Replay

## 1. Scope and parent authority

P1-A20 is an additive conformance slice over exact P1-A19-F2 commit `66b25d4f27ded3e273922f9fdcf80b9c88c8c808`. It binds the runner and toolchain fixture to the SHA-256 of the unchanged P1-A19 report, `8008f0eb90328a4ff01f1bd4a594f1f7417ecbd3f5c68efdcf07bf801be62c2a`.

The slice demonstrates, inside one declared fixture environment:

- authenticated registration and admission of runner identities;
- explicit active, retired and quarantined runner states;
- authenticated toolchain succession with active, predecessor-compatible and candidate states;
- platform- and generation-specific compatibility windows;
- rejection outside ordinary compatibility windows;
- signed, runner-bound and time-bounded rollback authorization;
- single-use rollback replay rejection;
- byte-exact Python and independent Go convergence.

## 2. Independent authorities

Three Ed25519 authorities are distinct:

1. `p1-a20-runner-registrar-v1` signs the runner registry;
2. `p1-a20-toolchain-registrar-v1` signs the toolchain registry;
3. `p1-a20-rollback-authority-v1` signs the rollback authorization.

Only public keys are committed. The workflow materializes each canonical payload and signature, then verifies all three independently with OpenSSL.

## 3. Runner admission model

The signed registry contains six runners:

- four active runners;
- one retired runner superseded by a later Linux generation;
- one quarantined runner.

Each runner record binds:

- runner identifier;
- platform and architecture;
- generation;
- declared SHA-256 identity;
- admission sequence;
- validity end sequence;
- lifecycle state;
- optional successor identifier.

Admission requires exact registry membership, exact identity digest, active state and a route sequence inside the declared admission window. Registration alone is insufficient: retired and quarantined records remain authenticated but are rejected.

## 4. Toolchain succession model

The signed toolchain registry contains:

- `1.8.0`, the registered predecessor in compatibility state;
- `1.9.0`, the active version;
- `2.0.0-rc1`, a registered candidate that is not admitted for execution.

Each version binds its artifact SHA-256, release sequence, ordinary compatibility window, rollback eligibility end and compatible runner generations by platform.

A registered artifact is not automatically executable. The route must also satisfy state, exact digest, runner platform/generation compatibility and the relevant window.

## 5. Ordinary compatibility and rollback

Ordinary execution accepts an active or predecessor-compatible toolchain only inside its ordinary sequence window. The predecessor remains usable through sequence 130; sequence 131 is rejected as `compatibility-window-closed`.

Rollback is a distinct mode. It does not reopen the ordinary compatibility window. It requires a signed authorization binding:

- authorization identifier;
- exact active-to-predecessor lineage;
- exact runner;
- exact environment;
- not-before and not-after sequence;
- `maxUses = 1`;
- reason digest.

The authorized rollback at sequence 132 is accepted. Reuse of the same authorization at sequence 133 is rejected as `rollback-authorization-replayed`.

## 6. Canonical route matrix

| Route | Expected decision | Reason |
|---|---|---|
| Linux generation 3 with active toolchain | accepted | ordinary admission and window satisfied |
| macOS generation 2 with active toolchain | accepted | ordinary admission and window satisfied |
| Windows generation 2 with active toolchain | accepted | ordinary admission and window satisfied |
| Linux generation 2 with predecessor | accepted | registered compatibility window |
| macOS predecessor at sequence 130 | accepted | inclusive window edge |
| predecessor at sequence 131 | rejected | compatibility window closed |
| signed rollback at sequence 132 | accepted | runner-bound single-use authorization |
| reuse at sequence 133 | rejected | authorization replay |
| retired runner | rejected | retired state |
| quarantined runner | rejected | quarantined state |
| runner identity substitution | rejected | identity mismatch |
| candidate toolchain | rejected | candidate state |
| incompatible Linux generation 2 with active 1.9.0 | rejected | runner/toolchain incompatibility |

## 7. Mutation and schema closure

Thirty semantic mutations cover signature, digest, source binding, admission, lifecycle, toolchain, compatibility and rollback failures. Nine additional Draft 2020-12 schema mutations exercise closed-object enforcement through local `$ref` boundaries.

The dedicated workflow executes 57 Python tests. Repository-wide discovery can import the test module without the optional schema dependency; the schema test class runs only after the locked dependency set is installed by the P1-A20 workflow.

## 8. Independent replay

The Go adapter independently:

- parses and verifies the three Ed25519 signatures;
- validates runner and toolchain registries;
- replays all thirteen decisions in order;
- tracks rollback authorization use;
- recomputes registry and decision digests;
- emits the complete report in canonical JSON.

The Python and Go reports must be byte-identical.

## 9. Decision boundary

Boundary: `signed-runner-admission-toolchain-succession-declared-compatibility-window-single-use-rollback-replay-closure`.

Conformant inside the boundary:

- the signed fixture runner registry;
- declared SHA-256 runner identity binding;
- active, retired and quarantined lifecycle handling;
- the signed active/predecessor/candidate toolchain lineage;
- declared sequence-bounded compatibility matrices;
- signed runner- and environment-bound single-use rollback;
- deterministic Python/Go differential replay.

Outside the boundary:

- hardware-rooted runner identity;
- verification of provider or platform attestation services;
- provider-enforced runner isolation;
- compatibility with every toolchain or future runner;
- automatic admission of future toolchain versions;
- rollback safety beyond the declared fixture and authorization model.
