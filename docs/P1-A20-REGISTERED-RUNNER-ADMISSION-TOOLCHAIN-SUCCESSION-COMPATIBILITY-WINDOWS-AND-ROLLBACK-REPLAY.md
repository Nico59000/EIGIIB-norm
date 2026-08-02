# P1-A20 — Registered Runner Admission, Toolchain Succession, Compatibility Windows and Rollback Replay

## Scope

P1-A20 is an additive replay slice over exact P1-A19-F2 commit `66b25d4f27ded3e273922f9fdcf80b9c88c8c808`.

It defines a closed fixture registry for three named runner identities, four toolchain profiles, one Go succession event, a bounded compatibility window and a bounded rollback route. It does not claim access to or enforcement of GitHub-hosted runner administration.

## Registered runners

The fixture admits exactly:

- `gha-ubuntu-24.04-x64`;
- `gha-macos-15-arm64`;
- `gha-windows-2025-x64`.

Each runner is active at the captured epoch and admits the same canonical toolchain set: Python 3.13, Go 1.26 and OpenSSL 3.

## Toolchain succession

The declared succession moves Go from profile `go-1.25` to `go-1.26` at epoch 2. Compatibility and rollback remain permitted through epoch 4. The captured epoch is 3.

Python 3.13.14 is exact. OpenSSL 3 is represented by a bounded numeric 3.x window because the hosted images expose different patch releases.

## Replay routes

Six routes are replayed:

1. current Linux toolchain acceptance;
2. macOS compatibility-window acceptance;
3. current Windows toolchain acceptance;
4. authorized Go rollback inside the window;
5. unregistered runner rejection;
6. expired rollback rejection.

Twenty negative mutations cover registry identity, duplicate runners and routes, inactive or future admission, canonical toolchain sets, unknown predecessors, reversed version and epoch windows, unauthorized rollback, expired compatibility, and decision or reason substitution.

## Validation

The workflow runs on Ubuntu 24.04, macOS 15 and Windows 2025 with Python 3.13.14. Every platform must reproduce the exact report and bind its operating system to one of the three named fixture runners.

## Decision boundary

Boundary: `registered-fixture-runner-admission-toolchain-succession-window-and-rollback-replay-closure`.

Conformant within the boundary:

- three named fixture-runner admissions;
- declared Python, Go and OpenSSL toolchain profiles;
- one bounded Go succession window;
- compatibility acceptance and rollback acceptance/rejection replay;
- deterministic multi-platform report reproduction.

Not claimed:

- live administrative registration of hosted runners;
- cryptographic hardware or platform attestation of runner identity;
- prevention of platform-operator substitution;
- compatibility with future unregistered runners;
- universal toolchain succession compatibility.
