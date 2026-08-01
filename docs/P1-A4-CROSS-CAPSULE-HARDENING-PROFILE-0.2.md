# P1-A4-H0.2 — Exact Executable-Closure Binding

Status: additive hardening profile for P1-A4. It does not rewrite the baseline and is not a numbered EIGIIB extension.

## Motivation

The P1-A4 baseline binds the ordered checker paths and the tool versions reported by those checkers. That is necessary but not sufficient for an exact replay boundary:

```text
same path + same declared version != same implementation bytes
```

A modified checker could retain its path and `TOOL_VERSION`. P1-A4-H0.2 therefore binds the exact repository bytes of the complete executable closure before accepting a positive baseline replay.

## Exact closure

`tests/fixtures/p1-a4/implementation-set.json` lists, in fixed order:

1. P1-A1 checker;
2. P1-A2 checker;
3. P1-A3 baseline checker;
4. P1-A3-H0.2 checker;
5. P1-A4 orchestrator;
6. P1-A4 contract module;
7. P1-A4 validation module;
8. P1-A4-H0.2 checker itself.

Each entry carries a repository-relative fixed path and a SHA-256 digest plus exact byte length. The hardening checker resolves every path inside the repository and rejects missing files, symlink escape, path substitution, order substitution, malformed identity or byte mismatch.

Including the hardening checker itself closes the otherwise circular omission where the verifier of the closure would remain outside the closure.

## Baseline handoff

Only after the eight implementation identities are valid does H0.2 invoke the unchanged P1-A4 baseline. The baseline result must match the complete positive carrier contract:

```text
manifest_binding_result = conformant
p1a1_replay_result = conformant
p1a2_replay_result = conformant
p1a3_replay_result = conformant
cross_capsule_binding_result = conformant
end_to_end_result = conformant
chain_identity = 8082fbe1...e28a97d / 2182 bytes
```

The hardening profile therefore proves a bounded statement:

```text
these exact repository checker bytes produced a positive P1-A4 fixture replay
```

It does not prove that another interpreter, provider, operating system or live service is equivalent.

## Result carriers

The checker reports separately:

```text
structural_result
implementation_binding_result
baseline_replay_result
hardening_result
```

A malformed or mismatched implementation set suppresses the baseline replay as `not-evaluated`. A valid implementation set with a failed baseline reports `implementation_binding_result = valid` and `baseline_replay_result = invalid`.

## Claim boundary

P1-A4-H0.2 preserves:

```text
byte-exact replay closure != trusted Python interpreter
byte-exact replay closure != trusted OpenSSL provider
implementation identity != source authenticity
exact checker bytes != production environment equivalence
P1-A4-H0.2 != replacement of upstream P1 authorities
```

The profile does not authenticate Git history, attest the runner image, validate Python or OpenSSL provenance, establish hermetic execution, or claim production interoperability.
