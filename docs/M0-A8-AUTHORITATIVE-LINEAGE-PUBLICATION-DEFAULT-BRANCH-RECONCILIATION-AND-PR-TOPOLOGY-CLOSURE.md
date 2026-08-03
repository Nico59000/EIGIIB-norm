# M0-A8 — Authoritative Lineage Publication, Default-Branch Reconciliation and PR-Topology Closure

## Purpose

M0-A8 normalizes how the repository exposes the exact closed E16 lineage without rewriting historical authorities or implying a merge into the default branch.

## Source boundary

The sole source is E16-A5 head `fc3f8402bfbe447227f5777bad92b620c7bcb350`, closed by PR #153 under profile `EIGIIB-E16-1.0` with 95 frozen authorities.

M0-A8 is repository governance infrastructure. It is not an E17 extension and does not add custody, retention, recovery or release semantics.

## Publication roles

Three branch roles are kept separate:

```text
main
  = legacy default branch
  != current normative lineage

stable/eigiib-e16-1.0
  = exact published E16 stable lineage
  != default branch migration

agent/m0-a8-...
  = additive governance successor
  != rewrite of E16-A5
```

The stable branch points exactly to the E16-A5 closure head. `main` is not moved and no merge is authorized.

## Pull-request topology

The machine authority records the contiguous stacked route from M0-A5-F1 through E16-A5. Each slice consumes the exact preceding head.

Direct cumulative PRs #141, #145, #147 and the automatically opened stable-publication PR #155 targeted `main` and were closed unmerged. Their branch heads remain unchanged; only the non-authoritative review surfaces were closed.

The policy rejects an `agent/` branch targeting `main` unless a future authority explicitly admits that exact head. Unknown direct-to-default state is negative, not permissive.

## Historical status supersession

The E15 root document contains an older human-readable status line. That file is part of the descendant frozen lineage. M0-A8 therefore does not rewrite it silently.

Current E15 status is owned by:

- `conformance/e15-final-closure.json`;
- `conformance/e15-a5-authority-freeze.json`;
- the active profile in `EIGIIB.toml` at the E16-A5 source head.

The stale line is recorded as historical text superseded by those authorities.

## Reconciliation result

The normalized result is:

```text
lineage-publication-normalized
```

It means that default-branch identity, stable normative publication and active governance succession are no longer overloaded into one branch role.

## Nonclaims

M0-A8 does not:

- move the default branch;
- authorize a merge or release;
- prove external durability of a Git branch;
- prevent repository administrators from moving refs;
- universally prevent accidental pull requests;
- rewrite historical E14, E15 or E16 authorities.
