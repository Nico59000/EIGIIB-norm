# M0-A12-F2 manual review authority

## Exact lineage

- base branch: `agent/m0-a12-f1-bound-external-evidence-ingress-point-in-time-activation-closure`;
- exact base head: `eaa64be6c27d30ceba7762ecf1ec7f93fe805745`;
- no historical E14, E15, E16, P1 or M0 head may be moved or rewritten.

## Baseline review

The initial tranche is valid only when F1 remains `not-closed`, no
`evidence/m0-a12-f2` tree is committed, the ledger is empty, the report is `NF`,
and `--require-accumulated` exits with code 2.

## Live accumulation review

A future `T` decision additionally requires genuine F1 closure in `T`, exact
sequence 2 through 30, valid detached observer signatures, strict digest-chain
and timestamp continuity, both immutable channels in every observation,
checkpoints at 7, 14, 21 and 28, at least 2,505,600 elapsed seconds, zero
overdue observations, zero lapses, a current or grace state at review time, a
valid derived continuity certificate and all final-head workflows in success.

## Prohibited interpretation

Thirty observations are a bounded registered window, not a perpetual guarantee.
A future lapse invalidates current continuity without rewriting the historical
window. F2 does not authorize E17 adoption.
