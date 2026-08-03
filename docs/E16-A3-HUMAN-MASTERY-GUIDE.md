# E16-A3 Human Mastery Guide

## What this slice establishes

E16-A3 gives a verifier a typed path from one exact positive E16-A2 placement decision to:

1. one declared retention window;
2. one represented opening observation;
3. one represented closing observation;
4. one declared-role-separated readback;
5. one restore attempt;
6. one declared-role-separated restore verification;
7. one derived repository decision.

Every link carries identifier, revision and canonical commitment.

## What the window means

The opening and closing timestamps are represented UTC claims under a declared clock basis. They are not automatically trusted external time.

Positive opening and closing observations establish that the represented content was positively observed at two represented events. They do not prove continuous survival between those events.

## What “independent” means here

The repository requires distinct declared identities and control-domain labels for reader versus custodian and verifier versus executor.

That requirement prevents silent same-role reuse. It does not prove actual independence, different ownership, different infrastructure or resistance to collusion.

## Decision precedence

`deny` precedes `unavailable`, which precedes `held`, which precedes `permit`.

A known negative digest, boundary, role-separation, readback or restore result therefore cannot be converted into a weaker uncertainty state.

## Review focus

Human review should inspect:

- whether the selected E16-A2 placement decision is the intended one;
- whether the declared window is meaningful for the policy;
- whether boundary evidence actually represents the declared boundaries;
- whether reader/custodian and verifier/executor separation declarations are credible;
- whether restore targets were isolated and disposable;
- whether evidence references remain retrievable;
- whether any external time or independence assertion is being overstated.

## Later slices

E16-A4 owns succession, migration, loss, quarantine and anti-rollback recovery.

E16-A5 owns independent verifier diversity, differential restore replay and final freeze.
