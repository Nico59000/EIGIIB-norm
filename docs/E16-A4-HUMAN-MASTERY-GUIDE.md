# E16-A4 Human Mastery Guide

## Review objective

Confirm that the repository distinguishes authorization, migration, observation, loss, quarantine and recovery replay instead of compressing them into one implicit success claim.

## Required review sequence

1. Verify the exact E16-A3 source commit and isolated replay result.
2. Check the succession authorization against the exact positive E16-A3 decision commitment.
3. Check predecessor and successor custodian and replica identities separately.
4. Verify that the target generation is strictly newer than the source generation.
5. Verify the migration observation independently from the migration plan.
6. Read every loss report, including reports affecting only the superseded source.
7. Read every quarantine record; release never erases the historical quarantine.
8. Verify that the recovery replay is strictly ordered and duplicate-free.
9. Verify that the candidate generation is not below either the accepted generation or the declared minimum.
10. Confirm that superseded commitments are explicitly bound.
11. Recompute the seven gates and compare them with the stored decision.
12. Re-read the nonclaims before interpreting a positive decision.

## Positive interpretation

`successor-replica-recovered` means only that the represented successor target passed the bounded repository checks for the represented recovery replay.

It does not mean:

- that the predecessor bytes were destroyed;
- that the successor has legal custody;
- that all losses were detected;
- that future rollback is impossible;
- that future retention or restoration will succeed.

## Negative-evidence discipline

A negative migration observation, confirmed target loss, active target quarantine or generation rollback is a denial even when another source is unavailable or a review is held.

Do not downgrade known negative evidence to uncertainty.

## Source-loss containment

A confirmed source loss can coexist with a positive successor recovery only when:

- the migration observation is positive;
- the target is not lost or quarantined;
- the recovery replay is positive;
- the target generation is strictly newer;
- the old source commitment remains explicitly superseded.

The loss remains part of history.
