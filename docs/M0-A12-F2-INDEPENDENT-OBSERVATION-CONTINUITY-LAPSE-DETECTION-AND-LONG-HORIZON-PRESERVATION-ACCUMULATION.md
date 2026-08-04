# M0-A12-F2 — Independent Observation Continuity, Lapse Detection and Long-Horizon Preservation Accumulation

M0-A12-F2 is stacked exactly on M0-A12-F1 head `eaa64be6c27d30ceba7762ecf1ec7f93fe805745`. The tranche does
not treat the F1 gate as a completed external activation. Its baseline state is
blocked until the F1 closure ledger records a real point-in-time closure in `T`.

The registered bounded profile observes campaign `eigiib-m0-a11-external-preservation-observation-v1` from sequence 1
through sequence 30. Sequence 1 is inherited from the F1-bound M0-A12 evidence;
F2 admits exactly sequences 2 through 30. The cadence is 86,400 seconds, grace
is 21,600 seconds, and lapse is reached 172,800 seconds after the expected due
time. A positive accumulation decision requires 30 accepted observations,
at least 2,505,600 elapsed seconds, no observation beyond grace, no lapse, and
checkpoints at sequences 7, 14, 21 and 28.

For every observation `i > 1`, the sequence is contiguous, the previous digest
equals the accepted digest of `i-1`, and time strictly increases. Each
observation covers both immutable channels, the exact E16 stable-bundle digest,
retention-policy readback and resolvable evidence references. Checkpoints also
bind a retention-attributed deletion denial and an exact restore readback for
each channel.

Let `d = lastObservedAt + cadence`. The state is `current` no later than `d`,
`grace` through `d + grace`, `overdue` before `d + lapseAfter`, and `lapsed`
thereafter. A later observation does not erase a recorded lapse.

A `T` result means only that this registered bounded window has been observed
continuously and is current at evaluation time. It does not guarantee the next
observation, perpetual provider operation, universal failure independence,
legal durability or E17 readiness.
