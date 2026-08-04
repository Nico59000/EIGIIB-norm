# M0-A12-F3 — Independent Multi-Observer Differential Continuity and Custodian Succession Replay

## Authority

This tranche is stacked exactly on M0-A12-F2 head `597ba0931d3510b01136d8ca6c6075ee106a7f19`. It establishes a fail-closed verifier for seven paired observation rounds, a second independent observer, one bounded primary-custodian succession, and explicit stale-authority rejection.

## Formal gate

The live replay can close only after F2 is genuinely accumulated in `T`. Sequences 31 through 37 must be observed independently by both registered observers, with zero semantic mismatch and no cadence lapse. The primary custodian changes at sequence 34 while the secondary custodian remains the continuity anchor.

## Claim boundary

A positive result establishes only a bounded differential window and one registered succession replay. It does not guarantee future continuity, all possible custodian transitions, catastrophic recovery, or E17 adoption.
