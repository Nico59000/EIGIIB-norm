# M0-A15

M0-A15 registers a fail-closed verifier for long-term maintenance history witnessed through three independent registries. It detects conflicting heads or governance snapshots, freezes reconciliation on divergence, requires witness quorum and preserves every candidate lineage until an append-only reconciliation record identifies the authoritative continuation.

The baseline contains no live registry receipt, witness endorsement, split-brain event or reconciliation certificate. Therefore the current decision is `NF`.

A future positive result is bounded to the observed registry history and does not imply future registry agreement, future governance stability or universal absence of split brain.
