# P1-A9-F1 — Append-Only Runner Distribution Succession, Multi-Generation Toolchain Registration and Exact Compatibility Replay

P1-A9-F1 replaces the former two-generation Windows compatibility switch with an ordered, append-only registry of exact runner distributions.

## Authority boundary

A registered generation binds an exact `ImageVersion` and exact `git --version` to one immutable A7.7 toolchain policy snapshot. Each successor names its immediate predecessor and declares the exact Windows fields changed from that predecessor. Non-Windows platform records and all top-level toolchain invariants remain byte-equivalent across the succession.

Registration does not imply trust in future images, universal Windows portability, or equivalence of an unregistered toolchain. Unknown `(ImageVersion, git)` pairs fail closed.

## Current succession

- generation 0: `20260714.173.1 | git version 2.55.0.windows.2`;
- generation 1: `20260728.188.1 | git version 2.55.0.windows.3`;
- generation 2: `20260803.193.1 | git version 2.55.0.windows.3`.

Generation 2 changes only `imageVersion` relative to generation 1. Its admission is bounded by exact A7.1–A7.7 and P1-A8 replay on the observed runner; it is not a wildcard for later `windows-2025` images.

## Replay rule

The selector validates the full predecessor chain before returning a policy. P1-A7.7 and P1-A8 consume the same registry. A new GitHub runner image therefore remains `NT` for compatibility until a new append-only generation is explicitly registered and replayed.
