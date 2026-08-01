# P1-A5-H0.2 — Exact Independent Source and Matrix Execution Closure

P1-A5-H0.2 is an additive hardening profile for P1-A5. It does not create a numbered `E*` extension and does not replace P1-A1 through P1-A5 authorities.

The baseline P1-A5 matrix proves agreement between the Python/OpenSSL P1-A4-H0.2 route and an independently implemented Go route on Linux, macOS and Windows. H0.2 closes a narrower substitution gap: the same route name, Go version and workflow label do not identify the exact sources and matrix configuration that were replayed.

Before invoking the unchanged P1-A5 checker, H0.2 verifies SHA-256 and byte length for the closed set of fourteen files: the Go module and runtime sources, the Python differential checker, the P1-A5 matrix and canonical result, structural state, line-ending policy, cross-platform workflow and the H0.2 checker itself.

The workflow actions are pinned to exact commits. The manifest also fixes Go `1.26.5`, Python `3.13`, the reference OpenSSL mode and the three required runner labels.

A positive H0.2 result requires exact implementation binding followed by a positive P1-A5 baseline result. Any missing file, symlink, path escape, byte mismatch, action substitution, toolchain declaration change, unavailable route or differential divergence is non-conformant.

This profile does not identify the downloaded Go or Python binaries byte-for-byte, does not authenticate the GitHub runner image, does not prove action-source authenticity from a commit hash alone, does not establish independent trust roots, does not imply production equivalence and does not promote verifier agreement into EIGIIB claim truth.
