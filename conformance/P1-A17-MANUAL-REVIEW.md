# P1-A17 manual review

- [x] Exact P1-A16 commit, report, capsule and OCI manifest are bound.
- [x] The protected set contains the OCI manifest, configuration and three content layers.
- [x] GHCR is the named primary location.
- [x] GitHub Release `eigiib-p1-a17-recovery-v1` is the named recovery location.
- [x] Recovery Release id, node id, tag, target commit and nine assets are frozen.
- [x] A canonical Ed25519-signed retention policy declares 90 days and seven-day restore audits.
- [x] Policy declaration is separated from platform enforcement.
- [x] The complete set restores from GHCR alone.
- [x] The complete set restores from the GitHub Release alone.
- [x] Cross-location byte identity is exact.
- [x] Current two-location availability is not promoted to a future guarantee.
- [x] GitHub Release and GHCR are not described as provider-independent.
- [x] Administrative deletion prevention and correlated-failure resistance remain unclaimed.
- [x] Python, Go, ORAS and GitHub CLI routes converge on one portable result.
- [x] Only public verification keys are included.
- [x] Boundary: `named-ghcr-primary-github-release-recovery-retention-and-single-location-restore-closure`.
