# P1-A12 manual review

- [ ] Confirm the exact P1-A11 report and capsule identities.
- [ ] Confirm the transparency-root, two service and four witness SPKI identities.
- [ ] Confirm registration policy signature and `2-of-3` witness threshold.
- [ ] Recompute all leaf, node and checkpoint roots.
- [ ] Verify both size-4 checkpoints are service-signed and quorum-witnessed.
- [ ] Confirm equal service, epoch, sequence and tree size with distinct roots.
- [ ] Confirm `witness-b` signs both conflicting checkpoints.
- [ ] Confirm service epoch 1 and `witness-b` are quarantined.
- [ ] Confirm the root-signed succession to service epoch 2.
- [ ] Confirm the recovered size-8 checkpoint extends the accepted size-4 root.
- [ ] Confirm no private key is present in the published A12 scope.
- [ ] Preserve the distinction between registered-history consistency and global append-only consistency.
