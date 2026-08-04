# M0-A15 operator runbook

1. Confirm M0-A14 is genuinely `T`.
2. Register three registries with distinct values for every required independence dimension.
3. Register five witnesses independent from all registry identity roots and control domains.
4. Collect one receipt from every registry for every checkpoint.
5. Require four witness endorsements over one canonical checkpoint digest.
6. Freeze on any divergent head, snapshot or receipt predecessor.
7. Reconcile only from a common ancestor with two supporting registries, witness quorum, quarantine, stale-head rejection and independent readback.
8. Preserve all divergent receipts and reconciliation records append-only.
9. Run `python tools/eigiib_m0_a15_check.py . --require-verified`.
10. Perform independent manual readback before any `T` declaration.
