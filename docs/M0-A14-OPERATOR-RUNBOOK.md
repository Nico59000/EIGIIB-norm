# M0-A14 operator runbook

1. Confirm M0-A13 is genuinely `T` and preserve its closure certificate.
2. Record every cycle with contiguous sequence, exact predecessor and successor refreeze digests, exact scope and complete closure evidence.
3. Record governance snapshots before authorization. A changed snapshot requires a non-weakening transition approved identically by all three colleges.
4. Exercise and record at least one threshold-valid revocation. Reject all writes at or after its effective time and close that cycle by rollback or bounded successor refreeze.
5. Require at least three cycles spanning 2,592,000 seconds, then issue an independent continuity certificate.
6. Run `python tools/eigiib_m0_a14_check.py . --require-verified` only on the evidence-bearing exact head.

Never infer elapsed time, approvals, revocation effectiveness, independence or drift absence.
