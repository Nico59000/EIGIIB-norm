# M0-A15-F1 operator runbook

1. Check out a descendant of exact M0-A15 head `a39a3865dfe27fe394345e6fb7e9030c37f25203` with complete Git history.
2. Keep all private keys and live evidence outside the repository.
3. Register exactly three registry profiles, five witness profiles and at least two readback-observer profiles with distinct declared control dimensions and unique Ed25519 keys.
4. Supply the complete A14 continuity case; do not supply an A14 result flag. The checker replays the exact frozen historical verifier.
5. Sign each registry receipt over its canonical payload. Never provide a trusted receipt digest; the checker derives it.
6. Sign witness endorsements over the derived A14 replay, checkpoint, reconciliation, governance and certificate digests.
7. On divergent authenticated receipts, preserve all candidate views. Provide the derived proof object exactly; the checker rejects fabricated support or quarantine sets.
8. Provide signed readbacks for the authoritative published state and every quarantined registry state, using at least two independent observer profiles.
9. Validate the external evidence file with `python tools/eigiib_m0_a15_f1_check.py . --evidence /secure/path/authenticated-history.json --require-verified`.
10. Preserve the report, evidence digest, exact Git head and execution environment outside the repository.
