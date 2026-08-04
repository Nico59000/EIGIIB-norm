# M0-A12-F2 operator runbook

Do not begin a live F2 campaign until M0-A12-F1 is genuinely closed in `T` on
exact head `eaa64be6c27d30ceba7762ecf1ec7f93fe805745` and its external references remain resolvable.

Baseline replay:

```bash
python -m unittest -v tests/test_eigiib_m0_a12_f2.py
python tools/eigiib_m0_a12_f2_check.py . --output m0-a12-f2-baseline.json
```

Expected baseline is `conformant-blocked-prerequisite`, `f1-closure-pending`,
`NF`, and lapse state `blocked`. `--require-accumulated` must exit 2.

After F1 closure, append one independently signed observation per cadence under
`evidence/m0-a12-f2/observations/000002.json` through `000030.json`, each with a
detached `.sig`. Never rewrite an accepted observation.

Sequences 7, 14, 21 and 28 must verify retention-policy readback,
retention-attributed deletion denial, exact restore readback and resolvable
evidence references for both channels.

Use `--as-of` with an explicit UTC time for reproducible review. A static
certificate does not suppress future lapse detection. Abort or classify `NT`
when F1 is not closed, a sequence is missing, a digest or signature fails,
either channel is absent, an observation exceeds grace, a checkpoint is
incomplete, a lapse is detected, or the certificate differs from the derived
chain.
