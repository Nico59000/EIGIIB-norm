# EIGIIB norm

EIGIIB defines a general engineering rule for software and systems projects:

> **Explicit Is Good, Implicit Is Better. Too explicit is never good.**

The repository separates authority by concern instead of repeating the standard.

- [`EIGIIB-STANDARD.md`](EIGIIB-STANDARD.md) — canonical core specification.
- [`extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md`](extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md) — typed evidence, claim boundary, uncertainty, contradiction, and conformance semantics.
- [`extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md`](extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md) — mechanically decidable repository-conformance contract.
- [`schemas/eigiib-e1-record.schema.json`](schemas/eigiib-e1-record.schema.json) — E1 typed registry schema.
- [`schemas/eigiib-e2-ownership.schema.json`](schemas/eigiib-e2-ownership.schema.json) — E2 durable-fact ownership schema.
- [`tools/eigiib_check.py`](tools/eigiib_check.py) — dependency-free Python 3.11+ E2 reference checker.
- [`EIGIIB.toml`](EIGIIB.toml) — this repository's adoption profile.

The checker is intentionally static: it performs no network access and executes no repository-provided build, test, generator, or shell command. It validates only the mechanically decidable subset of EIGIIB; semantic/manual gates remain explicitly separate.

## Validation

```sh
python -m unittest discover -s tests -p 'test_*.py'
python tools/eigiib_check.py . --json
```

MIT License.
