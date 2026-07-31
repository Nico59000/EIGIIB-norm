# EIGIIB norm

EIGIIB defines a general engineering rule for software and systems projects:

> **Explicit Is Good, Implicit Is Better. Too explicit is never good.**

The repository separates authority by concern instead of repeating the standard.

- [`EIGIIB-STANDARD.md`](EIGIIB-STANDARD.md) — canonical core specification.
- [`extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md`](extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md) — typed evidence, claim boundary, uncertainty, contradiction, and conformance semantics.
- [`extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md`](extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md) — mechanically decidable repository-conformance contract.
- [`extensions/E3-REPRODUCIBLE-EVIDENCE-PROVENANCE-ARTIFACT-IDENTITY.md`](extensions/E3-REPRODUCIBLE-EVIDENCE-PROVENANCE-ARTIFACT-IDENTITY.md) — artifact identity, production provenance, replay and reproducibility semantics.
- [`extensions/E4-AUTHENTICATED-ATTESTATIONS-TRUST-ROOTS-PROVENANCE-INTEGRITY.md`](extensions/E4-AUTHENTICATED-ATTESTATIONS-TRUST-ROOTS-PROVENANCE-INTEGRITY.md) — authenticated attestations, trust roots, delegation, revocation and provenance-integrity semantics.
- [`schemas/eigiib-e1-record.schema.json`](schemas/eigiib-e1-record.schema.json) — E1 typed registry schema.
- [`schemas/eigiib-e2-ownership.schema.json`](schemas/eigiib-e2-ownership.schema.json) — E2 durable-fact ownership schema.
- [`schemas/eigiib-e3-provenance.schema.json`](schemas/eigiib-e3-provenance.schema.json) — E3 provenance-registry schema.
- [`schemas/eigiib-e4-trust.schema.json`](schemas/eigiib-e4-trust.schema.json) — E4 trust/attestation registry schema.
- [`eigiib-conformance.schema.json`](eigiib-conformance.schema.json) — E2 normalized checker-report schema.
- [`tools/eigiib_check.py`](tools/eigiib_check.py) — dependency-free Python 3.11+ E2 reference checker.
- [`tools/eigiib_provenance_check.py`](tools/eigiib_provenance_check.py) — static E3 artifact/provenance checker.
- [`tools/eigiib_trust_check.py`](tools/eigiib_trust_check.py) — E4 trust checker with optional fixed OpenSSL Ed25519 verification.
- [`conformance/provenance.json`](conformance/provenance.json) — this repository's E3 provenance authority.
- [`conformance/trust.json`](conformance/trust.json) — this repository's E4 trust authority; currently structural-only with no production trust root asserted.
- [`EIGIIB.toml`](EIGIIB.toml) — this repository's adoption profile.

The checkers execute no repository-provided build, test, generator, or shell command. E2 validates mechanically decidable repository invariants. E3 recomputes local artifact identities and provenance/replay graph invariants. E4 may invoke only its fixed cryptographic provider adapter and keeps signature validity, trust, authorization and semantic truth separate. The repository does not invent a production signing identity merely by adopting E4.

## Validation

```sh
python -m unittest discover -s tests -p 'test_*.py'
python tools/eigiib_check.py . --json
python tools/eigiib_provenance_check.py . --json
python tools/eigiib_trust_check.py . --crypto-provider openssl --json
```

MIT License.
