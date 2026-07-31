# EIGIIB norm

EIGIIB defines a general engineering rule for software and systems projects:

> **Explicit Is Good, Implicit Is Better. Too explicit is never good.**

The repository separates authority by concern instead of repeating the standard.

- [`EIGIIB-STANDARD.md`](EIGIIB-STANDARD.md) — canonical core specification.
- [`extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md`](extensions/E1-TYPED-EVIDENCE-CLAIMS-CONFORMANCE.md) — typed evidence, claim boundary, uncertainty, contradiction, and conformance semantics.
- [`extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md`](extensions/E2-MACHINE-CHECKABLE-REPOSITORY-CONFORMANCE.md) — mechanically decidable repository-conformance contract.
- [`extensions/E3-REPRODUCIBLE-EVIDENCE-PROVENANCE-ARTIFACT-IDENTITY.md`](extensions/E3-REPRODUCIBLE-EVIDENCE-PROVENANCE-ARTIFACT-IDENTITY.md) — artifact identity, production provenance, replay and reproducibility semantics.
- [`extensions/E4-AUTHENTICATED-ATTESTATIONS-TRUST-ROOTS-PROVENANCE-INTEGRITY.md`](extensions/E4-AUTHENTICATED-ATTESTATIONS-TRUST-ROOTS-PROVENANCE-INTEGRITY.md) — authenticated attestations, trust roots, delegation, revocation and provenance-integrity semantics.
- [`extensions/E5-TRANSPARENCY-WITNESSING-APPEND-ONLY-TRUST-HISTORY.md`](extensions/E5-TRANSPARENCY-WITNESSING-APPEND-ONLY-TRUST-HISTORY.md) — transparency logs, append-only checkpoints, witnessing and transparent trust-history semantics.
- [`extensions/E6-GOSSIP-CROSS-LOG-CONSISTENCY-FORK-ACCOUNTABILITY.md`](extensions/E6-GOSSIP-CROSS-LOG-CONSISTENCY-FORK-ACCOUNTABILITY.md) — multi-observer gossip comparison, cross-log anchoring and bounded fork-accountability semantics.
- [`schemas/eigiib-e1-record.schema.json`](schemas/eigiib-e1-record.schema.json) — E1 typed registry schema.
- [`schemas/eigiib-e2-ownership.schema.json`](schemas/eigiib-e2-ownership.schema.json) — E2 durable-fact ownership schema.
- [`schemas/eigiib-e3-provenance.schema.json`](schemas/eigiib-e3-provenance.schema.json) — E3 provenance-registry schema.
- [`schemas/eigiib-e4-trust.schema.json`](schemas/eigiib-e4-trust.schema.json) — E4 trust/attestation registry schema.
- [`schemas/eigiib-e5-transparency.schema.json`](schemas/eigiib-e5-transparency.schema.json) — E5 transparency/witness registry schema.
- [`schemas/eigiib-e6-gossip.schema.json`](schemas/eigiib-e6-gossip.schema.json) — E6 gossip/cross-log/accountability registry schema.
- [`eigiib-conformance.schema.json`](eigiib-conformance.schema.json) — E2 normalized checker-report schema.
- [`tools/eigiib_check.py`](tools/eigiib_check.py) — dependency-free Python 3.11+ E2 reference checker.
- [`tools/eigiib_provenance_check.py`](tools/eigiib_provenance_check.py) — static E3 artifact/provenance checker.
- [`tools/eigiib_trust_check.py`](tools/eigiib_trust_check.py) — E4 trust checker with optional fixed OpenSSL Ed25519 verification.
- [`tools/eigiib_transparency_check.py`](tools/eigiib_transparency_check.py) — E5 Merkle/inclusion/consistency/witness checker.
- [`tools/eigiib_gossip_check.py`](tools/eigiib_gossip_check.py) — E6 static gossip, cross-log and fork-accountability checker.
- [`conformance/provenance.json`](conformance/provenance.json) — this repository's E3 provenance authority.
- [`conformance/trust.json`](conformance/trust.json) — this repository's E4 trust authority; structural-only with no production trust root asserted.
- [`conformance/transparency.json`](conformance/transparency.json) — this repository's E5 transparency authority; structural-only with no production log or witness asserted.
- [`conformance/gossip.json`](conformance/gossip.json) — this repository's E6 gossip/accountability authority; structural-only with no live gossip network, production fork or attribution asserted.
- [`EIGIIB.toml`](EIGIIB.toml) — this repository's adoption profile.

The checkers execute no repository-provided build, test, generator, or shell command. E2 validates mechanically decidable repository invariants. E3 recomputes local artifact identities and provenance/replay graph invariants. E4 may invoke only its fixed cryptographic provider adapter and keeps signature validity, trust, authorization and semantic truth separate. E5 recomputes its reference Merkle profile, inclusion/consistency relations and declarative witness quorum mechanics, while consuming E4 authentication only as an external typed decision. E6 compares exact E5 checkpoint views, validates directed cross-log references and applies a deliberately narrow attribution profile without inferring malicious intent, real-world identity, peer independence, global fork absence, or atomic cross-log state.

## Validation

```sh
python -m unittest discover -s tests -p 'test_*.py'
python tools/eigiib_check.py . --json
python tools/eigiib_provenance_check.py . --json
python tools/eigiib_trust_check.py . --crypto-provider openssl --json
python tools/eigiib_transparency_check.py . --json
python tools/eigiib_gossip_check.py . --json
```

MIT License.
