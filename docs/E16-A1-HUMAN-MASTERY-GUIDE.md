# E16-A1 Human Mastery Guide

## Reading order

1. `conformance/m0-a7-e16-entry.json`
2. `conformance/e16-a1-adoption-transition.json`
3. `extensions/E16-EXTERNAL-CUSTODY-REPLICATION-RETENTION-RECOVERY-GOVERNANCE.md`
4. `conformance/preservation-intent.json`
5. `schemas/eigiib-e16-a1-preservation-intent.schema.json`
6. `tools/eigiib_historical_m0_a7_replay.py`
7. `tools/eigiib_preservation_intent_check.py`
8. `conformance/e16-a1-authority-freeze.json`

## Operational interpretation

An admissible E16-A1 decision means that an exact positive E15 publication record, its lifecycle decision, a custodian profile, a replica profile and a preservation policy are consistently bound in the repository. It does not mean that the replica exists externally.

The custodian role and replica role remain distinct. A custodian can authorize or operate a service boundary; a replica profile describes an intended endpoint class and storage role. Their equality is never inferred from matching labels.

A2 must add external placement or custody evidence. A3 must add bounded retention, readback and restoration evidence. A4 must add loss and succession transitions. A5 must compare independent verifiers.
