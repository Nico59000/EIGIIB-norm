# M0-A10 human mastery guide

## Reading order

1. Read `conformance/m0-a10-dual-channel-publication.json` for the machine decision.
2. Verify the exact source and bundle identity in `conformance/m0-a10-stable-bundle-manifest.json`.
3. Verify the Ed25519 signature with the published public key.
4. Compare the captured Release and OCI identities in `conformance/m0-a10-live-publication-evidence.json`.
5. Confirm that all four restore routes contain the same four object identities.
6. Read `conformance/m0-a10-ops-cleanup-record.json` before interpreting the deleted `ops/` refs.
7. Verify every frozen authority with `tools/eigiib_m0_a10_check.py`.

## Decisive distinction

A successful readback is evidence of a successful readback. It is not evidence of uninterrupted retention before the observation or guaranteed availability after it.

A signature under the published M0-A10 key is evidence of manifest integrity under that key. The key is not promoted to a production release authority.

A 404 from a compare URL that names a deleted technical branch is expected. Branch deletion removes the ref required by compare; there is no persistent compare record to purge.

## Reproduction

```text
python tools/eigiib_m0_a10_check.py . --json
python tools/eigiib_m0_a10_live_replay.py . --json
python -m unittest -v tests/test_eigiib_m0_a10.py
```

The structural checker is deterministic. The live replay is an observation of external services and may return unavailable if a named service cannot be reached; unavailability must not be converted into success.
