# M0-A15-F2 operator runbook

## Local baseline

Run `python tools/eigiib_m0_a15_f2_check.py .`. With no external package, the expected label is `NF` and the decision is `external-authenticated-activation-not-observed`.

## External activation verification

Keep the activation package outside the normative source tree. Record the evaluation instant supplied by the activation issuer, then run:

```text
python tools/eigiib_m0_a15_f2_check.py . \
  --package /absolute/path/activation-package.json \
  --at 2026-04-02T00:30:00Z \
  --require-t
```

A successful exit establishes only the bounded point-in-time closure represented by that package. Preserve the package bytes, SHA-256 digest, carrier readback, evaluation instant, workflow run and exact F2 head together.

## Publication sequence

1. Publish the authenticated F1 history through the declared external carrier.
2. Read it back through at least two declared observer profiles.
3. Issue the activation only after the exact F1 report is `T`.
4. Obtain the 3-of-4 activation witness quorum.
5. Publish and independently read back the activation.
6. Replay the byte-exact package with the fixed evaluation instant.
7. Do not infer future validity after `validUntil`.

Any changed package byte, source revision, signature, profile, locator, timing field or readback requires a new verification. M0-A16 must consume the resulting activation digest explicitly rather than infer succession from branch ancestry alone.
