# P1-A19-F2 — Draft 2020-12 Closed-Schema Enforcement and Review Closure

## 1. Scope

P1-A19-F2 corrects the schema-validation gate of exact P1-A19 commit `d791f780bc97d70e8f97e5165d3c86dc4a90fddf`. The P1-A19 registry, six active-profile routes, expected report, signatures, capability decisions and claim boundary are unchanged.

The correction replaces a structural inspection of the schema document with execution of `jsonschema` 4.26.0 `Draft202012Validator`. The validator first checks the committed schema against the Draft 2020-12 meta-schema, then validates the complete interoperability bundle before the existing semantic replay runs.

## 2. Closed-schema enforcement

The committed schema uses local references of the form `#/$defs/...`. P1-A19-F2 resolves those references while validating the instance and therefore enforces nested `additionalProperties: false`, item types, patterns, cardinalities and constants at the referenced object boundaries.

Eight negative schema mutations are required:

1. extra property on the bundle;
2. extra property on the signed registry envelope;
3. extra property on the referenced registry payload;
4. extra property on a referenced profile;
5. extra property on a referenced route;
6. extra property on a referenced transcript;
7. non-string item in a referenced canonical set;
8. empty item violating the referenced canonical-set minimum length.

Every mutation must be rejected by the Draft 2020-12 validator before semantic acceptance.

## 3. Validator dependency

The workflow installs an exact five-package set:

- `jsonschema==4.26.0`;
- `attrs==26.1.0`;
- `jsonschema-specifications==2025.9.1`;
- `referencing==0.37.0`;
- `rpds-py==2026.5.1`.

The validation environment remains Python 3.13.14 on Ubuntu 24.04, macOS 15 and Windows 2025.

## 4. Preserved replay

After schema validation, the unchanged P1-A19 semantic validator verifies the signed registry and reproduces all six accepted negotiation transcripts. The workflow also preserves:

- the exact reference report;
- independent Go tests and report;
- byte-exact Python/Go convergence;
- external OpenSSL verification of the registry signature;
- private-key and normative-scope guards.

## 5. Review closure

The correction addresses the unresolved P2 review on PR #99. That review correctly observed that checking only the root `additionalProperties` declaration did not validate the fixture against the committed schema. Review closure requires a successful exact-head workflow, a reply identifying the correcting commit and tests, and resolution of the review thread.

## 6. Decision boundary

Boundary: `draft202012-committed-schema-local-ref-closed-instance-and-semantic-replay-closure`.

Conformant inside the boundary:

- Draft 2020-12 schema-document validation;
- validation of the complete committed P1-A19 bundle;
- local `#/$defs` reference resolution;
- nested closed-object enforcement;
- eight negative schema mutations;
- preservation of the P1-A19 semantic and differential replay.

Outside the boundary:

- resolution of arbitrary remote schemas;
- network retrieval of schema resources;
- format-assertion coverage not present in the committed schema;
- universal compatibility with future schema vocabularies.
