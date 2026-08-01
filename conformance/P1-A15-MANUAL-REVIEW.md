# P1-A15 manual review

Review the following boundaries independently.

1. The canonical lightweight tag peels to the exact P1-A14 head.
2. The GitHub Release is published, remains a prerelease fixture, and is not a draft.
3. Exactly three declared assets are present.
4. API digest, authenticated download SHA-256, public download SHA-256 and manifest digest agree for every asset.
5. The Release `immutable` field is preserved exactly; content identity is not confused with platform mutation prevention.
6. The signed registrar capsule binds the exact frozen evidence and manifest.
7. The three live routes emit byte-identical portable projections.
8. Production authorization, external registry publication and durable retention remain outside the positive result.

A conformant result requires all eight checks.
