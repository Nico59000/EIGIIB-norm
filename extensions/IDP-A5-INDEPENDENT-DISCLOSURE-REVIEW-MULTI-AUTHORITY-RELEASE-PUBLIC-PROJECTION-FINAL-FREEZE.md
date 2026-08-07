# IDP-A5 — Independent Disclosure Review, Multi-Authority Release Approval, Public Projection Replay and Final Selective-Transparency Freeze

IDP-A5 closes the first selective-transparency sequence above IDP-A4. It separates construction of a public projection from authority to release that exact projection.

A release is conformant only when the A4 projection is replayed byte-for-byte, independent reviewer profiles remain in distinct control domains, at least two of three reviewers approve the exact projection digest, and at least two approving authorities sign the exact release payload. A final freeze then binds that release, the approval-set digest, the projection digest, and an append-only successor policy.

The committed authority records and keys are synthetic conformance material. They establish cryptographic replay and structural authority separation only. They do not establish production reviewer identity, production key custody, publication of a real restricted artifact, public opening of an A4 opaque commitment, or universal confidentiality/unlinkability.

Any byte drift in the public projection, invalid review or release signature, weakened threshold, duplicated control domain, temporal inversion, approval-set mismatch, or mutable successor policy is nonconformant.
