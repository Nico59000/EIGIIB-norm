# M0-A15-F2 — External authenticated history ingress and point-in-time T closure

M0-A15-F2 is the additive activation successor to M0-A15-F1. It does not weaken or rewrite the frozen F1 authority. It accepts one externally carried activation package, replays the embedded history through the exact F1 verifier, and permits `T` only inside a signed and explicitly supplied point-in-time window.

The package binds the exact F1 head and tree, the canonical history digest and byte length, an external HTTPS carrier, a publisher-signed ingress receipt, and at least two independently profiled ingress readbacks. The embedded history must itself produce `T` under the exact F1 checker, including the exact historical A14 replay.

Activation is sequence one with no predecessor. A distinct activation authority signs the derived F1 report digest, ingress receipt digest, ingress-readback-set digest, nonce, activation instant and expiry. Three of four independently profiled witnesses endorse the activation digest, and at least two independent observers read back the published activation. The caller supplies the evaluation instant; the verifier never reads the host clock and rejects evaluation outside the maximum one-hour window.

No production key, provider credential or live activation package belongs to the normative branch. CI creates a random-key candidate only after the three-platform matrix succeeds. That candidate is not authoritative until separately published, read back byte-exactly and replayed against its fixed evaluation instant.

A verified result is bounded to the supplied package, source revisions, declared profiles, external carrier and evaluation instant. It does not prove legal identity, physical independence, provider honesty, future availability, future registry agreement, or automatic safety of M0-A16.
