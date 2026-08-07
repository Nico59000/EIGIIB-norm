# IDP-A5 human mastery guide

The operative sequence is deliberately short:

1. construct the D0 projection under IDP-A4;
2. review the exact bytes independently;
3. obtain the declared threshold of cryptographic approvals;
4. release only the digest-bound projection;
5. freeze the approved state append-only.

A technically valid projection is not self-authorizing. Review approval is not transferable to another digest. A later change requires explicit append-only supersession rather than mutation of the frozen record.

The repository fixture is synthetic. Treat its Ed25519 signatures as conformance evidence, not as evidence of a real institution, reviewer, publication or custody system.
