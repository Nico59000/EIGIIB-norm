# P1-A14 manual review

- [x] P1-A13 head, report, capsule, revocation envelope and accepted history are bound exactly.
- [x] Advisory, remediation and fixed-release roles use distinct registered key identities.
- [x] The advisory binds the exact revoked predecessor and fixture vulnerability identifier.
- [x] The remediation statement binds the exact advisory, predecessor, successor, descriptor and change-set.
- [x] The fixed release binds exact descriptor and archive bytes.
- [x] The idempotent exact replay does not add an accepted-history node.
- [x] The revoked predecessor remains rejected above the fixed-release floor.
- [x] Same-id archive substitution, wrong advisory lineage and below-floor replay are rejected.
- [x] Python/OpenSSL, independent Go and external go-cose routes are required to agree exactly.
- [x] Closed schemas cover capsule, route report and three-route replay.
- [x] No private key is published in the P1-A14 scope.
- [x] Production authorization, live publication, external assignment and real-world defect removal remain unclaimed.
