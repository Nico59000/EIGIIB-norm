# P1-A11 — Trusted Timestamp Authority, Validity Windows, Clock Rollback and Expiry Replay

## Scope

P1-A11 binds trusted-time evaluation to the exact conformant P1-A10 authorization report and recovered authorization payload. A supplied time trust root delegates one Ed25519 timestamp authority through a deterministic COSE_Sign1 policy. The authority signs four fixed observations.

This slice establishes trusted effective time only relative to the supplied root, the delegated timestamp-authority key, the exact signed observations and the closed validity window. It does not infer time from a local runner clock.

## Closed window

The inclusive authorization window is:

```text
notBefore = 2026-08-01T16:00:00Z = 1785600000
notAfter  = 2026-08-02T16:00:00Z = 1785686400
```

The replay order is:

1. `before-window`, sequence 100, timestamp 1785599999: rejected as not yet valid;
2. `valid-window`, sequence 101, timestamp 1785603600: accepted;
3. `clock-rollback`, sequence 102, timestamp 1785601800: rejected because the signed timestamp regresses despite the increasing observation sequence;
4. `expired-window`, sequence 103, timestamp 1785686401: rejected after expiry.

Rejected observations do not advance the accepted clock. The final accepted timestamp remains `2026-08-01T17:00:00Z`.

## Cryptographic boundaries

The time-root policy binds:

- the exact A10 authorization report;
- the exact A10 capsule;
- the exact recovered authorization payload;
- the exact A8 release descriptor identity and release id;
- the exact timestamp-authority SPKI;
- the validity window and monotonicity policy.

Each observation is a deterministic COSE_Sign1 object with Ed25519 and a protected content type. No private key is part of the repository.

## Independent routes

- `reference-python-openssl` uses the strict Python carrier and OpenSSL Ed25519;
- `independent-go-stdlib` uses an independent deterministic-CBOR decoder and `crypto/ed25519`;
- `external-go-cose` uses `fxamacker/cbor v2.5.0` and `go-cose v1.3.0`.

Portable equality covers source identities, time-root and TSA identities, policy identity, window bounds, accepted observation set, final accepted time and every replay decision.

## Claim boundary

P1-A11 does not establish real-world operator identity, secure-clock hardware integrity, legal or commercial effective time, transparency-log trust, global append-only consistency, content revocation, distribution withdrawal or production governance.
