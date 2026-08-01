# P1-A12 — Transparency Service Trust, Witness Quorum, Consistency and Equivocation Replay

## 1. Scope

P1-A12 binds the exact P1-A11 trusted-time result to a registered transparency service, a closed witness set and an append-only Merkle history. It distinguishes registration, checkpoint validity, witness quorum, consistency and equivocation instead of collapsing them into a single Boolean claim.

The operational state follows the HT+NT separation between internal evidence and externally replayed persistence. A checkpoint can be internally well signed while the external replay still rejects it because an equal-size conflicting root has already been observed. No binary absolutization is permitted outside the declared service epochs, witness sets and accepted history.

## 2. Exact source binding

The capsule binds:

- P1-A11 report SHA-256 `2a1931b186def40a370fe3ea3d6a6b40eddd5576123c09ef0a94fa33b2d2e277`;
- P1-A11 capsule SHA-256 `526d1713db54b1648504be7cd33d6d8701a8744eeed8d5a95d4c58586b57ca46`;
- accepted effective time `1785603600`;
- release id `eigiib-p1-a7-authority-1.0`.

## 3. Registration and witness quorum

A supplied transparency root registers service epoch 1 and witness set 1:

- service `eigiib-p1-a12-log-1`, epoch `1`;
- witnesses `witness-a`, `witness-b`, `witness-c`;
- threshold `2` of `3`;
- consistency profile `power-of-two-prefix-rfc6962-v1`.

All policies, checkpoints and witness statements use deterministic Ed25519 COSE_Sign1 envelopes.

## 4. Accepted history

The registered service publishes:

1. `epoch1-size2`, root `4fd4b61224eb6b534fd08611aa36955290cfa757ae82fe8d46096810d73b3050`, witnessed by `a,b`;
2. `epoch1-size4-main`, root `b745f1a17e8760cc2c9f8c153880261ed58024a107f2bf1f5b7325087f0a227a`, witnessed by `a,b` and consistent with size 2.

The tree uses SHA-256 with RFC 6962-style domain separation:

```text
LeafHash(x)    = SHA-256(0x00 || x)
NodeHash(l, r) = SHA-256(0x01 || l || r)
```

For the frozen power-of-two prefixes, the registered consistency proof contains the right subtree root and verifies `newRoot = NodeHash(oldRoot, proof[0])`.

## 5. Signed equivocation

The same service epoch then publishes `epoch1-size4-fork`:

- same service id;
- same epoch `1`;
- same checkpoint sequence `11`;
- same tree size `4`;
- different root `fea76e8be8a90c8390dbf339e3282e0b6873a8a58110b93ff32623bb40545bc9`.

The fork has a valid service signature, a valid consistency proof from size 2 and a valid `2-of-3` quorum from `witness-b,witness-c`. Therefore signature validity, consistency from a common prefix and quorum satisfaction are individually insufficient to rule out equivocation.

The collision on `(service id, epoch, checkpoint sequence, tree size)` with two roots quarantines service epoch 1. The quorum intersection identifies `witness-b` as signing both conflicting checkpoints, so that witness is also quarantined.

## 6. Recovery

The transparency root signs a succession policy that:

- binds both conflicting checkpoint envelopes;
- preserves `epoch1-size4-main` as the accepted predecessor;
- quarantines service epoch 1 and `witness-b`;
- registers `eigiib-p1-a12-log-2`, epoch `2`;
- registers witness set 2: `witness-a,witness-c,witness-d`, threshold `2`.

The successor publishes `epoch2-size8-recovery`, root `cbaa2980c0c57054a161f77c34a1300d86f4cd4c04a06fbcdde35ef5d4628641`, witnessed by `witness-a,witness-d`. Its consistency proof extends the accepted size-4 root and records the equivocation evidence, quarantine and succession policy in the appended subtree.

## 7. Portable result

The three routes must agree on:

```text
reference-python-openssl
independent-go-stdlib
external-go-cose
```

The portable accepted history is:

```text
epoch1-size2
  -> epoch1-size4-main
  -> epoch2-size8-recovery
```

The fork is rejected and never advances accepted history.

## 8. Claim boundary

P1-A12 establishes contextual trust only for the supplied root, registered services, frozen witness sets and accepted `2 -> 4 -> 8` history. It does not establish:

- real-world operator identity;
- absence of witness collusion;
- global append-only consistency across all logs or observers;
- content revocation or distribution withdrawal;
- production release governance;
- universal interoperability.

The final boundary is:

```text
registered-transparency-quorum-consistency-equivocation-recovery-closure
```
