# P1 post-A9 closure roadmap

## Estimate

The safe estimate is **11 slices including P1-A10**, ending at P1-A20.

Every transition to `T` is contextual: the trust anchor, log set, registry set, retention interval, governance domain, implementation matrix or runner-admission policy must be explicitly frozen. No unbounded trust claim is inferred from fixture validity.

| Slice | Primary closure | Decisions advanced |
|---|---|---|
| P1-A10 | Delegated release authorization, threshold approval and delegate revocation | trusted release signer; authorized release signer |
| P1-A11 | Timestamp authority, validity windows, clock rollback and expiry replay | trusted effective time |
| P1-A12 | Transparency-service trust, witness quorum, checkpoint consistency and equivocation replay | trusted transparency service; append-only consistency for the registered log and witness set |
| P1-A13 | Content revocation, channel withdrawal, anti-rollback and stale-client replay | content revocation; distribution withdrawal |
| P1-A14 | Vulnerability advisory binding, remediation lineage and fixed-release replay | vulnerability remediation |
| P1-A15 | Live GitHub Release creation, immutable asset identity and API read-back replay | live GitHub Release |
| P1-A16 | Named external registry publication and cross-registry digest replay | external registry publication |
| P1-A17 | Replicated storage, retention window, restore drill and durability evidence | external persistence or durability |
| P1-A18 | Deployed release governance, separation of duties, emergency override and audit replay | production release governance |
| P1-A19 | Registered interoperability profile matrix and independent ecosystem replay | bounded replacement for universal interoperability |
| P1-A20 | Runner admission, toolchain succession, policy revision and rollback replay | bounded replacement for future unregistered runner compatibility |

## Status interpretation

Twelve original decisions can become `T` under their declared context. Two original formulations are intentionally not valid terminal goals:

- **universal interoperability** is not finitely demonstrable over all present and future implementations. P1-A19 targets `T` over a closed, versioned interoperability profile and implementation matrix; the absolute formulation remains `NF`.
- **future unregistered runner compatibility** conflicts with explicit admission control. P1-A20 targets `T` for future runners admitted by a signed policy transition; an unregistered runner must remain rejected, so the original formulation is `F/NF`, not `T`.

The estimate may expand by one or two slices if a live provider exposes a materially different trust or retention boundary during A15-A17.
