# E15-A1 Human Mastery Guide

## Operator sequence

1. Identify the exact E14 source commit.
2. Read the historical replay report.
3. Confirm the E14 freeze and all E14 component reports are conformant.
4. Identify the exact release event, receipt and released commitment.
5. Resolve endpoint, carrier and policy revisions.
6. Check the evaluation context and idempotency key.
7. Read every component result before the derived state.
8. Stop if any binding is stale, missing or contradictory.

## What `admissible` means

`admissible` means that the repository can establish the declared E14 source boundary and that the endpoint, carrier, policy and idempotency gates are positive for one delivery intent.

It does not mean that a transfer started, a service accepted data, a recipient acknowledged it, or a durable publication exists.

## Negative precedence

A known negative cannot be hidden by an unavailable or held component.

```text
retired carrier + unavailable endpoint -> rejected
wrong release receipt + contested policy -> rejected
valid binding + unavailable endpoint -> unavailable
valid binding + contested carrier -> held
```

## Idempotency

Only an earlier `admissible` decision consumes an idempotency key. Rejected, held and unavailable decisions do not.

Idempotency inside E15-A1 does not prove exactly-once execution in an external service.

## Escalation boundary

Escalate rather than infer when the exact historical commit cannot be materialized, the historical E14 report is non-conformant, an endpoint or carrier revision changed, a release receipt does not bind its event, two authority roles merely share an identifier, or external delivery evidence is presented during A1.

External delivery evidence belongs to E15-A2.
