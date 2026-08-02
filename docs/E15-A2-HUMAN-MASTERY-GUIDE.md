# E15-A2 Human Mastery Guide

## Question answered

E15-A2 answers: “Given an admissible E15-A1 delivery intent, what bounded repository evidence exists for an attempted crossing, an external delivery observation and an acknowledgement?”

It does not answer whether a human actually possessed, read or understood the object.

## Three non-collapsible coordinates

1. **Transfer attempt** — what the local actor attempted and observed locally.
2. **External delivery evidence** — what a declared external attester says occurred.
3. **Recipient acknowledgement** — what a declared recipient-side interface or principal acknowledged.

Never infer the third from the second or the second from the first.

## Lifecycle interpretation

- `not-started`: a prepared attempt has no external evidence.
- `in-progress`: a submitted or locally completed attempt has no external evidence.
- `externally-attested`: all required bindings, attesters, freshness checks, delivery evidence and acknowledgement policy pass.
- `rejected`: a known negative coordinate exists.
- `held`: evidence is pending or a required acknowledgement is absent.
- `contested`: at least one typed record is contested and no known negative dominates it.
- `unavailable`: required evidence cannot be obtained and no known negative dominates it.

## Negative precedence

A negative delivery receipt remains `rejected` even when an acknowledgement service is unavailable. This prevents uncertainty from masking a known failure.

## Freshness

Evidence and acknowledgements are evaluated at the decision’s fixed `evaluated_at` instant. Their validity windows and policy maximum ages are checked without consulting an implicit wall clock.

## Idempotence

Each transfer attempt has its own idempotency key and sequence. Reusing an attempt key is non-conformant; it cannot silently create a second external effect.

## Nonclaims

A conformant E15-A2 record is not proof of physical possession, human awareness, service honesty, durable publication, universal availability, downstream retention, withdrawal or erasure.
