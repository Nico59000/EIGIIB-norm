# E14-A5 human mastery guide

## What closes here

A5 closes the repository-local E14 chain from a confidential source record to a committed release-event envelope.

A correct mental model is:

```text
A1 says what projection exists.
A2 says whether the crossing is permitted.
A3 says whether correlation and use budgets permit consumption.
A4 says whether the path remains fresh and non-rolled-back.
A5 says whether one exact release event may be recorded.
```

## What `released` means

`released` means that the repository checker found an A4-admissible upstream decision, a permitting release policy, authenticated-recipient evidence identifiers, protected-transport evidence identifiers and a fresh release nonce, and that a committed receipt binds the exact envelope.

It does not mean that a remote party definitely received or retained bytes.

## Why the matrix matters

The reference and independent implementations use different control flow and do not import each other. Agreement catches many implementation mistakes, especially precedence errors.

Agreement is still bounded by the frozen vector set. It is not a universal proof of correctness.

## Why the freeze matters

The final freeze converts “these are the intended E14 files” into a mechanically checked byte set. A changed byte, missing path or unexpected path breaks closure.

The freeze does not create external durability. Repository publication and long-term persistence remain separate operational concerns.

## Reviewer questions

1. Does every release request bind exact A1–A4 revisions and commitments?
2. Does every known negative dominate unavailable and held states?
3. Can only prior released events consume a nonce?
4. Does every released event have exactly one bound receipt?
5. Do both verifiers agree with every frozen expected result?
6. Does the freeze contain exactly the required E14 authority set?
7. Are external delivery, possession and durability nonclaims still explicit?
