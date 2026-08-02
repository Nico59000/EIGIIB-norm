# E14-A4 human mastery guide

## What A4 decides

A4 answers one bounded question: does a previously authorized and consumed disclosure path remain admissible against the exact current status heads supplied by this repository?

## Operator checklist

Before interpreting `admissible`, verify:

1. the source and projection commitments match E14-A1;
2. the authorization decision is the exact E14-A2 `permit`;
3. the correlation consumption is the exact E14-A3 `committed` record;
4. the distribution channel is bound to that projection;
5. each referenced status entry is the latest chained head;
6. the evaluation epoch equals the current epoch of the named freshness source;
7. every head is effective and unexpired;
8. no source, projection or channel is revoked, withdrawn or superseded.

## Reading failures

- `rejected`: a known negative exists, including rollback, stale status or withdrawal;
- `unavailable`: no known negative exists, but a required authority or component is unavailable;
- `held`: no known negative or unavailable component exists, but a component is contested or not yet effective;
- `admissible`: all bounded checks are positive.

## Critical boundaries

A4 does not prove global time, global propagation, byte recall, external consensus or release. An `admissible` result is a repository-local replay result only.

A withdrawal can stop future positive decisions in this model. It cannot make already delivered information disappear.
