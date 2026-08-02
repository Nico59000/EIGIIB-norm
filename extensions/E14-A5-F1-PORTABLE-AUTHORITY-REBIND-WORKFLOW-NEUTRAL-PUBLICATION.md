# E14-A5-F1 — Portable Authority Rebinding and Workflow-Neutral Publication

Status: bounded corrective closure 1.0.

## 1. Trigger

E14-A5 was built from the corrected E14-A4 branch, but its first authority freeze still named the pre-correction A4 head and the pre-correction bytes of the A4 revocation checker. The first publication path also attempted to push a workflow through a token lacking workflow-mutation permission.

These are concrete closure defects:

```text
corrected authority bytes != stale frozen digest
corrected A4 head != pre-correction A4 head
validated payload != publishable workflow mutation
```

## 2. Correction

A5-F1 performs only the following changes:

- rebinds the A5 source head to the final corrected A4 commit;
- refreezes the corrected A4 checker bytes and every A5 authority changed by this correction;
- compares generated JSON reports as decoded objects across platforms;
- publishes normative files without requiring a workflow mutation from the CI token;
- records the correction in the E14 graph, profile and manual review.

The release-decision relation, verifier vectors, release registry and final profile revision remain unchanged.

## 3. Publication boundary

The workflow-neutral publication procedure is transport for repository bytes only. It is not an E14 release event and proves neither external delivery nor durable publication.

## 4. Closure rule

A5-F1 closes only when:

1. the corrected A4 head is frozen exactly;
2. every frozen byte length and SHA-256 digest matches;
3. the reference and independent A5 verifiers agree;
4. Ubuntu, macOS and Windows replay the final reports successfully;
5. the final branch contains no temporary payload or materializer.

## 5. Nonclaims

A5-F1 does not add E14-A6, change disclosure semantics, broaden release authorization, establish workflow-token authority, or prove external persistence.
