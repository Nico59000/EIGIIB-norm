# M0-A5-F1 — Cross-Platform Canonical Report Normalization, Windows Byte-Exact Replay and Final Authority Freeze

## Status

This closure freezes the M0-A5 report representation without changing its semantic content. It repairs one platform-dependent output path observed on Windows and preserves the canonical P1 lineage and the non-adoption boundary for E14.

## Observed failure

The M0-A5 validator produced the expected JSON object on Ubuntu, macOS and Windows. The four semantic tests passed on all three systems. The Windows runner nevertheless failed the byte comparison because a text-mode write translated the terminal line feed into a carriage-return/line-feed sequence.

The failure was representational only:

- the report object was conformant;
- the canonical fixture remained unchanged;
- the P1 lineage head remained `c1983e9f2e95879ee16c162075c8d72bc73d88f9`;
- E14 remained ready for design and not normatively adopted.

## Canonical output contract

The report is serialized with sorted keys and compact JSON separators, encoded as UTF-8, and terminated by exactly one line-feed byte. Output is written as bytes. Platform text newline translation is forbidden.

The frozen fixture is `tests/fixtures/m0-a5/expected-report.json` with:

- byte length: `587`;
- SHA-256: `f7829589228cf480c3b69f4e954edf882eea238301aefdd16e34a00422abace6`;
- carriage-return count: `0`;
- terminal bytes: one `LF` after the closing JSON object.

## Replay matrix

Closure requires all of the following on Ubuntu 24.04, macOS 15 and Windows 2025:

1. the M0-A5 unit tests pass;
2. generated report bytes equal the frozen fixture;
3. the P1-A20 canonical commit is an ancestor of the tested head;
4. no E14 extension file or adoption entry exists;
5. the M0-A5-F1 authority state and manual review remain present.

A platform-specific success cannot substitute for the complete matrix.

## Final authority freeze

The following authorities remain controlling by repository path:

- `conformance/m0-a5-p1-lineage.json`;
- `conformance/m0-a5-e14-handoff.json`;
- `docs/M0-A5-HUMAN-MASTERY-GUIDE.md`;
- `conformance/m0-a5-f1-authority-freeze.json`.

The freeze does not copy or restate the P1 authorities. It binds the report representation to their existing M0-A5 inventory and preserves exact-commit authority.

## Human operating rule

When a generated report differs from its fixture, compare the decoded object and the raw bytes separately. A semantic match does not prove a byte-exact match, and a byte difference must not be promoted into a semantic failure without evidence.

For this report, the correct sequence is:

1. validate the authority graph and E14 boundary;
2. serialize the report canonically;
3. write bytes without newline translation;
4. compare raw bytes to the frozen fixture;
5. accept closure only after the full platform matrix passes.

## Nonclaims

M0-A5-F1 does not adopt E14, add new P1 lineage content, alter the M0-A5 report semantics, or claim equivalence on platforms outside the tested matrix.
