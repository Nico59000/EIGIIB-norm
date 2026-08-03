# M0-A8 Human Mastery Guide

## Read the repository state in this order

1. Use `conformance/m0-a8-lineage-publication.json` for branch and PR authority.
2. Use `stable/eigiib-e16-1.0` for the exact published stable E16 tree.
3. Treat `main` as the legacy default branch until a distinct future migration authority exists.
4. Continue new governance work from the exact M0-A8 stacked branch, not from `main`.

## Review rule

An `agent/` branch must target its exact declared predecessor. A cumulative `agent/` branch targeting `main` is non-authoritative and must be closed unmerged.

## Status rule

A historical document status may be superseded by a later final closure. Do not rewrite a frozen historical path merely to improve current prose. Record the supersession at the new authority boundary.

## Safe continuation

M0-A8 permits controlled study of future functionality. It does not authorize E17, a default-branch move, a release or a merge.
