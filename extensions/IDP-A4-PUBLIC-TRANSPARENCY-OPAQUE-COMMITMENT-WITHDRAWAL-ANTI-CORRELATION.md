# IDP-A4 — Public Transparency Records, Opaque Commitment Construction, Withdrawal and Anti-Correlation Disclosure

IDP-A4 defines the public side of selective transparency. It allows a public record to state that a restricted, non-public subject exists within a declared verification boundary without publishing its internal identity, exact restricted class, payload digest, opening salt, bridge endpoint, access grant, institution, subject identity, or key material.

## Public record boundary

Every A4 announcement is D0 and uses the coarse subject disclosure `restricted-nonpublic`. D3 and D4 are deliberately not distinguished on the public surface. D5 is never represented by an A4 subject announcement.

A public announcement contains a fresh public record identity, a non-reused opaque public handle, a salted commitment, a bounded verification state, publication time, and active/withdrawn state. Absence from the public registry implies neither existence nor absence of an unlisted restricted artifact.

## Opaque commitment

For a public record identifier `R`, private 32-byte salt `S`, and internal payload digest `D`, the commitment is:

`SHA256("EIGIIB-IDP-A4-COMMITMENT-1.0" || 0x00 || UTF8(R) || 0x00 || S || D)`.

The public registry contains only the resulting commitment. `S` and `D` remain outside the public record. The conformance fixture is synthetic and deterministic; it proves construction, binding, non-zero salt and non-reuse, not production entropy. A production implementation must separately establish a cryptographically secure source for salt and handle generation before claiming operational hiding strength.

## Anti-correlation boundary

A4 rejects reuse of a public handle, salt, or commitment inside the declared registry. The positive fixture intentionally commits twice to the same synthetic payload digest under distinct record identifiers and salts and obtains distinct public commitments.

This is not a universal anonymity claim. Timing, traffic volume, textual announcements, release cadence, external observations, or other semantic side channels can still correlate records and are outside A4's structural claim.

## Withdrawal

Withdrawal is append-only. A withdrawn announcement remains present in `records` and is bound to exactly one withdrawal event. A withdrawal cannot precede publication and does not reveal restricted identifiers or opening material. Withdrawal means that the public announcement is no longer active; it does not delete history, disclose the subject, or imply revocation of every non-public authorization concerning that subject.

## Claim boundary

A4 establishes the public-record shape, exact salted commitment construction against synthetic private witnesses, non-reuse rules, append-only withdrawal, and differential rejection of disclosure/correlation mistakes. It does not establish public payload access, public opening verification, production entropy, universal unlinkability, or the existence/absence of anything not represented by a public record.
