# EIGIIB P1-A3 — SCITT Transparency Registration Capsule and Receipt-Bound Evidence

Status: portable interoperability capsule profile. P1-A3 is not a numbered EIGIIB extension and does not add semantic authority above Core/E1–E13.

## Purpose

P1-A3 takes one exact, conformant P1-A2 Sigstore carrier and binds its byte identity into a SCITT Signed Statement. It then verifies one SCITT Receipt containing an RFC9162_SHA256 inclusion proof against one explicitly supplied Transparency Service Ed25519 public key.

The positive mechanical conclusion is deliberately bounded:

```text
exact P1-A2 identity
+ valid SCITT Signed Statement signature for supplied issuer key
+ valid RFC9162_SHA256 inclusion proof
+ valid Receipt signature for supplied Transparency Service key
= receipt-bound registration evidence relative to those supplied keys
```

It is not a claim that either key is trusted, that the Transparency Service is globally consistent, that a Registration Policy was correct, that the registration time is trusted, or that the transported EIGIIB claim is true.

## External references

P1-A3 is based on the current stable SCITT object model:

- RFC 9943, *An Architecture for Trustworthy and Transparent Digital Supply Chains*;
- RFC 9942, *CBOR Object Signing and Encryption (COSE) Receipts*;
- `draft-ietf-scitt-scrapi-11` only for the bounded HTTP registration transcript profile.

RFC 9943 defines SCITT Signed Statements and Receipts as COSE_Sign1 objects and registers:

```text
application/scitt-statement+cose
application/scitt-receipt+cose
```

RFC 9942 defines VDS algorithm `RFC9162_SHA256 = 1`, inclusion proof type `-1`, VDS header `395`, and VDP header `396`.

SCRAPI remains work in progress. P1-A3 therefore treats its `POST /entries`, `201`, and `Location` fields as transcript metadata only. They do not create registration evidence by themselves.

## Relationship to P1-A2

P1-A2 remains authoritative for the authenticated DSSE/Sigstore carrier. P1-A3 does not reinterpret its in-toto predicate or aggregate result.

Instead, the SCITT Signed Statement payload is a deterministic CBOR map containing only the exact P1-A2 byte identity:

```text
mediaType = application/vnd.dev.sigstore.bundle.v0.3+json
sha256    = SHA256(exact P1-A2 JSON bytes)
bytes     = exact P1-A2 byte length
```

This follows the RFC 9943 pattern that permits a Signed Statement over a payload hash rather than transporting the full potentially large or sensitive payload to a Transparency Service.

## SCITT Signed Statement profile

The fixture Signed Statement is tagged COSE_Sign1 and uses:

```text
alg          = EdDSA (-8)
kid          = SHA256(DER SubjectPublicKeyInfo)
content-type = application/cbor
typ          = application/scitt-statement+cose
CWT iss      = https://eigiib.example/p1-a3/issuer
CWT sub      = urn:eigiib:p1-a2:<P1-A2 SHA256>
unprotected  = {}
payload      = deterministic CBOR P1-A2 identity map
```

The checker verifies the Ed25519 COSE Sig_structure with the explicitly supplied issuer public key. This proves only cryptographic validity relative to that key.

## Receipt profile

The Receipt is also tagged COSE_Sign1. Its protected header uses:

```text
alg     = EdDSA (-8)
kid     = SHA256(DER Transparency Service SubjectPublicKeyInfo)
typ     = application/scitt-receipt+cose
vds     = RFC9162_SHA256 (1)
CWT iss = https://eigiib.example/p1-a3/transparency-service
CWT sub = the exact P1-A2 subject URN
```

Its unprotected header contains exactly one VDP inclusion proof under labels `396` and `-1`. The Receipt payload is detached.

For candidate entry bytes `E`:

```text
leaf = SHA256(0x00 || E)
```

and the RFC9162 inclusion path is applied to obtain the Merkle root `R`. P1-A3 then verifies the Receipt COSE signature using `R` as the detached payload.

The fixture uses a one-entry tree (`treeSize = 1`, `leafIndex = 0`, empty path), while the reference verifier implements the general RFC9162 inclusion-path computation.

## Registration transcript

The repository fixture records a synchronous SCRAPI-style transcript:

```text
POST /entries
status = 201
Location = https://transparency.example/entries/<Signed Statement SHA256>
```

The transcript is explicitly marked `fixture-no-network`. P1-A3 does not contact a Transparency Service.

The `Location` value is a locator and an exact-fixture binding only. It is not used as authentication or proof of persistence.

## Result separation

The checker reports distinct result carriers:

```text
upstream_p1a2_result
signed_statement_signature_result
receipt_signature_result
inclusion_result
registration_evidence_result
trust_result
append_only_result
cross_view_result
time_result
```

A conformant fixture may therefore report a valid Receipt and verified inclusion while still reporting trust, append-only consistency, cross-view convergence and trusted time as not evaluated.

## Fixed negative implication boundary

Every P1-A3 capsule carries exactly:

```text
receipt-signature-valid-does-not-imply-trusted-transparency-service
inclusion-proof-valid-does-not-imply-global-append-only-consistency
receipt-bound-registration-does-not-imply-eigiib-claim-truth
location-header-does-not-imply-receipt-authenticity
registration-http-status-does-not-imply-persistence-without-receipt
receipt-registration-does-not-imply-e11-trusted-time
single-receipt-does-not-imply-e6-cross-view-convergence
scitt-registration-does-not-imply-registration-policy-correctness
p1-a3-fixture-does-not-imply-production-transparency-service
```

Removing, replacing, or reordering the boundary makes the capsule non-conformant.

## Cryptographic fixtures

The repository stores only two public Ed25519 keys:

- one fixture Issuer key for the SCITT Signed Statement;
- one fixture Transparency Service key for the Receipt.

No private key is committed. The self-check rejects private-key markers in the P1-A3 fixture directory.

The fixture proves reference-verifier interoperability only. It does not establish a production issuer, production Transparency Service, or operational key custody.

## Parsing and deterministic transport profile

P1-A3 uses a dependency-free, repository-local deterministic CBOR subset for its fixtures and signature structures. It rejects indefinite-length encodings, duplicate map keys, floating-point/simple values outside `false`, `true`, and `null`, trailing bytes, and alternate deterministic encodings.

This is P1-A3 transport hardening; it does not redefine generic CBOR, COSE, SCITT, or RFC 9942.

JSON wrappers reject duplicate members and non-finite numbers. Base64 fields must use canonical RFC 4648 spelling.

## Non-goals

P1-A3 does not:

- trust or authorize the Issuer key;
- trust or authorize the Transparency Service key;
- discover keys over the network;
- execute `POST /entries` or poll a Receipt resource;
- prove a global append-only property from a single inclusion Receipt;
- verify a consistency proof;
- prove absence of equivocation across observers;
- promote Receipt registration time into E11 trusted time;
- prove correctness of the Transparency Service Registration Policy;
- establish production transparency;
- establish EIGIIB claim truth.

E4 remains authoritative for trust/authentication decisions, E5 for transparency semantics, E6 for cross-view/fork accountability, and E11 for trusted temporal semantics.
