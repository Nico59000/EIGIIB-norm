# EIGIIB P1-A2 — Sigstore Signed Bundle Capsule and Authenticated Carrier Binding

Status: portable interoperability capsule profile. P1-A2 is not a numbered EIGIIB extension and does not add semantic authority above Core/E1–E13.

## Purpose

P1-A2 wraps the exact P1-A1 in-toto `Statement/v1` payload in a Sigstore Bundle v0.3 DSSE carrier and verifies one Ed25519 signature against one explicitly supplied out-of-band public key.

It establishes only a bounded cryptographic fact:

```text
signature valid over DSSE PAE for supplied public key
```

It does not establish signer trust, signer authorization, real-world identity, trusted signing time, transparency inclusion, EIGIIB claim truth, or production conformance.

## External reference

The profile is based on the Sigstore Bundle Format documentation identifying version `0.3.2` and media type:

```text
application/vnd.dev.sigstore.bundle.v0.3+json
```

For attestations, P1-A2 uses a DSSE envelope with:

```text
payloadType = application/vnd.in-toto+json
signatures  = exactly one
```

The DSSE signature is computed over the standard pre-authentication encoding:

```text
PAE(type, body) =
  "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
```

P1-A2 does not vendor either external specification.

## Relationship to P1-A1

P1-A1 remains authoritative for constructing the Statement from the exact M0-A2 aggregate report.

P1-A2 extracts the `statement` object from a conformant P1-A1 capsule and serializes it using the repository-local deterministic profile:

```text
UTF-8 JSON
sorted object keys
compact separators
no NaN/Infinity
```

This serialization profile is an adapter rule, not a claim that in-toto requires canonical JSON. DSSE authenticates the resulting exact payload bytes and therefore does not depend on a verifier independently reserializing the Statement.

## P1-A2 capsule

The EIGIIB wrapper contains:

```text
standard      = EIGIIB-P1-A2-1.0
profile       = sigstore-p1-a1-dsse-bundle-v1
external_spec = sigstore-bundle-0.3.2
crypto_profile = ed25519-spki-openssl-v1
trust_scope   = supplied-public-key-only
bundle        = <Sigstore Bundle v0.3 subset>
binding       = <exact Statement and public-key identities>
claimBoundary = <fixed negative implication boundary>
```

The embedded Sigstore bundle is deliberately restricted to:

```text
verificationMaterial.publicKeyIdentifier
DSSE envelope
```

P1-A2 intentionally rejects transparency-log entries and RFC3161 timestamp material. Those concerns are reserved for P1-A3 and later stages so that signature verification, transparency, and trusted-time evidence remain separate.

## Public-key profile

P1-A2 uses an out-of-band Ed25519 SubjectPublicKeyInfo public key.

The bundle `publicKeyIdentifier.hint` and DSSE `keyid` are both:

```text
p1-a2-ed25519-spki-sha256:<SHA256(DER SubjectPublicKeyInfo)>
```

The hint is only a lookup/binding hint. It MUST NOT be used as proof of trust, identity, authorization, or exclusive key ownership.

The wrapper additionally binds the exact DER SubjectPublicKeyInfo using SHA-256 and byte length.

## Signature verification

For payload bytes `B` and payload type `T`:

```text
M = PAE(UTF8(T), B)
```

The checker verifies the Ed25519 signature over `M` with the supplied public key using a fixed OpenSSL adapter.

The same payload bytes that are verified are then parsed and delivered to the P1-A1 binding check. P1-A2 never verifies one representation and later substitutes a reparsed/re-serialized representation.

## Core separations

```text
valid signature != trusted signer
matching public key != real-world identity
trusted signer != authorized signer
keyid/hint != security decision
signed Statement != true EIGIIB claim
authenticated carrier != production conformance
Sigstore bundle != transparency inclusion
signature verification != trusted signing time
P1-A2 != P1-A3 SCITT/Rekor registration
```

## Fixed negative implication boundary

Every P1-A2 capsule carries exactly:

```text
signature-valid-does-not-imply-trusted-signer
public-key-match-does-not-imply-real-world-identity
trusted-key-does-not-imply-authorized-signer
authenticated-carrier-does-not-imply-eigiib-claim-truth
sigstore-bundle-does-not-imply-transparency-inclusion
absence-of-timestamp-does-not-imply-trusted-time
p1-a2-bundle-does-not-imply-scitt-registration
```

Removing, reordering, or replacing these boundaries makes the capsule non-conformant.

## Cryptographic fixture

The repository test fixture contains only:

- one P1-A1 capsule already owned by P1-A1;
- one Ed25519 public key;
- one Sigstore Bundle capsule with a valid DSSE signature.

The private key used to create the fixed test signature is intentionally not stored in the repository. The P1-A2 self-check fails if private-key material appears in its fixture directory.

The fixture proves only that the reference verifier can validate a fixed signature against the fixed public key.

## Reference implementation

`tools/eigiib_sigstore_bundle.py` provides:

```text
assemble  P1-A1 capsule + externally supplied signature + public key -> P1-A2 capsule
verify    P1-A2 capsule + supplied public key [+ exact P1-A1 capsule]
check     repository self-check of fixture/profile/boundary state
```

The tool never generates or persists a private key. It does not sign. Signing is an external operation whose key custody and authorization are outside P1-A2.

The fixed crypto adapter may invoke only OpenSSL for:

- decoding the supplied public key to DER;
- verifying the Ed25519 signature.

It does not invoke network services, Fulcio, Rekor, SCITT, policy engines, or repository commands.

## Parsing and encoding safety

P1-A2 rejects duplicate JSON object members and non-finite JSON numbers.

The profile uses canonical standard RFC 4648 base64 for the bundle fields it owns. A decodable but non-canonical spelling is rejected.

These restrictions are repository-local transport hardening; they do not redefine the wider DSSE specification.

## M0-A3 lifecycle

P1-A2 adds a Sigstore external specification entry and an implemented profile:

```text
sigstore-p1-a1-dsse-bundle-v1
```

The Sigstore documentation URL is a moving reference even though the observed document reports version `0.3.2`. Therefore the profile MUST NOT be promoted to M0-A3 `validated` solely from this reference.

This preserves:

```text
implemented adapter != byte-identified external specification validation
```

## Non-goals

P1-A2 does not:

- generate or manage signing keys;
- use Fulcio certificates;
- establish OIDC identity;
- contact Sigstore public infrastructure;
- submit to or verify Rekor;
- attach or verify RFC3161 timestamps;
- establish signing time;
- establish signer trust or authorization;
- establish transparency inclusion;
- replace E4 trust semantics;
- replace P1-A1 Statement semantics;
- establish EIGIIB claim truth;
- establish production conformance.

Transparency registration and receipt semantics remain reserved for P1-A3.
