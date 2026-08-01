# P1-A8 — Exact Distribution Bundle, Release Digests and Independent Publication Replay

## Status

P1-A8 is an additive distribution profile over the frozen P1-A7 authority. It does not modify the P1-A7 corpus, reports, source authority or registered authority root.

The distributed source commit is fixed to:

```text
a478bda55bb88bb3fa611e3ae52a9ce880d2243b
```

The imported P1-A7 authority root is fixed to:

```text
e338247156165c48b7b1ce88a69f24123defc0162b1f3f6a58c4ecd510e105be
```

## Distribution object

The release object is one uncompressed USTAR archive named:

```text
eigiib-p1-a7-authority-1.0.tar
```

The archive contains the complete tracked Git tree of the fixed source commit. Source bytes are read through `git ls-tree` and `git cat-file`; they are not read from a possibly transformed checkout.

The closed USTAR profile requires:

- ASCII paths sorted bytewise;
- regular Git blobs only, with repository modes `100644` or `100755`;
- normalized archive modes `0644` or `0755`;
- UID, GID and mtime equal to zero;
- empty owner and group names;
- no directory entries;
- no PAX, GNU or sparse extensions;
- exact POSIX USTAR magic and version;
- exact NUL-terminated octal fields;
- exactly two zero trailer blocks and no additional record padding.

The lack of compression is intentional. It removes compressor implementation, level, timestamp and header variability from the byte-equivalence claim.

## Embedded manifest

The archive contains one canonical JSON manifest at:

```text
eigiib-p1-a7-authority-1.0/META-INF/eigiib-p1-a8-bundle-manifest.json
```

Every tracked source file is represented by:

- repository-relative path;
- normalized mode;
- byte length;
- SHA-256 digest;
- exact Git blob SHA-1 identity.

The manifest carries one source-tree root:

```text
SHA-256(
  "EIGIIB-P1-A8 source-tree-root v1\n" ||
  Σ(path || NUL || mode || NUL || bytes || NUL || sha256 || NUL || git_blob_sha1 || LF)
)
```

Rows are sorted by path before hashing. This root is an inventory identity, not source authentication.

## Detached release records

A deterministic publication produces four files:

```text
eigiib-p1-a7-authority-1.0.tar
eigiib-p1-a8-bundle-manifest.json
eigiib-p1-a8-release.json
SHA256SUMS
```

The detached release descriptor binds:

- release id;
- exact source commit;
- imported P1-A7 authority root;
- archive name, byte length and SHA-256;
- embedded manifest path, byte length and SHA-256;
- source-entry count;
- source-tree root;
- required publishers and platforms;
- explicit claim boundaries.

`SHA256SUMS` contains exactly two lines: the archive SHA-256 and the detached manifest SHA-256.

## Independent publishers

The required publishers are:

```text
reference-python-stdlib
independent-go-stdlib
```

The Python publisher and the Go publisher separately:

1. read the exact source commit through Git object commands;
2. validate the closed path and mode profile;
3. construct the same canonical JSON manifest;
4. construct USTAR headers and padding directly;
5. compute the detached release descriptor and `SHA256SUMS`.

No archive library is shared between the two producers. Conformance requires byte equality of all four outputs.

## Independent publication replay

The replay gate does not trust either producer's success message. It:

1. compares all four producer outputs byte-for-byte;
2. parses the USTAR structure with a closed parser;
3. validates header checksums, metadata, ordering, padding and trailer length;
4. requires the embedded and detached manifest bytes to be equal;
5. recomputes every source file length, SHA-256 and Git blob identity;
6. recomputes the source-tree root and detached release digests;
7. extracts the archive into a fresh directory without `.git`;
8. replays P1-A7.1 through P1-A7.6 from the extracted source;
9. replays the P1-A7.7 authority gate without the Git-ancestry option;
10. compares the canonical P1-A8 publication report with the registered result.

The absence of `.git` during the final replay distinguishes archive sufficiency from repository checkout availability.

## Required platforms

The full producer and replay sequence runs on:

- Ubuntu 24.04;
- macOS 15;
- Windows 2025.

CPython 3.13.14 and Go 1.26.5 are fixed as in the P1-A7.7 distribution policy. OpenSSL remains platform-specific and is used only by the extracted P1-A7 cryptographic replays, not by USTAR generation.

## Claim boundary

A conformant P1-A8 result does not imply:

- creation of a GitHub Release or publication to an external registry;
- source authenticity or maintainer authorization;
- a trusted builder, runner, operating system or hardware root;
- production-input coverage;
- universal archive, filesystem or toolchain portability;
- compatibility of future source, runner or toolchain revisions without a new release authority.

The release digest establishes byte identity of the generated bundle. It is not, by itself, a signature, authorization decision, trusted timestamp, transparency receipt or durable external publication proof.

## Registration phase

The first CI pass is a measurement probe. It must produce one common candidate release across both publishers and all three platforms. The measured archive digest, manifest digest, source-tree root, entry count and canonical publication report are then registered in a replacement commit directly parented to the frozen P1-A7 head.
