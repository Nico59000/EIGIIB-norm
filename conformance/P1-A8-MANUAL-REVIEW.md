# P1-A8 manual claim-boundary review

- [x] The distributed source commit is the exact frozen P1-A7.7 head.
- [x] The P1-A7 authority root is imported unchanged.
- [x] Archive bytes are read from Git objects rather than checkout files.
- [x] The archive profile excludes compression, PAX, GNU extensions and directory entries.
- [x] Python and Go implement separate manifest and USTAR producers.
- [x] Producer success text is not used as the equality decision.
- [x] The replay parser validates exact headers, checksums, padding and trailer length.
- [x] The archive is replayed in a fresh directory without `.git`.
- [x] P1-A7.1 through P1-A7.7 are replayed from extracted bytes.
- [x] Release SHA-256 identity is not described as authentication or authorization.
- [x] No GitHub Release, registry upload or durable external publication is claimed.
- [x] Builder, runner, operating-system and hardware trust remain outside the result.

The checked-in release digests and canonical publication report are byte-identical on all required platforms. External publication remains explicitly unclaimed.
