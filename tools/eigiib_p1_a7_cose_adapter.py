#!/usr/bin/env python3
"""Portable P1-A7.5 deterministic CBOR and COSE_Sign1 adapter."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from eigiib_p1_a7_cose_codec import (
    CborError, CborMap, CborTag, Reject, canonical_b64, canonical_decode,
    decode_canonical_b64, decode_cbor, encode_cbor, identity, map_replace,
    parse_public_key_pem, strict_json_loads,
)
from eigiib_p1_a7_cose_profile import (
    ALGORITHM_EDDSA, CONTENT_TYPE, COSE_SIGN1_TAG, ISSUER, ROUTE, STANDARD, TYPE,
    Result, evaluate, sig_structure, verify_ed25519,
)

__all__ = [name for name in globals() if not name.startswith("_")]

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--vector-id", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        result = evaluate(
            args.input.read_bytes(),
            args.public_key.read_text(encoding="utf-8"),
            args.vector_id,
            args.openssl,
        )
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
