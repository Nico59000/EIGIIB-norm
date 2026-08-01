#!/usr/bin/env python3
"""Portable P1-A7.6 Receipt adapter."""
from __future__ import annotations
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from eigiib_p1_a7_receipt_profile import *

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--vector-id", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        result = evaluate(args.input.read_bytes(), args.vector_id, args.openssl)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
