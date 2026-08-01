#!/usr/bin/env python3
"""Replay the P1-A7.4 manifest, DSSE and signature negative corpus."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eigiib_signature_replay_runner import check_repository


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--go", default="go")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = check_repository(
        args.root,
        args.go,
        args.openssl,
        args.expected,
        args.corpus,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(result["overall_result"])
        for finding in result["findings"]:
            print(
                f"{finding['code']}: {finding['route']}: "
                f"{finding['vector_id']}: {finding['message']}"
            )
    return 0 if result["overall_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
