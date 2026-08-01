#!/usr/bin/env python3
"""Replay P1-A7.6 Receipt vectors across three routes."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from eigiib_receipt_replay_runner import check_repository

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument("--go", default="go")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = check_repository(args.root, args.go, args.openssl, args.expected, args.corpus)
    print(json.dumps(report, indent=None if args.json else 2, sort_keys=True, separators=(",", ":") if args.json else None))
    return 0 if report["overall_result"] == "conformant" else 1

if __name__ == "__main__":
    raise SystemExit(main())
