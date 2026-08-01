#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a15_common import ConformanceError, canonical_json_bytes, load_json, require


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        require(len(args.results) == 3, "exactly three route results are required")
        results = [load_json(path) for path in args.results]
        routes = [result.get("route") for result in results]
        require(len(set(routes)) == 3, "route names must be distinct")
        require(set(routes) == {"reference-python-urllib", "independent-go-stdlib", "external-gh-cli"}, "route set mismatch")
        portable = results[0].get("portable")
        for result in results[1:]:
            require(result.get("portable") == portable, f"portable mismatch for route {result.get('route')}")
        replay = {
            "standard": "EIGIIB-P1-A15-THREE-ROUTE-REPLAY-1.0",
            "routes": sorted(routes),
            "portable": portable,
            "overallResult": "conformant",
        }
    except ConformanceError as exc:
        print(f"P1-A15 route replay failed: {exc}", file=sys.stderr)
        return 1
    payload = canonical_json_bytes(replay)
    if args.output:
        args.output.write_bytes(payload)
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
