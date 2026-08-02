#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

EXPECTED_ROUTES = [
    "external-oras-cli",
    "independent-go-stdlib",
    "reference-python-urllib",
]


def strict_load(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("routes", nargs=3)
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        results = [strict_load(pathlib.Path(item)) for item in args.routes]
        route_names = sorted(item.pop("route") for item in results)
        if route_names != EXPECTED_ROUTES:
            raise ValueError(f"route set mismatch: {route_names}")
        first = results[0]
        for index, item in enumerate(results[1:], start=2):
            if item != first:
                raise ValueError(f"portable route {index} differs")
        replay = {
            "standard": "EIGIIB-P1-A16-ROUTE-REPLAY-1.0",
            "routes": route_names,
            "portable": first,
            "overallResult": "conformant",
        }
    except Exception as exc:
        print(f"P1-A16 route replay failed: {exc}", file=sys.stderr)
        return 1
    encoded = json.dumps(replay, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        pathlib.Path(args.output).write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
