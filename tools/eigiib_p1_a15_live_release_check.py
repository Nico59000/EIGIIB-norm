#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a15_common import ConformanceError, canonical_json_bytes, validate_fixture


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        report = validate_fixture(ROOT)
    except ConformanceError as exc:
        print(f"P1-A15 non-conformant: {exc}", file=sys.stderr)
        return 1
    payload = canonical_json_bytes(report)
    if args.output:
        args.output.write_bytes(payload)
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
