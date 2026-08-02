#!/usr/bin/env python3
from __future__ import annotations

import json
import sys

from eigiib_p1_a16_common import live_public_route


def main() -> int:
    try:
        result = live_public_route()
    except Exception as exc:
        print(f"P1-A16 Python live route failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
