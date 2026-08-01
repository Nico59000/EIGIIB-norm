#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a15_common import ConformanceError, canonical_json_bytes, live_projection


def main() -> int:
    try:
        projection = live_projection(os.environ.get("GH_TOKEN"))
    except ConformanceError as exc:
        print(f"P1-A15 live readback failed: {exc}", file=sys.stderr)
        return 1
    result = {"route": "reference-python-urllib", "portable": projection}
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
