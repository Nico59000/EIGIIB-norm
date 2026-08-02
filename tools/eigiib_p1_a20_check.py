from __future__ import annotations

import argparse
from pathlib import Path

from eigiib_p1_a20_core import FIXTURE, canonical_bytes, load_bundle
from eigiib_p1_a20_report import report

DEFAULT_BUNDLE = FIXTURE / "bundle-index.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = report(load_bundle(args.bundle))
    data = canonical_bytes(result)
    if args.output:
        args.output.write_bytes(data)
    else:
        print(data.decode(), end="")


if __name__ == "__main__":
    main()
