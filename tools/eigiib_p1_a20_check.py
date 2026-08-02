from __future__ import annotations

import argparse
import json
from pathlib import Path

from eigiib_p1_a20_common import FIXTURE, build_report, load_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, default=FIXTURE / "runner-admission-bundle.json")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = build_report(load_json(args.bundle))
    rendered = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if args.output:
        args.output.write_bytes(rendered)
    else:
        print(rendered.decode("utf-8"), end="")


if __name__ == "__main__":
    main()
