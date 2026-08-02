from __future__ import annotations

import argparse
import json
from pathlib import Path

from eigiib_p1_a19_common import FIXTURE, load_json, report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    args = parser.parse_args()
    result = report(load_json(FIXTURE / "interoperability-bundle.json"))
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
