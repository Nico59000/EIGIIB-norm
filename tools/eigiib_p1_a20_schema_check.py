from __future__ import annotations

import argparse
from pathlib import Path

from eigiib_p1_a20_core import FIXTURE, load_bundle, load_json
from eigiib_p1_a20_replay import validate_bundle
from eigiib_p1_a20_schema import validate_draft202012_instance

ROOT = FIXTURE.parent.parent.parent
DEFAULT_SCHEMA = ROOT / "schemas/eigiib-p1-a20-bundle.schema.json"
DEFAULT_BUNDLE = FIXTURE / "bundle-index.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    schema = load_json(args.schema)
    bundle = load_bundle(args.bundle)
    validate_draft202012_instance(schema, bundle)
    validate_bundle(bundle)
    print("P1-A20 Draft 2020-12 closed-schema and runner/toolchain replay: PASS")


if __name__ == "__main__":
    main()
