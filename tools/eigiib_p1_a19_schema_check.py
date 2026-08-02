from __future__ import annotations

import argparse
from pathlib import Path

from eigiib_p1_a19_common import FIXTURE, load_json, validate_bundle
from eigiib_p1_a19_schema import validate_draft202012_instance

ROOT = FIXTURE.parent.parent.parent
DEFAULT_SCHEMA = ROOT / "schemas/eigiib-p1-a19-bundle.schema.json"
DEFAULT_BUNDLE = FIXTURE / "interoperability-bundle.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    schema = load_json(args.schema)
    bundle = load_json(args.bundle)
    validate_draft202012_instance(schema, bundle)
    validate_bundle(bundle)
    print("P1-A19 Draft 2020-12 closed-schema and semantic validation: PASS")


if __name__ == "__main__":
    main()
