#!/usr/bin/env python3
"""Independent E14-A5 decision derivation for portable matrix replay."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

TOOL_VERSION = "0.1.0"


def classify(values: dict[str, str]) -> str:
    ordered = (
        ("rejected", (
            values.get("upstream_result") == "rejected",
            values.get("policy_result") == "deny",
            values.get("recipient_result") == "unauthenticated",
            values.get("transport_result") == "unprotected",
            values.get("replay_result") == "replay-detected",
        )),
        ("unavailable", tuple(value == "unavailable" for value in values.values())),
        ("held", tuple(value == "held" for value in values.values())),
    )
    for state, predicates in ordered:
        if any(predicates):
            return state
    return "released"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("vector")
    args = parser.parse_args(argv)
    vector = json.loads(Path(args.vector).read_text(encoding="utf-8"))
    print(json.dumps({"id": vector.get("id"), "state": classify(vector["inputs"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
