#!/usr/bin/env python3
"""Reference E15-A5 external-evidence classification."""
from __future__ import annotations
import argparse, json
from pathlib import Path

TOOL_VERSION = "0.1.0"

NEGATIVE = {
    "lineage_result": {"replay-detected"},
    "delivery_result": {"rejected"},
    "publication_result": {"rejected"},
    "withdrawal_result": {"rejected", "contested"},
    "content_identity_result": {"rejected"},
    "observer_independence_result": {"insufficient"},
    "anti_rollback_result": {"rollback-detected"},
}
STAGE = [
    ("withdrawal_result", "post-withdrawal-observed", "withdrawal-evidence-bounded"),
    ("withdrawal_result", "distribution-stopped", "distribution-stop-bounded"),
    ("withdrawal_result", "tombstoned", "tombstone-bounded"),
    ("withdrawal_result", "withdrawal-requested", "withdrawal-request-bounded"),
    ("publication_result", "independently-read-back", "independent-readback-bounded"),
    ("publication_result", "persistence-observed", "persistence-evidence-bounded"),
    ("publication_result", "publication-observed", "publication-evidence-bounded"),
    ("delivery_result", "acknowledged", "acknowledgement-evidence-bounded"),
    ("delivery_result", "externally-attested", "delivery-evidence-bounded"),
]

def classify(values: dict[str, str]) -> str:
    if any(values.get(key) in states for key, states in NEGATIVE.items()):
        return "rejected"
    if any(value == "unavailable" for value in values.values()):
        return "unavailable"
    if any(value == "held" for value in values.values()):
        return "held"
    for key, value, state in STAGE:
        if values.get(key) == value:
            return state
    return "held"

def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("vector"); args=parser.parse_args(argv)
    vector=json.loads(Path(args.vector).read_text(encoding="utf-8"))
    if isinstance(vector.get("cases"), list):
        out={str(case.get("id")): classify(case["inputs"]) for case in vector["cases"]}
        print(json.dumps({"states":out},sort_keys=True))
    else:
        print(json.dumps({"id":vector.get("id"),"state":classify(vector["inputs"])},sort_keys=True))
    return 0
if __name__ == "__main__": raise SystemExit(main())
