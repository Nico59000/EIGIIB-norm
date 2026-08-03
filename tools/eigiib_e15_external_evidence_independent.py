#!/usr/bin/env python3
"""Independent E15-A5 external-evidence classification."""
from __future__ import annotations
import argparse, json
from pathlib import Path

TOOL_VERSION = "0.1.0"

def classify(v: dict[str, str]) -> str:
    denials = (
        v.get("lineage_result") == "replay-detected",
        v.get("delivery_result") == "rejected",
        v.get("publication_result") == "rejected",
        v.get("withdrawal_result") in ("rejected", "contested"),
        v.get("content_identity_result") == "rejected",
        v.get("observer_independence_result") == "insufficient",
        v.get("anti_rollback_result") == "rollback-detected",
    )
    if True in denials:
        return "rejected"
    values=tuple(v.values())
    if "unavailable" in values:
        return "unavailable"
    if "held" in values:
        return "held"
    withdrawal={"withdrawal-requested":"withdrawal-request-bounded","tombstoned":"tombstone-bounded","distribution-stopped":"distribution-stop-bounded","post-withdrawal-observed":"withdrawal-evidence-bounded"}
    publication={"publication-observed":"publication-evidence-bounded","persistence-observed":"persistence-evidence-bounded","independently-read-back":"independent-readback-bounded"}
    delivery={"externally-attested":"delivery-evidence-bounded","acknowledged":"acknowledgement-evidence-bounded"}
    if v.get("withdrawal_result") in withdrawal: return withdrawal[v["withdrawal_result"]]
    if v.get("publication_result") in publication: return publication[v["publication_result"]]
    return delivery.get(v.get("delivery_result"), "held")

def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(); p.add_argument("vector"); a=p.parse_args(argv)
    data=json.loads(Path(a.vector).read_text(encoding="utf-8"))
    if isinstance(data.get("cases"), list):
        out={str(case.get("id")): classify(case["inputs"]) for case in data["cases"]}
        print(json.dumps({"states":out},sort_keys=True))
    else:
        print(json.dumps({"id":data.get("id"),"state":classify(data["inputs"])},sort_keys=True))
    return 0
if __name__ == "__main__": raise SystemExit(main())
