#!/usr/bin/env python3
"""Independent non-importing E16-A5 preservation closure verifier."""
from __future__ import annotations

import json
import re
import sys

STANDARD = "EIGIIB-E16-A5-VERIFIER-1.0"
SHA = re.compile(r"^[0-9a-f]{64}$")


def evaluate(item):
    problems = []
    identifier = item.get("id") if isinstance(item, dict) else ""
    payload = item.get("inputs") if isinstance(item, dict) else None
    if not isinstance(identifier, str) or not identifier:
        identifier = ""
        problems.append("case-id-invalid")
    if not isinstance(payload, dict):
        payload = {}
        problems.append("inputs-invalid")

    digest = payload.get("expected_content_sha256")
    generation = payload.get("accepted_generation")
    route_values = payload.get("restore_routes")
    if not isinstance(digest, str) or SHA.fullmatch(digest) is None:
        problems.append("expected-content-invalid")
    if not isinstance(generation, int) or generation < 0:
        problems.append("accepted-generation-invalid")
    if not isinstance(route_values, list):
        route_values = []
        problems.append("restore-routes-invalid")

    ids = []
    control_domains = []
    passed = 0
    route_statuses = []
    for position, value in enumerate(route_values):
        if not isinstance(value, dict):
            problems.append(f"route-{position}-invalid")
            route_statuses.append("deny")
            continue
        rid = value.get("id")
        control = value.get("verifier_domain")
        outcome = value.get("result")
        if isinstance(rid, str) and rid:
            ids.append(rid)
        else:
            problems.append(f"route-{position}-id-invalid")
            route_statuses.append("deny")
        if isinstance(control, str) and control:
            control_domains.append(control)
        else:
            problems.append(f"route-{position}-domain-invalid")
            route_statuses.append("deny")
        if outcome == "verified":
            passed += 1
            route_statuses.append("permit")
        elif outcome == "mismatch":
            problems.append(f"route-{position}-negative")
            route_statuses.append("deny")
        elif outcome == "held":
            route_statuses.append("held")
        elif outcome == "unavailable":
            route_statuses.append("unavailable")
        else:
            problems.append(f"route-{position}-result-invalid")
            route_statuses.append("deny")
        if value.get("content_sha256") != digest:
            problems.append(f"route-{position}-content-mismatch")
            route_statuses.append("deny")
        if value.get("generation") != generation:
            problems.append(f"route-{position}-generation-mismatch")
            route_statuses.append("deny")

    if len(ids) != len(set(ids)):
        problems.append("route-id-duplicate")
        route_statuses.append("deny")
    if len(control_domains) != len(set(control_domains)):
        problems.append("verifier-domain-duplicate")
        route_statuses.append("deny")
    if len(route_values) < 3:
        problems.append("route-count-insufficient")
        route_statuses.append("deny")

    def classify(value, allowed, rejected):
        if value in rejected:
            return "deny"
        if value == "unavailable":
            return "unavailable"
        if value == "held":
            return "held"
        if value in allowed:
            return "permit"
        return "deny"

    if "deny" in route_statuses:
        route_gate = "deny"
    elif "unavailable" in route_statuses:
        route_gate = "unavailable"
    elif "held" in route_statuses:
        route_gate = "held"
    else:
        route_gate = "permit"

    gates = {
        "lineage": classify(payload.get("lineage_result"), {"current"}, {"stale"}),
        "a4_recovery": classify(payload.get("a4_recovery_result"), {"successor-replica-recovered"}, {"rejected"}),
        "content_identity": classify(payload.get("content_identity_result"), {"verified"}, {"rejected"}),
        "verifier_independence": classify(payload.get("verifier_independence_result"), {"independent"}, {"insufficient"}),
        "route_coverage": classify(payload.get("route_coverage_result"), {"complete"}, {"incomplete"}),
        "anti_rollback": classify(payload.get("anti_rollback_result"), {"current"}, {"rollback-detected"}),
        "loss": classify(payload.get("loss_result"), {"clear", "source-loss-contained"}, {"target-loss-confirmed"}),
        "quarantine": classify(payload.get("quarantine_result"), {"clear", "source-quarantine-contained"}, {"target-quarantine-active"}),
        "final_freeze": classify(payload.get("final_freeze_result"), {"conformant"}, {"non-conformant"}),
        "restore_routes": route_gate,
    }
    all_gates = tuple(gates.values())
    if "deny" in all_gates:
        combined = "deny"
    elif "unavailable" in all_gates:
        combined = "unavailable"
    elif "held" in all_gates:
        combined = "held"
    else:
        combined = "permit"
    state = {
        "deny": "rejected",
        "unavailable": "unavailable",
        "held": "held",
        "permit": "e16-preservation-closure-verified",
    }[combined]
    return {
        "standard": STANDARD,
        "case_id": identifier,
        "state": state,
        "gates": gates,
        "route_count": len(route_values),
        "verified_route_count": passed,
        "content_sha256": digest,
        "generation": generation,
        "findings": sorted(set(problems)),
    }


def main():
    try:
        data = json.load(sys.stdin)
        if not isinstance(data, dict):
            raise ValueError("case must be an object")
        result = evaluate(data)
    except Exception as exc:
        result = {
            "standard": STANDARD,
            "case_id": "",
            "state": "rejected",
            "gates": {},
            "route_count": 0,
            "verified_route_count": 0,
            "content_sha256": None,
            "generation": None,
            "findings": [f"input-error:{exc}"],
        }
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
