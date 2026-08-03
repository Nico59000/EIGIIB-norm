#!/usr/bin/env python3
"""Reference E16-A5 preservation closure verifier."""
from __future__ import annotations

import json
import re
import sys
from typing import Any

STANDARD = "EIGIIB-E16-A5-VERIFIER-1.0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def combine(gates: dict[str, str]) -> str:
    values = list(gates.values())
    if "deny" in values:
        return "deny"
    if "unavailable" in values:
        return "unavailable"
    if "held" in values:
        return "held"
    return "permit"


def scalar_gate(value: str, permit: set[str], deny: set[str], held: set[str] = {"held"}, unavailable: set[str] = {"unavailable"}) -> str:
    if value in deny:
        return "deny"
    if value in unavailable:
        return "unavailable"
    if value in held:
        return "held"
    if value in permit:
        return "permit"
    return "deny"


def verify(case: dict[str, Any]) -> dict[str, Any]:
    case_id = case.get("id")
    data = case.get("inputs")
    findings: list[str] = []
    if not isinstance(case_id, str) or not case_id:
        findings.append("case-id-invalid")
        case_id = ""
    if not isinstance(data, dict):
        data = {}
        findings.append("inputs-invalid")

    expected_digest = data.get("expected_content_sha256")
    generation = data.get("accepted_generation")
    routes = data.get("restore_routes")
    if not isinstance(expected_digest, str) or not HEX64.fullmatch(expected_digest):
        findings.append("expected-content-invalid")
    if not isinstance(generation, int) or generation < 0:
        findings.append("accepted-generation-invalid")
    if not isinstance(routes, list):
        routes = []
        findings.append("restore-routes-invalid")

    route_ids: list[str] = []
    domains: list[str] = []
    verified_count = 0
    route_gate = "permit"
    for index, route in enumerate(routes):
        if not isinstance(route, dict):
            findings.append(f"route-{index}-invalid")
            route_gate = "deny"
            continue
        rid = route.get("id")
        domain = route.get("verifier_domain")
        result = route.get("result")
        digest = route.get("content_sha256")
        route_generation = route.get("generation")
        if not isinstance(rid, str) or not rid:
            findings.append(f"route-{index}-id-invalid")
            route_gate = "deny"
        else:
            route_ids.append(rid)
        if not isinstance(domain, str) or not domain:
            findings.append(f"route-{index}-domain-invalid")
            route_gate = "deny"
        else:
            domains.append(domain)
        if result == "mismatch":
            findings.append(f"route-{index}-negative")
            route_gate = "deny"
        elif result == "unavailable":
            if route_gate != "deny":
                route_gate = "unavailable"
        elif result == "held":
            if route_gate not in {"deny", "unavailable"}:
                route_gate = "held"
        elif result == "verified":
            verified_count += 1
        else:
            findings.append(f"route-{index}-result-invalid")
            route_gate = "deny"
        if digest != expected_digest:
            findings.append(f"route-{index}-content-mismatch")
            route_gate = "deny"
        if route_generation != generation:
            findings.append(f"route-{index}-generation-mismatch")
            route_gate = "deny"

    if len(route_ids) != len(set(route_ids)):
        findings.append("route-id-duplicate")
        route_gate = "deny"
    if len(domains) != len(set(domains)):
        findings.append("verifier-domain-duplicate")
        route_gate = "deny"
    if len(routes) < 3:
        findings.append("route-count-insufficient")
        route_gate = "deny"

    gates = {
        "lineage": scalar_gate(str(data.get("lineage_result")), {"current"}, {"stale"}),
        "a4_recovery": scalar_gate(str(data.get("a4_recovery_result")), {"successor-replica-recovered"}, {"rejected"}),
        "content_identity": scalar_gate(str(data.get("content_identity_result")), {"verified"}, {"rejected"}),
        "verifier_independence": scalar_gate(str(data.get("verifier_independence_result")), {"independent"}, {"insufficient"}),
        "route_coverage": scalar_gate(str(data.get("route_coverage_result")), {"complete"}, {"incomplete"}),
        "anti_rollback": scalar_gate(str(data.get("anti_rollback_result")), {"current"}, {"rollback-detected"}),
        "loss": scalar_gate(str(data.get("loss_result")), {"clear", "source-loss-contained"}, {"target-loss-confirmed"}),
        "quarantine": scalar_gate(str(data.get("quarantine_result")), {"clear", "source-quarantine-contained"}, {"target-quarantine-active"}),
        "final_freeze": scalar_gate(str(data.get("final_freeze_result")), {"conformant"}, {"non-conformant"}),
        "restore_routes": route_gate,
    }
    aggregate = combine(gates)
    state = {
        "permit": "e16-preservation-closure-verified",
        "deny": "rejected",
        "held": "held",
        "unavailable": "unavailable",
    }[aggregate]
    return {
        "standard": STANDARD,
        "case_id": case_id,
        "state": state,
        "gates": gates,
        "route_count": len(routes),
        "verified_route_count": verified_count,
        "content_sha256": expected_digest,
        "generation": generation,
        "findings": sorted(set(findings)),
    }


def main() -> int:
    try:
        value = json.load(sys.stdin)
        if not isinstance(value, dict):
            raise ValueError("case must be an object")
        report = verify(value)
    except Exception as exc:
        report = {
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
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
