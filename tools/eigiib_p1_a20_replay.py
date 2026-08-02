from __future__ import annotations

from typing import Any

from eigiib_p1_a20_core import ENVIRONMENT, SOURCE_COMMIT, SOURCE_REPORT_SHA256, sha256_json
from eigiib_p1_a20_registry import load_registries


def decision_for_route(
    route: dict[str, Any],
    runner_registry: dict[str, Any],
    toolchain_registry: dict[str, Any],
    authorizations: dict[str, dict[str, Any]],
    used_authorizations: set[str],
) -> dict[str, Any]:
    base = {
        "routeId": route["routeId"],
        "sequence": route["sequence"],
        "environment": route["environment"],
        "runnerId": route["runnerId"],
        "toolchainVersion": route["toolchainVersion"],
        "mode": route["mode"],
        "rollbackAuthorizationId": route["rollbackAuthorizationId"],
        "sourceP1A19F2Commit": SOURCE_COMMIT,
        "sourceP1A19ReportSha256": SOURCE_REPORT_SHA256,
        "runnerRegistrySha256": sha256_json(runner_registry),
        "toolchainRegistrySha256": sha256_json(toolchain_registry),
    }

    def finish(decision: str, reason: str) -> dict[str, Any]:
        result = {**base, "decision": decision, "reason": reason}
        result["decisionSha256"] = sha256_json(result)
        return result

    if route["environment"] != ENVIRONMENT:
        return finish("rejected", "environment-mismatch")
    runners = {item["runnerId"]: item for item in runner_registry["runners"]}
    runner = runners.get(route["runnerId"])
    if runner is None:
        return finish("rejected", "unknown-runner")
    if route["runnerIdentitySha256"] != runner["identitySha256"]:
        return finish("rejected", "runner-identity-mismatch")
    if runner["status"] != "active":
        return finish("rejected", f"runner-status-{runner['status']}")
    if route["sequence"] < runner["admittedAtSequence"]:
        return finish("rejected", "runner-not-yet-admitted")
    if route["sequence"] > runner["validThroughSequence"]:
        return finish("rejected", "runner-admission-expired")

    versions = {item["version"]: item for item in toolchain_registry["versions"]}
    toolchain = versions.get(route["toolchainVersion"])
    if toolchain is None:
        return finish("rejected", "unknown-toolchain")
    if route["toolchainArtifactSha256"] != toolchain["artifactSha256"]:
        return finish("rejected", "toolchain-artifact-mismatch")
    if toolchain["state"] not in {"active", "compatibility"}:
        return finish("rejected", f"toolchain-state-{toolchain['state']}")
    if runner["generation"] not in toolchain["compatibleRunnerGenerations"].get(runner["platform"], []):
        return finish("rejected", "incompatible-runner-toolchain")

    if route["mode"] == "normal":
        if route["rollbackAuthorizationId"] is not None:
            return finish("rejected", "unexpected-rollback-authorization")
        if not (toolchain["ordinaryFromSequence"] <= route["sequence"] <= toolchain["ordinaryThroughSequence"]):
            return finish("rejected", "compatibility-window-closed")
        return finish("accepted", "ordinary-admission-and-compatibility-window-satisfied")

    if route["mode"] != "rollback":
        return finish("rejected", "unknown-execution-mode")
    authorization_id = route["rollbackAuthorizationId"]
    if authorization_id is None:
        return finish("rejected", "rollback-authorization-required")
    if authorization_id in used_authorizations:
        return finish("rejected", "rollback-authorization-replayed")
    authorization = authorizations.get(authorization_id)
    if authorization is None:
        return finish("rejected", "unknown-rollback-authorization")
    if route["toolchainVersion"] != toolchain_registry["predecessorVersion"]:
        return finish("rejected", "rollback-target-is-not-registered-predecessor")
    if authorization["fromVersion"] != toolchain_registry["activeVersion"] or authorization["toVersion"] != route["toolchainVersion"]:
        return finish("rejected", "rollback-lineage-mismatch")
    if authorization["runnerId"] != route["runnerId"] or authorization["environment"] != route["environment"]:
        return finish("rejected", "rollback-authorization-binding-mismatch")
    if not (authorization["notBeforeSequence"] <= route["sequence"] <= authorization["notAfterSequence"]):
        return finish("rejected", "rollback-authorization-window-closed")
    if route["sequence"] > toolchain["rollbackEligibleThroughSequence"]:
        return finish("rejected", "toolchain-rollback-window-closed")
    used_authorizations.add(authorization_id)
    return finish("accepted", "signed-single-use-rollback-authorized")


def validate_bundle(bundle: dict[str, Any], verify_signatures: bool = True) -> list[dict[str, Any]]:
    if bundle.get("standard") != "EIGIIB-P1-A20-CONFORMANCE-1.0":
        raise ValueError("bundle standard mismatch")
    if bundle.get("sourceP1A19F2Commit") != SOURCE_COMMIT:
        raise ValueError("bundle source commit mismatch")
    if bundle.get("sourceP1A19ReportSha256") != SOURCE_REPORT_SHA256:
        raise ValueError("bundle source report mismatch")
    if bundle.get("environment") != ENVIRONMENT:
        raise ValueError("bundle environment mismatch")

    runner_registry, toolchain_registry, authorizations = load_registries(bundle, verify_signatures)
    used_authorizations: set[str] = set()
    seen_routes: set[str] = set()
    decisions: list[dict[str, Any]] = []
    for route in bundle["routes"]:
        if route["routeId"] in seen_routes:
            raise ValueError("duplicate route id")
        seen_routes.add(route["routeId"])
        expected = decision_for_route(route, runner_registry, toolchain_registry, authorizations, used_authorizations)
        if route["expectedDecision"] != expected:
            raise ValueError("route decision differs from canonical replay")
        decisions.append(expected)
    if len(decisions) != 13:
        raise ValueError("route matrix size mismatch")
    return decisions
