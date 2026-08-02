from __future__ import annotations

from typing import Any

from eigiib_p1_a20_core import ENVIRONMENT, SOURCE_COMMIT, SOURCE_REPORT_SHA256, sha256_json
from eigiib_p1_a20_registry import load_registries

_ROUTE_FIELDS = (
    "routeId",
    "sequence",
    "environment",
    "runnerId",
    "runnerIdentitySha256",
    "toolchainVersion",
    "toolchainArtifactSha256",
    "mode",
    "rollbackAuthorizationId",
)

_CANONICAL_ROUTE_MATRIX = (
    ("route-01-linux-active-current", 120, ENVIRONMENT, "runner-linux-amd64-g3", "830b6503b71b20cc233e36f02ad0f2b6fdffdc31df4b9754bfd2d92c51a4d0c8", "1.9.0", "d877fc1be3066de1c4d2195ef522913a14753a1b43b3a5275fbbee8d78a9e15e", "normal", None),
    ("route-02-macos-active-current", 120, ENVIRONMENT, "runner-macos-arm64-g2", "6f9639be17dc0386778cbd7701693f7057c39f78d3f86746866aa5857040e9f0", "1.9.0", "d877fc1be3066de1c4d2195ef522913a14753a1b43b3a5275fbbee8d78a9e15e", "normal", None),
    ("route-03-windows-active-current", 120, ENVIRONMENT, "runner-windows-amd64-g2", "b50dfced73a1e75c918bae9eb82e2b901696de68f58c31d2a1defd4e39514975", "1.9.0", "d877fc1be3066de1c4d2195ef522913a14753a1b43b3a5275fbbee8d78a9e15e", "normal", None),
    ("route-04-linux-g2-predecessor-compatible", 120, ENVIRONMENT, "runner-linux-amd64-g2-compat", "2d49c471d669cd7121178789ecf70bceca301ff5d80d18a62aceea1c2fe969e1", "1.8.0", "984a23b0835a4ca9e0b349937031d5881006cf481c3d51efc9cbde4791715dcf", "normal", None),
    ("route-05-macos-predecessor-window-edge", 130, ENVIRONMENT, "runner-macos-arm64-g2", "6f9639be17dc0386778cbd7701693f7057c39f78d3f86746866aa5857040e9f0", "1.8.0", "984a23b0835a4ca9e0b349937031d5881006cf481c3d51efc9cbde4791715dcf", "normal", None),
    ("route-06-predecessor-window-expired", 131, ENVIRONMENT, "runner-linux-amd64-g3", "830b6503b71b20cc233e36f02ad0f2b6fdffdc31df4b9754bfd2d92c51a4d0c8", "1.8.0", "984a23b0835a4ca9e0b349937031d5881006cf481c3d51efc9cbde4791715dcf", "normal", None),
    ("route-07-authorized-rollback", 132, ENVIRONMENT, "runner-linux-amd64-g3", "830b6503b71b20cc233e36f02ad0f2b6fdffdc31df4b9754bfd2d92c51a4d0c8", "1.8.0", "984a23b0835a4ca9e0b349937031d5881006cf481c3d51efc9cbde4791715dcf", "rollback", "rollback-1.9.0-to-1.8.0-prod-v1"),
    ("route-08-rollback-replay", 133, ENVIRONMENT, "runner-linux-amd64-g3", "830b6503b71b20cc233e36f02ad0f2b6fdffdc31df4b9754bfd2d92c51a4d0c8", "1.8.0", "984a23b0835a4ca9e0b349937031d5881006cf481c3d51efc9cbde4791715dcf", "rollback", "rollback-1.9.0-to-1.8.0-prod-v1"),
    ("route-09-retired-runner", 120, ENVIRONMENT, "runner-linux-amd64-g2-retired", "3105d26a9d074f97d98bdeec350e9262588c9a25de0708c27550fab1d26fa973", "1.8.0", "984a23b0835a4ca9e0b349937031d5881006cf481c3d51efc9cbde4791715dcf", "normal", None),
    ("route-10-quarantined-runner", 120, ENVIRONMENT, "runner-linux-arm64-g1-quarantined", "c00fea49bd6d3a32f6c5605376716c7a9cbc983d05a9b6265276f5a11edacbde", "1.8.0", "984a23b0835a4ca9e0b349937031d5881006cf481c3d51efc9cbde4791715dcf", "normal", None),
    ("route-11-runner-identity-mismatch", 120, ENVIRONMENT, "runner-linux-amd64-g3", "0000000000000000000000000000000000000000000000000000000000000000", "1.9.0", "d877fc1be3066de1c4d2195ef522913a14753a1b43b3a5275fbbee8d78a9e15e", "normal", None),
    ("route-12-candidate-toolchain", 160, ENVIRONMENT, "runner-linux-amd64-g3", "830b6503b71b20cc233e36f02ad0f2b6fdffdc31df4b9754bfd2d92c51a4d0c8", "2.0.0-rc1", "d0370f30605a938f4aeae473a8f0ebe575c64702b502e2277969c832770be1b4", "normal", None),
    ("route-13-incompatible-runner-generation", 120, ENVIRONMENT, "runner-linux-amd64-g2-compat", "2d49c471d669cd7121178789ecf70bceca301ff5d80d18a62aceea1c2fe969e1", "1.9.0", "d877fc1be3066de1c4d2195ef522913a14753a1b43b3a5275fbbee8d78a9e15e", "normal", None),
)


def _validate_canonical_route_matrix(routes: Any) -> None:
    if not isinstance(routes, list):
        raise ValueError("route matrix must be an array")
    actual = tuple(tuple(route.get(field) for field in _ROUTE_FIELDS) for route in routes)
    if actual != _CANONICAL_ROUTE_MATRIX:
        raise ValueError("route matrix differs from canonical scenarios")


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

    _validate_canonical_route_matrix(bundle.get("routes"))
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
    return decisions
