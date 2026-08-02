from __future__ import annotations

import base64
import copy
from typing import Any


def _runner_identity(bundle: dict[str, Any], runner_id: str) -> str:
    for runner in bundle["signedRunnerRegistry"]["payload"]["runners"]:
        if runner["runnerId"] == runner_id:
            return runner["identitySha256"]
    raise KeyError(runner_id)


def _toolchain_digest(bundle: dict[str, Any], version: str) -> str:
    for item in bundle["signedToolchainRegistry"]["payload"]["versions"]:
        if item["version"] == version:
            return item["artifactSha256"]
    raise KeyError(version)


def mutation_cases(bundle: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    def add(name: str, mutate) -> None:
        item = copy.deepcopy(bundle)
        mutate(item)
        cases.append((name, item))

    add("runner-registry-signature", lambda b: b["signedRunnerRegistry"].__setitem__("signatureBase64", base64.b64encode(b"x" * 64).decode()))
    add("toolchain-registry-signature", lambda b: b["signedToolchainRegistry"].__setitem__("signatureBase64", base64.b64encode(b"x" * 64).decode()))
    add("rollback-authorization-signature", lambda b: b["signedRollbackAuthorizations"][0].__setitem__("signatureBase64", base64.b64encode(b"x" * 64).decode()))
    add("runner-registry-digest", lambda b: b["signedRunnerRegistry"].__setitem__("payloadSha256", "0" * 64))
    add("toolchain-registry-digest", lambda b: b["signedToolchainRegistry"].__setitem__("payloadSha256", "0" * 64))
    add("rollback-authorization-digest", lambda b: b["signedRollbackAuthorizations"][0].__setitem__("payloadSha256", "0" * 64))
    add("bundle-source-commit", lambda b: b.__setitem__("sourceP1A19F2Commit", "0" * 40))
    add("bundle-source-report", lambda b: b.__setitem__("sourceP1A19ReportSha256", "0" * 64))
    add("duplicate-route-id", lambda b: b["routes"][1].__setitem__("routeId", b["routes"][0]["routeId"]))
    add("unknown-runner", lambda b: b["routes"][0].__setitem__("runnerId", "runner-unknown"))
    add("runner-identity", lambda b: b["routes"][0].__setitem__("runnerIdentitySha256", "0" * 64))
    add("retired-runner", lambda b: (b["routes"][0].__setitem__("runnerId", "runner-linux-amd64-g2-retired"), b["routes"][0].__setitem__("runnerIdentitySha256", _runner_identity(b, "runner-linux-amd64-g2-retired"))))
    add("quarantined-runner", lambda b: (b["routes"][0].__setitem__("runnerId", "runner-linux-arm64-g1-quarantined"), b["routes"][0].__setitem__("runnerIdentitySha256", _runner_identity(b, "runner-linux-arm64-g1-quarantined"))))
    add("runner-before-admission", lambda b: b["routes"][0].__setitem__("sequence", 99))
    add("runner-after-expiry", lambda b: b["routes"][0].__setitem__("sequence", 181))
    add("unknown-toolchain", lambda b: b["routes"][0].__setitem__("toolchainVersion", "9.9.9"))
    add("toolchain-artifact", lambda b: b["routes"][0].__setitem__("toolchainArtifactSha256", "0" * 64))
    add("candidate-toolchain", lambda b: (b["routes"][0].__setitem__("toolchainVersion", "2.0.0-rc1"), b["routes"][0].__setitem__("toolchainArtifactSha256", _toolchain_digest(b, "2.0.0-rc1"))))
    add("compatibility-before-window", lambda b: b["routes"][3].__setitem__("sequence", 79))
    add("compatibility-after-window", lambda b: b["routes"][3].__setitem__("sequence", 131))
    add("incompatible-generation", lambda b: (b["routes"][0].__setitem__("runnerId", "runner-linux-amd64-g2-compat"), b["routes"][0].__setitem__("runnerIdentitySha256", _runner_identity(b, "runner-linux-amd64-g2-compat"))))
    add("rollback-missing-authorization", lambda b: b["routes"][6].__setitem__("rollbackAuthorizationId", None))
    add("rollback-unknown-authorization", lambda b: b["routes"][6].__setitem__("rollbackAuthorizationId", "rollback-unknown"))
    add("rollback-runner-binding", lambda b: (b["routes"][6].__setitem__("runnerId", "runner-macos-arm64-g2"), b["routes"][6].__setitem__("runnerIdentitySha256", _runner_identity(b, "runner-macos-arm64-g2"))))
    add("rollback-before-window", lambda b: b["routes"][6].__setitem__("sequence", 130))
    add("rollback-after-window", lambda b: b["routes"][6].__setitem__("sequence", 136))
    add("rollback-authorization-lineage", lambda b: b["signedRollbackAuthorizations"][0]["payload"].__setitem__("fromVersion", "1.8.0"))
    add("rollback-target-active", lambda b: (b["routes"][6].__setitem__("toolchainVersion", "1.9.0"), b["routes"][6].__setitem__("toolchainArtifactSha256", _toolchain_digest(b, "1.9.0"))))
    add("rollback-replay-expected-accept", lambda b: b["routes"][7].__setitem__("expectedDecision", copy.deepcopy(b["routes"][6]["expectedDecision"])))
    add("rollback-route-order", lambda b: b["routes"].__setitem__(slice(6, 8), [b["routes"][7], b["routes"][6]]))
    return cases
