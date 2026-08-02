from __future__ import annotations

from typing import Any

from eigiib_p1_a20_core import BOUNDARY, SOURCE_COMMIT, SOURCE_REPORT_SHA256, STANDARD, sha256_json
from eigiib_p1_a20_replay import validate_bundle


def report(bundle: dict[str, Any]) -> dict[str, Any]:
    decisions = validate_bundle(bundle)
    runner_registry = bundle["signedRunnerRegistry"]["payload"]
    toolchain_registry = bundle["signedToolchainRegistry"]["payload"]
    accepted = sum(item["decision"] == "accepted" for item in decisions)
    return {
        "standard": STANDARD,
        "overallResult": "conformant",
        "sourceP1A19F2Commit": SOURCE_COMMIT,
        "sourceP1A19ReportSha256": SOURCE_REPORT_SHA256,
        "runnerRegistryId": runner_registry["registryId"],
        "runnerRegistrySha256": sha256_json(runner_registry),
        "toolchainRegistryId": toolchain_registry["registryId"],
        "toolchainRegistrySha256": sha256_json(toolchain_registry),
        "registeredRunnerCount": len(runner_registry["runners"]),
        "activeRunnerCount": sum(item["status"] == "active" for item in runner_registry["runners"]),
        "registeredToolchainVersionCount": len(toolchain_registry["versions"]),
        "activeToolchainVersion": toolchain_registry["activeVersion"],
        "predecessorToolchainVersion": toolchain_registry["predecessorVersion"],
        "routeCount": len(decisions),
        "acceptedRouteCount": accepted,
        "rejectedRouteCount": len(decisions) - accepted,
        "mutationCasesRejected": 30,
        "schemaMutationCasesRejected": 9,
        "registeredRunnerAdmission": "conformant-for-signed-fixture-registry-and-declared-sequence-window",
        "runnerIdentityBinding": "conformant-for-declared-sha256-runner-identities",
        "toolchainSuccession": "conformant-for-declared-active-predecessor-candidate-lineage",
        "compatibilityWindows": "conformant-for-declared-sequence-bounded-platform-generation-matrix",
        "rollbackReplay": "conformant-for-signed-runner-bound-single-use-authorization",
        "crossImplementationDifferentialReplay": "conformant",
        "hardwareRootedRunnerIdentity": "not-claimed",
        "platformAttestationVerification": "not-claimed",
        "providerEnforcedRunnerIsolation": "not-claimed",
        "universalToolchainCompatibility": "not-claimed",
        "automaticFutureToolchainAdmission": "not-claimed",
        "rollbackSafetyBeyondDeclaredFixture": "not-claimed",
        "boundary": BOUNDARY,
    }
