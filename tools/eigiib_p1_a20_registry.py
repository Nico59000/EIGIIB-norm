from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from eigiib_p1_a20_core import FIXTURE, sha256_json, validate_source, verify_ed25519

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def validate_runner_registry(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate_source(registry)
    if registry.get("registryId") != "eigiib-p1-a20-runner-registry-v1" or registry.get("sequence") != 120:
        raise ValueError("runner registry metadata mismatch")
    runners = registry.get("runners")
    if not isinstance(runners, list) or runners != sorted(runners, key=lambda item: item["runnerId"]):
        raise ValueError("runner registry order mismatch")
    result: dict[str, dict[str, Any]] = {}
    for runner in runners:
        runner_id = runner["runnerId"]
        if runner_id in result:
            raise ValueError("duplicate runner id")
        if runner["status"] not in {"active", "retired", "quarantined"}:
            raise ValueError("unknown runner status")
        if runner["generation"] < 1 or runner["admittedAtSequence"] > runner["validThroughSequence"]:
            raise ValueError("invalid runner admission record")
        if not HEX64.fullmatch(runner["identitySha256"]):
            raise ValueError("invalid runner identity digest")
        result[runner_id] = runner
    return result


def validate_toolchain_registry(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate_source(registry)
    if registry.get("registryId") != "eigiib-p1-a20-toolchain-registry-v1" or registry.get("sequence") != 120:
        raise ValueError("toolchain registry metadata mismatch")
    if registry.get("toolchainId") != "eigiib-verifier":
        raise ValueError("toolchain id mismatch")
    result: dict[str, dict[str, Any]] = {}
    for item in registry["versions"]:
        if item["version"] in result:
            raise ValueError("duplicate toolchain version")
        if item["state"] not in {"active", "compatibility", "candidate", "retired"}:
            raise ValueError("unknown toolchain state")
        if item["ordinaryFromSequence"] > item["ordinaryThroughSequence"]:
            raise ValueError("invalid compatibility window")
        if item["rollbackEligibleThroughSequence"] < item["ordinaryThroughSequence"]:
            raise ValueError("invalid rollback window")
        if not HEX64.fullmatch(item["artifactSha256"]):
            raise ValueError("invalid toolchain artifact digest")
        for platform, generations in item["compatibleRunnerGenerations"].items():
            if platform not in {"linux", "macos", "windows"}:
                raise ValueError("unknown compatibility platform")
            if generations != sorted(set(generations)) or any(g < 1 for g in generations):
                raise ValueError("non-canonical compatible generation set")
        result[item["version"]] = item
    active = result.get(registry["activeVersion"])
    predecessor = result.get(registry["predecessorVersion"])
    if not active or active["state"] != "active":
        raise ValueError("active toolchain mismatch")
    if not predecessor or predecessor["state"] != "compatibility":
        raise ValueError("predecessor toolchain mismatch")
    if registry["activeVersion"] == registry["predecessorVersion"]:
        raise ValueError("toolchain lineage overlap")
    return result


def validate_rollback_authorization(payload: dict[str, Any]) -> None:
    validate_source(payload)
    if payload["authorizationId"] != "rollback-1.9.0-to-1.8.0-prod-v1":
        raise ValueError("rollback authorization id mismatch")
    if payload["fromVersion"] != "1.9.0" or payload["toVersion"] != "1.8.0":
        raise ValueError("rollback lineage mismatch")
    if payload["maxUses"] != 1 or payload["notBeforeSequence"] > payload["notAfterSequence"]:
        raise ValueError("invalid rollback authorization window")
    if not HEX64.fullmatch(payload["reasonSha256"]):
        raise ValueError("invalid rollback reason digest")


def validate_envelope(
    envelope: dict[str, Any], key_id: str, public_key: Path, validator: Callable[[dict[str, Any]], Any], verify_signature: bool
) -> dict[str, Any]:
    payload = envelope["payload"]
    if envelope["keyId"] != key_id:
        raise ValueError("signing key mismatch")
    if envelope["payloadSha256"] != sha256_json(payload):
        raise ValueError("signed payload digest mismatch")
    validator(payload)
    if verify_signature:
        verify_ed25519(public_key, payload, envelope["signatureBase64"])
    return payload


def load_registries(bundle: dict[str, Any], verify_signatures: bool = True):
    runner = validate_envelope(bundle["signedRunnerRegistry"], "p1-a20-runner-registrar-v1", FIXTURE / "runner-registrar-public-key.pem", validate_runner_registry, verify_signatures)
    toolchain = validate_envelope(bundle["signedToolchainRegistry"], "p1-a20-toolchain-registrar-v1", FIXTURE / "toolchain-registrar-public-key.pem", validate_toolchain_registry, verify_signatures)
    authorizations: dict[str, dict[str, Any]] = {}
    for envelope in bundle["signedRollbackAuthorizations"]:
        payload = validate_envelope(envelope, "p1-a20-rollback-authority-v1", FIXTURE / "rollback-authority-public-key.pem", validate_rollback_authorization, verify_signatures)
        if payload["authorizationId"] in authorizations:
            raise ValueError("duplicate rollback authorization")
        authorizations[payload["authorizationId"]] = payload
    return runner, toolchain, authorizations
