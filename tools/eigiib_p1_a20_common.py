from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/p1-a20"
BOUNDARY = "registered-fixture-runner-admission-toolchain-succession-window-and-rollback-replay-closure"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def version_tuple(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError as exc:
        raise ValueError(f"invalid numeric version: {value}") from exc


def _index_unique(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        name = item.get(key)
        if not isinstance(name, str) or not name or name in result:
            raise ValueError(f"invalid or duplicate {key}")
        result[name] = item
    return result


def validate_registry(registry: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    required = {"registryId", "sequence", "authority", "runners", "toolchains", "succession", "currentEpoch"}
    if set(registry) != required:
        raise ValueError("registry fields differ")
    if registry["sequence"] != 1 or registry["currentEpoch"] < 1:
        raise ValueError("invalid registry epoch")
    runners = _index_unique(registry["runners"], "runnerId")
    toolchains = _index_unique(registry["toolchains"], "toolchainId")
    succession = _index_unique(registry["succession"], "toolchainId")
    for runner in runners.values():
        if runner["status"] != "active" or runner["admissionEpoch"] > registry["currentEpoch"]:
            raise ValueError("inactive or future runner")
        admitted = runner["admittedToolchains"]
        if admitted != sorted(set(admitted)):
            raise ValueError("admitted toolchains must be canonical")
        if any(item not in toolchains for item in admitted):
            raise ValueError("runner references unknown toolchain")
    for toolchain in toolchains.values():
        window = toolchain["compatibilityWindow"]
        if version_tuple(window["min"]) > version_tuple(window["max"]):
            raise ValueError("reversed compatibility window")
        predecessor = toolchain["predecessor"]
        if predecessor is not None and predecessor not in toolchains:
            raise ValueError("unknown predecessor")
    for item in succession.values():
        if item["from"] not in toolchains or item["rollbackTarget"] not in toolchains:
            raise ValueError("unknown succession target")
        if item["effectiveEpoch"] > item["compatibilityEndsEpoch"]:
            raise ValueError("invalid compatibility epoch window")
        if item["rollbackAllowedUntilEpoch"] > item["compatibilityEndsEpoch"]:
            raise ValueError("rollback exceeds compatibility window")
    return runners, toolchains, succession


def decide_route(registry: dict[str, Any], route: dict[str, Any]) -> tuple[str, str]:
    runners, toolchains, succession = validate_registry(registry)
    runner = runners.get(route["runnerId"])
    if runner is None:
        return "reject", "runner-not-registered"
    requested = route["requestedToolchains"]
    if set(requested) != set(runner["admittedToolchains"]):
        return "reject", "toolchain-set-not-admitted"
    rollback = route.get("rollback")
    if rollback is not None:
        succession_item = succession.get(rollback["toolchainId"])
        if succession_item is None or rollback["target"] != succession_item["rollbackTarget"]:
            return "reject", "rollback-target-not-authorized"
        if rollback["epoch"] > succession_item["rollbackAllowedUntilEpoch"]:
            return "reject", "rollback-window-expired"
    used_compatibility = False
    for toolchain_id, requested_version in requested.items():
        toolchain = toolchains[toolchain_id]
        window = toolchain["compatibilityWindow"]
        current = toolchain["version"]
        if current != "3.x" and requested_version == current:
            continue
        if not (version_tuple(window["min"]) <= version_tuple(requested_version) <= version_tuple(window["max"])):
            return "reject", "toolchain-version-outside-window"
        succession_item = succession.get(toolchain_id)
        if succession_item and registry["currentEpoch"] > succession_item["compatibilityEndsEpoch"]:
            return "reject", "compatibility-window-expired"
        used_compatibility = True
    if rollback is not None:
        return "accept", "authorized-rollback-within-window"
    if used_compatibility:
        return "accept", "registered-runner-within-compatibility-window"
    return "accept", "registered-runner-current-toolchain"


def validate_bundle(bundle: dict[str, Any]) -> list[dict[str, str]]:
    if set(bundle) != {"standard", "captureTime", "registry", "routes"}:
        raise ValueError("bundle fields differ")
    if bundle["standard"] != "EIGIIB-P1-A20-BUNDLE-1.0":
        raise ValueError("bundle standard differs")
    validate_registry(bundle["registry"])
    route_ids: set[str] = set()
    results: list[dict[str, str]] = []
    for route in bundle["routes"]:
        route_id = route["routeId"]
        if route_id in route_ids:
            raise ValueError("duplicate route id")
        route_ids.add(route_id)
        actual_decision, actual_reason = decide_route(bundle["registry"], route)
        if (route["decision"], route["reason"]) != (actual_decision, actual_reason):
            raise ValueError(f"route expectation differs: {route_id}")
        results.append({"routeId": route_id, "decision": actual_decision, "reason": actual_reason})
    return results


def build_report(bundle: dict[str, Any]) -> dict[str, Any]:
    results = validate_bundle(bundle)
    registry = bundle["registry"]
    return {
        "acceptedRouteCount": sum(item["decision"] == "accept" for item in results),
        "activeRunnerCount": sum(item["status"] == "active" for item in registry["runners"]),
        "boundary": BOUNDARY,
        "compatibilityWindowAcceptedCount": sum(item["reason"] == "registered-runner-within-compatibility-window" for item in results),
        "overallResult": "conformant",
        "registeredRunnerCount": len(registry["runners"]),
        "registryId": registry["registryId"],
        "registrySha256": hashlib.sha256(canonical_bytes(registry)).hexdigest(),
        "rejectedRouteCount": sum(item["decision"] == "reject" for item in results),
        "rollbackAcceptedCount": sum(item["reason"] == "authorized-rollback-within-window" for item in results),
        "standard": "EIGIIB-P1-A20-REPORT-1.0",
        "successionCount": len(registry["succession"]),
        "toolchainCount": len(registry["toolchains"]),
    }
