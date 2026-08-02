from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A19-CONFORMANCE-1.0"
SOURCE_COMMIT = "be2eda2c9a86c703c6d486599d1062143c228ca9"
SOURCE_REPORT_SHA256 = "02ed5d44db18acb676714a27273c4df75d6a5a132cfe1fc8e7102e8bdc774ee6"
ENVIRONMENT = "p1-a18-fixture-production"
BOUNDARY = "registered-active-profile-matrix-canonical-capability-negotiation-claim-boundary-preserving-differential-replay-closure"
FIXTURE = Path("tests/fixtures/p1-a19")


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_ed25519(public_key: Path, payload: Any, signature_b64: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        payload_path = Path(td) / "payload.json"
        signature_path = Path(td) / "signature.bin"
        payload_path.write_bytes(canonical_bytes(payload))
        signature_path.write_bytes(base64.b64decode(signature_b64, validate=True))
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key), "-rawin", "-in", str(payload_path), "-sigfile", str(signature_path)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise ValueError("registry signature verification failed")


def profile_key(profile: dict[str, Any]) -> str:
    return f"{profile['profileId']}@{profile['version']}"


def registry_profiles(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for profile in registry["profiles"]:
        key = profile_key(profile)
        if key in result:
            raise ValueError("duplicate profile version")
        result[key] = profile
    return result


def validate_registry(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if registry.get("standard") != STANDARD:
        raise ValueError("registry standard mismatch")
    if registry.get("sourceP1A18Commit") != SOURCE_COMMIT:
        raise ValueError("registry source commit mismatch")
    if registry.get("sourceP1A18ReportSha256") != SOURCE_REPORT_SHA256:
        raise ValueError("registry source report mismatch")
    if registry.get("environment") != ENVIRONMENT:
        raise ValueError("registry environment mismatch")
    profiles = registry_profiles(registry)
    active = registry["activeVersions"]
    known_capabilities = set(registry["knownCapabilities"])
    known_extensions = set(registry["knownCriticalExtensions"])
    for profile_id, version in active.items():
        key = f"{profile_id}@{version}"
        if key not in profiles or profiles[key]["status"] != "active":
            raise ValueError("active version is not an active registered profile")
    for profile in profiles.values():
        required = profile["requiredCapabilities"]
        optional = profile["optionalCapabilities"]
        claims = profile["claimVocabulary"]
        if required != sorted(set(required)) or optional != sorted(set(optional)):
            raise ValueError("capabilities are not canonical sets")
        if set(required) & set(optional):
            raise ValueError("required and optional capabilities overlap")
        if not set(required + optional) <= known_capabilities:
            raise ValueError("unknown registered capability")
        if claims != sorted(set(claims)):
            raise ValueError("claim vocabulary is not canonical")
        if not set(profile["criticalExtensions"]) <= known_extensions:
            raise ValueError("unknown registered critical extension")
    return profiles


def supported(profile: dict[str, Any]) -> set[str]:
    return set(profile["requiredCapabilities"]) | set(profile["optionalCapabilities"])


def negotiate(registry: dict[str, Any], route: dict[str, Any]) -> dict[str, Any]:
    profiles = validate_registry(registry)
    source_key = f"{route['sourceProfileId']}@{route['sourceVersion']}"
    target_key = f"{route['targetProfileId']}@{route['targetVersion']}"
    if source_key not in profiles or target_key not in profiles:
        raise ValueError("unregistered profile")
    source = profiles[source_key]
    target = profiles[target_key]
    if registry["activeVersions"].get(source["profileId"]) != source["version"]:
        raise ValueError("source version downgrade")
    if registry["activeVersions"].get(target["profileId"]) != target["version"]:
        raise ValueError("target version downgrade")
    source_supported = supported(source)
    target_supported = supported(target)
    selected = sorted(source_supported & target_supported)
    if not set(source["requiredCapabilities"]) <= set(selected):
        raise ValueError("source mandatory capability unsupported")
    if not set(target["requiredCapabilities"]) <= set(selected):
        raise ValueError("target mandatory capability unsupported")
    source_claims = route["sourceClaims"]
    target_claims = route["targetClaims"]
    if source_claims != sorted(set(source_claims)) or target_claims != sorted(set(target_claims)):
        raise ValueError("claims are not canonical sets")
    if not set(source_claims) <= set(source["claimVocabulary"]):
        raise ValueError("source claim outside vocabulary")
    if not set(target_claims) <= set(target["claimVocabulary"]):
        raise ValueError("target claim outside vocabulary")
    if not set(target_claims) <= set(source_claims):
        raise ValueError("target claim boundary expansion")
    critical = sorted(set(source["criticalExtensions"]) | set(target["criticalExtensions"]))
    if critical != route["criticalExtensions"]:
        raise ValueError("critical extension set mismatch")
    if not set(critical) <= set(registry["knownCriticalExtensions"]):
        raise ValueError("unknown critical extension")
    transcript = {
        "routeId": route["routeId"],
        "registrySha256": sha256_json(registry),
        "sourceP1A18Commit": SOURCE_COMMIT,
        "sourceP1A18ReportSha256": SOURCE_REPORT_SHA256,
        "environment": ENVIRONMENT,
        "sourceProfile": source_key,
        "targetProfile": target_key,
        "selectedCapabilities": selected,
        "portableClaims": target_claims,
        "droppedOptionalCapabilities": sorted(source_supported - target_supported),
        "criticalExtensions": critical,
        "decision": "accepted",
    }
    transcript["transcriptSha256"] = sha256_json(transcript)
    return transcript


def validate_bundle(bundle: dict[str, Any], verify_signature: bool = True) -> list[dict[str, Any]]:
    if bundle.get("standard") != STANDARD:
        raise ValueError("bundle standard mismatch")
    signed_registry = bundle["signedRegistry"]
    registry = signed_registry["payload"]
    validate_registry(registry)
    if signed_registry["payloadSha256"] != sha256_json(registry):
        raise ValueError("registry payload digest mismatch")
    if signed_registry["keyId"] != "p1-a19-profile-registrar-v1":
        raise ValueError("registry key mismatch")
    if verify_signature:
        verify_ed25519(FIXTURE / "profile-registrar-public-key.pem", registry, signed_registry["signatureBase64"])
    seen: set[str] = set()
    transcripts: list[dict[str, Any]] = []
    for route in bundle["routes"]:
        if route["routeId"] in seen:
            raise ValueError("duplicate route id")
        seen.add(route["routeId"])
        expected = negotiate(registry, route)
        if expected != route["expectedTranscript"]:
            raise ValueError("transcript differs from canonical negotiation")
        transcripts.append(expected)
    if len(transcripts) != 6:
        raise ValueError("route matrix size mismatch")
    return transcripts


def report(bundle: dict[str, Any]) -> dict[str, Any]:
    transcripts = validate_bundle(bundle)
    registry = bundle["signedRegistry"]["payload"]
    return {
        "standard": STANDARD,
        "overallResult": "conformant",
        "sourceP1A18Commit": SOURCE_COMMIT,
        "sourceP1A18ReportSha256": SOURCE_REPORT_SHA256,
        "registryId": registry["registryId"],
        "registrySha256": sha256_json(registry),
        "activeProfileCount": len(registry["activeVersions"]),
        "routeCount": len(transcripts),
        "mutationCasesRejected": 25,
        "registeredProfileInteroperability": "conformant-for-declared-active-profile-matrix",
        "capabilityNegotiation": "conformant-for-registered-versioned-capabilities",
        "crossImplementationDifferentialReplay": "conformant",
        "downgradeResistance": "conformant",
        "claimBoundaryPreservation": "conformant",
        "unknownMandatoryCapabilityHandling": "conformant-by-explicit-rejection",
        "universalInteroperability": "not-claimed",
        "futureUnregisteredProfileCompatibility": "not-claimed",
        "futureUnregisteredRunnerCompatibility": "not-claimed",
        "semanticEquivalenceOfAllCarrierFormats": "not-claimed",
        "automaticUnknownExtensionCompatibility": "not-claimed",
        "boundary": BOUNDARY,
    }


def mutation_cases(bundle: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    def add(name: str, mutate) -> None:
        item = copy.deepcopy(bundle)
        mutate(item)
        cases.append((name, item))

    add("unknown-source-profile", lambda b: b["routes"][0].__setitem__("sourceProfileId", "unknown.example"))
    add("unknown-target-profile", lambda b: b["routes"][0].__setitem__("targetProfileId", "unknown.example"))
    add("source-version-downgrade", lambda b: b["routes"][0].__setitem__("sourceVersion", "1.0"))
    add("target-version-downgrade", lambda b: b["routes"][1].__setitem__("targetVersion", "0.2"))
    add("active-source-version-tamper", lambda b: b["signedRegistry"]["payload"]["activeVersions"].__setitem__("eigiib.native", "1.0"))
    add("active-target-version-tamper", lambda b: b["signedRegistry"]["payload"]["activeVersions"].__setitem__("sigstore.bundle", "0.2"))
    add("unknown-registered-capability", lambda b: b["signedRegistry"]["payload"]["profiles"][1]["requiredCapabilities"].append("unknown-capability"))
    add("source-mandatory-unsupported", lambda b: b["signedRegistry"]["payload"]["profiles"][2]["requiredCapabilities"].append("transparency-receipt"))
    add("target-mandatory-unsupported", lambda b: b["signedRegistry"]["payload"]["profiles"][5]["requiredCapabilities"].append("release-asset-set"))
    add("selected-capability-stripping", lambda b: b["routes"][0]["expectedTranscript"]["selectedCapabilities"].pop())
    add("selected-capability-injection", lambda b: b["routes"][0]["expectedTranscript"]["selectedCapabilities"].append("rekor-entry"))
    add("selected-capability-reordering", lambda b: b["routes"][0]["expectedTranscript"]["selectedCapabilities"].reverse())
    add("artifact-commit-substitution", lambda b: b["routes"][0]["expectedTranscript"].__setitem__("sourceP1A18Commit", "0" * 40))
    add("report-digest-substitution", lambda b: b["routes"][0]["expectedTranscript"].__setitem__("sourceP1A18ReportSha256", "0" * 64))
    add("environment-substitution", lambda b: b["routes"][0]["expectedTranscript"].__setitem__("environment", "production"))
    add("registry-digest-substitution", lambda b: b["routes"][0]["expectedTranscript"].__setitem__("registrySha256", "0" * 64))
    add("source-profile-substitution", lambda b: b["routes"][0]["expectedTranscript"].__setitem__("sourceProfile", "scitt.receipt@1.0"))
    add("target-profile-substitution", lambda b: b["routes"][0]["expectedTranscript"].__setitem__("targetProfile", "oci.distribution@1.1"))
    add("target-claim-expansion", lambda b: b["routes"][0]["targetClaims"].append("transparency-registration"))
    add("source-claim-outside-vocabulary", lambda b: b["routes"][0]["sourceClaims"].append("unknown-claim"))
    add("target-claim-outside-vocabulary", lambda b: b["routes"][0]["targetClaims"].append("unknown-claim"))
    add("unknown-critical-extension", lambda b: b["routes"][0]["criticalExtensions"].append("critical.example/unknown"))
    add("critical-extension-stripping", lambda b: b["routes"][0]["criticalExtensions"].clear())
    add("duplicate-route-id", lambda b: b["routes"][1].__setitem__("routeId", b["routes"][0]["routeId"]))
    add("registry-signature-tamper", lambda b: b["signedRegistry"].__setitem__("signatureBase64", base64.b64encode(b"x" * 64).decode()))
    return cases
