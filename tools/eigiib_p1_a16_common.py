from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import tempfile
import urllib.parse
import urllib.request
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests/fixtures/p1-a16"

SOURCE_A15_COMMIT = "461412075d97d9b8a8202e89fc3a9da3b6743f1b"
SOURCE_A15_REPORT_SHA256 = "89a4fcda3b0ad8a90803b58a53c2eba485a5f8afbfe99d7c370c5b6ab248403c"
SOURCE_A15_CAPSULE_SHA256 = "f954f2fbdab0f20f18ad4d3c03a5cd23156b40e0c5c6f21bcbb2aeb776de7785"
SOURCE_RELEASE_ID = 363652216
SOURCE_RELEASE_TAG = "eigiib-p1-a15-live-fixture-v2"
REGISTRY_HOST = "ghcr.io"
REGISTRY_REPOSITORY = "nico59000/eigiib-norm-p1-a16"
REGISTRY_TAG = "p1-a16-fixture-v1"
REGISTRY_REFERENCE = f"{REGISTRY_HOST}/{REGISTRY_REPOSITORY}"
OCI_MANIFEST_DIGEST = "sha256:cf0f9735cc1711cd45a242ac3c1c27185b738ae353f491cd58a5746dbf8a66d8"
OCI_MANIFEST_SIZE = 1493
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_ARTIFACT_TYPE = "application/vnd.eigiib.cross-registry-release-set.v1"
OCI_CONFIG_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
BOUNDARY = "named-ghcr-oci-publication-cross-registry-digest-readback-closure"

EXPECTED_LAYERS = [
    {
        "name": "eigiib-p1-a14-fixed-1.1.archive.txt",
        "mediaType": "application/vnd.eigiib.fixed-release.archive.v1+text",
        "size": 190,
        "digest": "sha256:14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682",
        "sourcePath": "tests/fixtures/p1-a14/fixed-release-archive.txt",
    },
    {
        "name": "eigiib-p1-a14-fixed-1.1.descriptor.json",
        "mediaType": "application/vnd.eigiib.fixed-release.descriptor.v1+json",
        "size": 776,
        "digest": "sha256:762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1",
        "sourcePath": "tests/fixtures/p1-a14/fixed-release-descriptor.json",
    },
    {
        "name": "eigiib-p1-a15-live-release-manifest.json",
        "mediaType": "application/vnd.eigiib.github-release-manifest.v1+json",
        "size": 1421,
        "digest": "sha256:82e61dcf91be3cac21d93349e22829f27b1bdca057e813e584a1593c5a7d604b",
        "sourcePath": "tests/fixtures/p1-a15/live-release-manifest.json",
    },
]

EXPECTED_DECISIONS = {
    "authenticatedRegistryReadback": "conformant",
    "crossRegistryDigestIdentity": "conformant-for-closed-three-asset-set",
    "durableRetention": "not-claimed",
    "externalRegistryPublication": "conformant-for-named-ghcr-oci-repository-scope",
    "productionAuthorization": "not-claimed",
    "publicRegistryReadback": "conformant",
    "registryAdministrativeImmutability": "not-claimed",
    "tagToManifestBinding": "conformant-at-capture-time",
    "universalInteroperability": "not-claimed",
}


class ConformanceError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConformanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_bytes(data: bytes) -> Any:
    try:
        return json.loads(data, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"invalid strict JSON: {exc}") from exc


def load_json(path: pathlib.Path) -> Any:
    try:
        return strict_json_bytes(path.read_bytes())
    except OSError as exc:
        raise ConformanceError(f"cannot read {path}: {exc}") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    require(set(value) == expected, f"{label} keys mismatch: {sorted(set(value) ^ expected)}")


def spki_sha256(public_key_path: pathlib.Path) -> str:
    process = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key_path), "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    return sha256_bytes(process.stdout)


def verify_signed_capsule(capsule_path: pathlib.Path, public_key_path: pathlib.Path) -> dict[str, Any]:
    capsule = load_json(capsule_path)
    require(isinstance(capsule, dict), "capsule must be an object")
    exact_keys(capsule, {"standard", "algorithm", "keyId", "payload", "signature"}, "capsule")
    require(capsule["standard"] == "EIGIIB-P1-A16-CAPSULE-1.0", "capsule standard mismatch")
    require(capsule["algorithm"] == "Ed25519", "capsule algorithm mismatch")
    require(capsule["keyId"] == "sha256:" + spki_sha256(public_key_path), "capsule key id mismatch")
    try:
        payload_bytes = base64.b64decode(capsule["payload"], validate=True)
        signature = base64.b64decode(capsule["signature"], validate=True)
    except Exception as exc:
        raise ConformanceError("invalid capsule base64") from exc
    with tempfile.TemporaryDirectory(prefix="eigiib-p1-a16-") as temp_dir:
        temp = pathlib.Path(temp_dir)
        payload_path = temp / "payload.bin"
        signature_path = temp / "signature.bin"
        payload_path.write_bytes(payload_bytes)
        signature_path.write_bytes(signature)
        process = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin",
                "-inkey", str(public_key_path), "-rawin",
                "-in", str(payload_path), "-sigfile", str(signature_path),
            ],
            capture_output=True,
        )
    require(process.returncode == 0, "capsule signature invalid")
    payload = strict_json_bytes(payload_bytes)
    require(isinstance(payload, dict), "capsule payload must be an object")
    require(canonical_json_bytes(payload) == payload_bytes, "capsule payload is not canonical JSON")
    exact_keys(
        payload,
        {
            "standard", "sequence", "sourceP1A15Commit", "sourceP1A15ReportSha256",
            "sourceP1A15CapsuleSha256", "sourceReleaseId", "sourceReleaseTag",
            "evidenceSha256", "ociManifestSha256", "registry", "registryTag", "boundary"
        },
        "capsule payload",
    )
    require(payload["standard"] == "EIGIIB-P1-A16-CAPSULE-PAYLOAD-1.0", "capsule payload standard mismatch")
    require(payload["sequence"] == 60, "capsule sequence mismatch")
    require(payload["sourceP1A15Commit"] == SOURCE_A15_COMMIT, "capsule source commit mismatch")
    require(payload["sourceP1A15ReportSha256"] == SOURCE_A15_REPORT_SHA256, "capsule source report mismatch")
    require(payload["sourceP1A15CapsuleSha256"] == SOURCE_A15_CAPSULE_SHA256, "capsule source capsule mismatch")
    require(payload["sourceReleaseId"] == SOURCE_RELEASE_ID, "capsule source release id mismatch")
    require(payload["sourceReleaseTag"] == SOURCE_RELEASE_TAG, "capsule source release tag mismatch")
    require(payload["evidenceSha256"] == sha256_file(FIXTURE_DIR / "live-registry-evidence.json"), "capsule evidence mismatch")
    require(payload["ociManifestSha256"] == sha256_file(FIXTURE_DIR / "oci-manifest.json"), "capsule manifest mismatch")
    require(payload["registry"] == f"{REGISTRY_HOST}/{REGISTRY_REPOSITORY}", "capsule registry mismatch")
    require(payload["registryTag"] == REGISTRY_TAG, "capsule registry tag mismatch")
    require(payload["boundary"] == BOUNDARY, "capsule boundary mismatch")
    return payload


def expected_manifest() -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "artifactType": OCI_ARTIFACT_TYPE,
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": OCI_CONFIG_DIGEST,
            "size": 2,
        },
        "layers": [
            {
                "mediaType": item["mediaType"],
                "digest": item["digest"],
                "size": item["size"],
                "annotations": {"org.opencontainers.image.title": item["name"]},
            }
            for item in EXPECTED_LAYERS
        ],
        "annotations": {
            "org.opencontainers.image.source": "https://github.com/Nico59000/EIGIIB-norm",
            "org.opencontainers.image.revision": SOURCE_A15_COMMIT,
            "org.opencontainers.image.title": "EIGIIB P1-A16 external registry fixture",
            "org.opencontainers.image.description": "Exact P1-A15 GitHub Release assets republished as a closed OCI artifact set.",
            "org.opencontainers.image.version": REGISTRY_TAG,
        },
    }


def validate_manifest_bytes(data: bytes) -> dict[str, Any]:
    require(len(data) == OCI_MANIFEST_SIZE, "OCI manifest size mismatch")
    require("sha256:" + sha256_bytes(data) == OCI_MANIFEST_DIGEST, "OCI manifest digest mismatch")
    manifest = strict_json_bytes(data)
    require(manifest == expected_manifest(), "OCI manifest content mismatch")
    return manifest


def validate_source_files(root: pathlib.Path = ROOT) -> None:
    require(sha256_file(root / "tests/fixtures/p1-a15/expected-report.json") == SOURCE_A15_REPORT_SHA256, "actual A15 report hash mismatch")
    require(sha256_file(root / "tests/fixtures/p1-a15/capsule.json") == SOURCE_A15_CAPSULE_SHA256, "actual A15 capsule hash mismatch")
    for item in EXPECTED_LAYERS:
        path = root / item["sourcePath"]
        require(path.stat().st_size == item["size"], f"source size mismatch for {item['name']}")
        require("sha256:" + sha256_file(path) == item["digest"], f"source digest mismatch for {item['name']}")


def validate_evidence(evidence: dict[str, Any], root: pathlib.Path = ROOT) -> None:
    require(isinstance(evidence, dict), "evidence must be an object")
    exact_keys(evidence, {"standard", "capturedAt", "source", "registry", "decisions", "boundary"}, "evidence")
    require(evidence["standard"] == "EIGIIB-P1-A16", "evidence standard mismatch")
    require(evidence["capturedAt"] == "2026-08-02T00:23:59Z", "capture time mismatch")
    require(evidence["boundary"] == BOUNDARY, "evidence boundary mismatch")
    require(evidence["decisions"] == EXPECTED_DECISIONS, "evidence decisions mismatch")

    source = evidence["source"]
    require(isinstance(source, dict), "source evidence missing")
    exact_keys(source, {"repository", "commit", "releaseId", "releaseTag", "assets"}, "source evidence")
    require(source["repository"] == "Nico59000/EIGIIB-norm", "source repository mismatch")
    require(source["commit"] == SOURCE_A15_COMMIT, "source commit mismatch")
    require(source["releaseId"] == SOURCE_RELEASE_ID, "source release id mismatch")
    require(source["releaseTag"] == SOURCE_RELEASE_TAG, "source release tag mismatch")
    assets = source["assets"]
    require(isinstance(assets, list) and len(assets) == 3, "source asset set mismatch")
    source_by_name = {item["name"]: item for item in assets}
    require(set(source_by_name) == {item["name"] for item in EXPECTED_LAYERS}, "source asset names mismatch")
    expected_ids = {
        "eigiib-p1-a14-fixed-1.1.archive.txt": 498366947,
        "eigiib-p1-a14-fixed-1.1.descriptor.json": 498366952,
        "eigiib-p1-a15-live-release-manifest.json": 498366956,
    }
    for item in EXPECTED_LAYERS:
        observed = source_by_name[item["name"]]
        exact_keys(
            observed,
            {
                "apiDigest", "assetId", "authenticatedDownloadSha256", "name",
                "publicDownloadSha256", "sha256", "size"
            },
            f"source asset {item['name']}",
        )
        digest_hex = item["digest"].split(":", 1)[1]
        require(observed["assetId"] == expected_ids[item["name"]], f"source asset id mismatch for {item['name']}")
        require(observed["size"] == item["size"], f"source asset size mismatch for {item['name']}")
        require(observed["apiDigest"] == item["digest"], f"source API digest mismatch for {item['name']}")
        require(observed["sha256"] == digest_hex, f"source digest mismatch for {item['name']}")
        require(observed["authenticatedDownloadSha256"] == digest_hex, f"source authenticated digest mismatch for {item['name']}")
        require(observed["publicDownloadSha256"] == digest_hex, f"source public digest mismatch for {item['name']}")

    registry = evidence["registry"]
    require(isinstance(registry, dict), "registry evidence missing")
    exact_keys(
        registry,
        {
            "host", "repository", "tag", "artifactType", "manifestMediaType",
            "manifestDigest", "manifestSize", "config", "layers", "publicTagListing"
        },
        "registry evidence",
    )
    require(registry["host"] == REGISTRY_HOST, "registry host mismatch")
    require(registry["repository"] == REGISTRY_REPOSITORY, "registry repository mismatch")
    require(registry["tag"] == REGISTRY_TAG, "registry tag mismatch")
    require(registry["artifactType"] == OCI_ARTIFACT_TYPE, "artifact type mismatch")
    require(registry["manifestMediaType"] == OCI_MANIFEST_MEDIA_TYPE, "manifest media type mismatch")
    require(registry["manifestDigest"] == OCI_MANIFEST_DIGEST, "manifest digest evidence mismatch")
    require(registry["manifestSize"] == OCI_MANIFEST_SIZE, "manifest size evidence mismatch")
    require(registry["config"] == {
        "digest": OCI_CONFIG_DIGEST,
        "mediaType": "application/vnd.oci.empty.v1+json",
        "size": 2,
    }, "config descriptor mismatch")
    require(registry["publicTagListing"] == [REGISTRY_TAG], "public tag listing mismatch")
    layers = registry["layers"]
    require(isinstance(layers, list) and len(layers) == 3, "registry layer set mismatch")
    layer_by_name = {item["name"]: item for item in layers}
    require(set(layer_by_name) == {item["name"] for item in EXPECTED_LAYERS}, "registry layer names mismatch")
    for item in EXPECTED_LAYERS:
        observed = layer_by_name[item["name"]]
        exact_keys(
            observed,
            {
                "authenticatedRegistryContentDigest", "authenticatedRegistrySha256", "digest",
                "githubReleaseSha256", "mediaType", "name", "publicRegistryContentDigest",
                "publicRegistrySha256", "size"
            },
            f"registry layer {item['name']}",
        )
        digest_hex = item["digest"].split(":", 1)[1]
        require(observed["digest"] == item["digest"], f"registry layer digest mismatch for {item['name']}")
        require(observed["mediaType"] == item["mediaType"], f"registry layer media type mismatch for {item['name']}")
        require(observed["size"] == item["size"], f"registry layer size mismatch for {item['name']}")
        require(observed["githubReleaseSha256"] == digest_hex, f"cross-registry source mismatch for {item['name']}")
        require(observed["authenticatedRegistrySha256"] == digest_hex, f"authenticated registry mismatch for {item['name']}")
        require(observed["publicRegistrySha256"] == digest_hex, f"public registry mismatch for {item['name']}")
        require(observed["authenticatedRegistryContentDigest"] is None, "unexpected authenticated blob digest header")
        require(observed["publicRegistryContentDigest"] is None, "unexpected public blob digest header")

    validate_manifest_bytes((root / "tests/fixtures/p1-a16/oci-manifest.json").read_bytes())
    validate_source_files(root)


def portable_projection(evidence: dict[str, Any]) -> dict[str, Any]:
    registry = evidence["registry"]
    layers = []
    for layer in sorted(registry["layers"], key=lambda item: item["name"]):
        layers.append({
            "name": layer["name"],
            "mediaType": layer["mediaType"],
            "size": layer["size"],
            "digest": layer["digest"],
        })
    return {
        "standard": "EIGIIB-P1-A16-PORTABLE-RESULT-1.0",
        "sourceP1A15Commit": SOURCE_A15_COMMIT,
        "sourceReleaseId": SOURCE_RELEASE_ID,
        "sourceReleaseTag": SOURCE_RELEASE_TAG,
        "registryHost": REGISTRY_HOST,
        "registryRepository": REGISTRY_REPOSITORY,
        "registryTag": REGISTRY_TAG,
        "manifestMediaType": registry["manifestMediaType"],
        "artifactType": registry["artifactType"],
        "manifestDigest": registry["manifestDigest"],
        "manifestSize": registry["manifestSize"],
        "config": registry["config"],
        "layers": layers,
        "publicTags": registry["publicTagListing"],
        "decisions": evidence["decisions"],
        "boundary": evidence["boundary"],
    }


def validate_fixture(root: pathlib.Path = ROOT) -> dict[str, Any]:
    evidence_path = root / "tests/fixtures/p1-a16/live-registry-evidence.json"
    evidence = load_json(evidence_path)
    validate_evidence(evidence, root)
    capsule_path = root / "tests/fixtures/p1-a16/capsule.json"
    public_key_path = root / "tests/fixtures/p1-a16/evidence-registrar-public-key.pem"
    payload = verify_signed_capsule(capsule_path, public_key_path)
    require(payload["evidenceSha256"] == sha256_file(evidence_path), "capsule evidence hash mismatch")
    require(payload["ociManifestSha256"] == sha256_file(root / "tests/fixtures/p1-a16/oci-manifest.json"), "capsule OCI manifest hash mismatch")
    return portable_projection(evidence)


def public_registry_token() -> str:
    query = urllib.parse.urlencode({
        "service": REGISTRY_HOST,
        "scope": f"repository:{REGISTRY_REPOSITORY}:pull",
    })
    req = urllib.request.Request(
        f"https://{REGISTRY_HOST}/token?{query}",
        headers={"User-Agent": "eigiib-p1-a16-readback"},
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        payload = strict_json_bytes(response.read())
    token = payload.get("token") or payload.get("access_token")
    require(isinstance(token, str) and token, "public registry token missing")
    return token


def registry_get(path: str, token: str, *, accept: str | None = None) -> tuple[bytes, dict[str, str]]:
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "eigiib-p1-a16-readback",
    }
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(f"https://{REGISTRY_HOST}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read(), {key.lower(): value for key, value in response.headers.items()}


def live_public_route(root: pathlib.Path = ROOT, route: str = "reference-python-urllib") -> dict[str, Any]:
    expected = validate_fixture(root)
    token = public_registry_token()
    base = f"/v2/{REGISTRY_REPOSITORY}"
    tag_manifest, tag_headers = registry_get(
        f"{base}/manifests/{REGISTRY_TAG}",
        token,
        accept=OCI_MANIFEST_MEDIA_TYPE,
    )
    digest_manifest, digest_headers = registry_get(
        f"{base}/manifests/{OCI_MANIFEST_DIGEST}",
        token,
        accept=OCI_MANIFEST_MEDIA_TYPE,
    )
    fixture_manifest = (root / "tests/fixtures/p1-a16/oci-manifest.json").read_bytes()
    require(tag_manifest == fixture_manifest, "live tag manifest differs from fixture")
    require(digest_manifest == fixture_manifest, "live digest manifest differs from fixture")
    for headers in (tag_headers, digest_headers):
        returned = headers.get("docker-content-digest")
        require(returned in (None, OCI_MANIFEST_DIGEST), "live manifest response digest mismatch")
    validate_manifest_bytes(tag_manifest)
    live_layers = []
    for item in EXPECTED_LAYERS:
        body, headers = registry_get(f"{base}/blobs/{item['digest']}", token)
        require(len(body) == item["size"], f"live layer size mismatch for {item['name']}")
        require("sha256:" + sha256_bytes(body) == item["digest"], f"live layer digest mismatch for {item['name']}")
        require(body == (root / item["sourcePath"]).read_bytes(), f"live layer bytes differ from source for {item['name']}")
        returned = headers.get("docker-content-digest")
        require(returned in (None, item["digest"]), f"live blob response digest mismatch for {item['name']}")
        live_layers.append({
            "name": item["name"],
            "mediaType": item["mediaType"],
            "size": len(body),
            "digest": "sha256:" + sha256_bytes(body),
        })
    tags_body, _ = registry_get(f"{base}/tags/list", token)
    tags = strict_json_bytes(tags_body).get("tags") or []
    require(REGISTRY_TAG in tags, "live public tag is absent")
    result = dict(expected)
    result["route"] = route
    result["layers"] = sorted(live_layers, key=lambda item: item["name"])
    result["publicTags"] = sorted(tags)
    return result
