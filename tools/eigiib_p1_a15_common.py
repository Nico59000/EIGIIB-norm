from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests/fixtures/p1-a15"
A14_DIR = ROOT / "tests/fixtures/p1-a14"

SOURCE_A14_COMMIT = "586784811f1139349141728c6db966f7f54459a1"
SOURCE_A14_REPORT_SHA256 = "e5d42e1cac67bb2ab4d1013c6d86332139f508326cd6b34b19d164d747d9fcaa"
SOURCE_A14_CAPSULE_SHA256 = "7e157a0da1d5de8c35f15bd1bb72221343aab97395ffcd35a4f08de18312b798"
FIXED_ARCHIVE_SHA256 = "14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682"
FIXED_DESCRIPTOR_SHA256 = "762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1"
REPOSITORY = "Nico59000/EIGIIB-norm"
RELEASE_TAG = "eigiib-p1-a15-live-fixture-v2"
RELEASE_NAME = "EIGIIB P1-A15 canonical live fixture release"
API_VERSION = "2026-03-10"
BOUNDARY = "canonical-live-github-release-asset-identity-api-readback-closure"
EXPECTED_ASSETS = {
    "eigiib-p1-a14-fixed-1.1.archive.txt": FIXED_ARCHIVE_SHA256,
    "eigiib-p1-a14-fixed-1.1.descriptor.json": FIXED_DESCRIPTOR_SHA256,
    "eigiib-p1-a15-live-release-manifest.json": None,
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


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"cannot load strict JSON {path}: {exc}") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


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
    require(capsule.get("standard") == "EIGIIB-P1-A15-CAPSULE-1.0", "capsule standard mismatch")
    require(capsule.get("algorithm") == "Ed25519", "capsule algorithm mismatch")
    expected_key_id = "sha256:" + spki_sha256(public_key_path)
    require(capsule.get("keyId") == expected_key_id, "capsule key id mismatch")
    try:
        payload_bytes = base64.b64decode(capsule["payload"], validate=True)
        signature = base64.b64decode(capsule["signature"], validate=True)
    except Exception as exc:
        raise ConformanceError("invalid capsule base64") from exc
    with tempfile.TemporaryDirectory(prefix="eigiib-p1-a15-") as temp_dir:
        temp = pathlib.Path(temp_dir)
        payload_path = temp / "payload.bin"
        signature_path = temp / "signature.bin"
        payload_path.write_bytes(payload_bytes)
        signature_path.write_bytes(signature)
        process = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(payload_path),
                "-sigfile",
                str(signature_path),
            ],
            capture_output=True,
        )
    require(process.returncode == 0, "capsule signature invalid")
    try:
        payload = json.loads(payload_bytes, object_pairs_hook=_reject_duplicates)
    except json.JSONDecodeError as exc:
        raise ConformanceError("capsule payload is not strict JSON") from exc
    require(canonical_json_bytes(payload) == payload_bytes, "capsule payload is not canonical JSON")
    return payload


def validate_manifest(manifest: dict[str, Any], evidence: dict[str, Any]) -> None:
    require(manifest.get("standard") == "EIGIIB-P1-A15-LIVE-RELEASE-1.0", "manifest standard mismatch")
    require(manifest.get("profile") == "canonical-live-github-release-v1", "manifest profile mismatch")
    require(manifest.get("repository") == REPOSITORY, "manifest repository mismatch")
    require(manifest.get("release_tag") == RELEASE_TAG, "manifest release tag mismatch")
    require(manifest.get("release_name") == RELEASE_NAME, "manifest release name mismatch")
    require(manifest.get("target_commit_sha") == SOURCE_A14_COMMIT, "manifest target commit mismatch")
    require(manifest.get("source_p1_a14_commit") == SOURCE_A14_COMMIT, "manifest A14 commit mismatch")
    require(manifest.get("source_p1_a14_report_sha256") == SOURCE_A14_REPORT_SHA256, "manifest A14 report mismatch")
    require(manifest.get("source_p1_a14_capsule_sha256") == SOURCE_A14_CAPSULE_SHA256, "manifest A14 capsule mismatch")
    require(manifest.get("fixed_release_archive_sha256") == FIXED_ARCHIVE_SHA256, "manifest archive mismatch")
    require(manifest.get("fixed_release_descriptor_sha256") == FIXED_DESCRIPTOR_SHA256, "manifest descriptor mismatch")
    release = evidence["release"]
    require(manifest.get("release_id") == release["id"], "manifest release id mismatch")
    entries = manifest.get("assets")
    require(isinstance(entries, list) and len(entries) == 2, "manifest source asset set mismatch")
    observed = {entry["name"]: entry for entry in entries}
    require(set(observed) == set(EXPECTED_ASSETS) - {"eigiib-p1-a15-live-release-manifest.json"}, "manifest source asset names mismatch")
    for name, expected_sha in EXPECTED_ASSETS.items():
        if expected_sha is None:
            continue
        entry = observed[name]
        require(entry.get("digest") == f"sha256:{expected_sha}", f"manifest digest mismatch for {name}")
        require(isinstance(entry.get("id"), int) and entry["id"] > 0, f"manifest asset id invalid for {name}")
        require(isinstance(entry.get("size"), int) and entry["size"] > 0, f"manifest asset size invalid for {name}")
    expected_boundary = {
        "release-publication-is-not-production-authorization",
        "digest-identity-is-not-platform-immutability-enforcement",
        "github-readback-is-not-external-registry-publication",
        "current-availability-is-not-durable-retention",
    }
    require(set(manifest.get("claim_boundary", [])) == expected_boundary, "manifest claim boundary mismatch")


def portable_projection(evidence: dict[str, Any], manifest_sha256: str) -> dict[str, Any]:
    release = evidence["release"]
    assets = evidence["assets"]
    projection_assets = []
    for asset in sorted(assets, key=lambda item: item["name"]):
        projection_assets.append(
            {
                "id": asset["id"],
                "name": asset["name"],
                "size": asset["size"],
                "digest": asset["api_digest"],
            }
        )
    return {
        "standard": "EIGIIB-P1-A15-PORTABLE-RESULT-1.0",
        "repository": evidence["repository"],
        "sourceP1A14Commit": evidence["source_p1_a14_commit"],
        "releaseId": release["id"],
        "releaseTag": release["tag_name"],
        "releaseName": release["name"],
        "peeledCommitSha": release["peeled_commit_sha"],
        "draft": release["draft"],
        "prerelease": release["prerelease"],
        "immutable": release.get("immutable"),
        "assets": projection_assets,
        "manifestSha256": manifest_sha256,
        "decisions": evidence["decisions"],
        "boundary": evidence["boundary"],
    }


def validate_evidence(evidence: dict[str, Any], manifest: dict[str, Any], manifest_sha256: str) -> dict[str, Any]:
    require(evidence.get("standard") == "EIGIIB-P1-A15-LIVE-READBACK-EVIDENCE-1.0", "evidence standard mismatch")
    require(evidence.get("profile") == "canonical-live-github-release-authenticated-public-readback-v1", "evidence profile mismatch")
    require(evidence.get("api_version") == API_VERSION, "evidence API version mismatch")
    require(evidence.get("repository") == REPOSITORY, "evidence repository mismatch")
    require(evidence.get("source_p1_a14_commit") == SOURCE_A14_COMMIT, "evidence A14 commit mismatch")
    require(evidence.get("source_p1_a14_report_sha256") == SOURCE_A14_REPORT_SHA256, "evidence A14 report mismatch")
    require(evidence.get("source_p1_a14_capsule_sha256") == SOURCE_A14_CAPSULE_SHA256, "evidence A14 capsule mismatch")
    require(evidence.get("boundary") == BOUNDARY, "evidence boundary mismatch")
    release = evidence.get("release")
    require(isinstance(release, dict), "release evidence missing")
    require(isinstance(release.get("id"), int) and release["id"] > 0, "release id invalid")
    require(release.get("tag_name") == RELEASE_TAG, "release tag mismatch")
    require(release.get("name") == RELEASE_NAME, "release name mismatch")
    require(release.get("draft") is False, "release must be published")
    require(release.get("prerelease") is True, "fixture must remain prerelease")
    require(release.get("peeled_commit_sha") == SOURCE_A14_COMMIT, "tag does not peel to exact A14 commit")
    require(release.get("tag_object_sha") == SOURCE_A14_COMMIT, "lightweight tag object mismatch")
    require(release.get("tag_object_type") == "commit", "fixture tag must be a lightweight commit tag")
    require(release.get("immutable") in (True, False, None), "invalid immutable field")
    require(isinstance(release.get("published_at"), str) and release["published_at"], "published_at missing")
    assets = evidence.get("assets")
    require(isinstance(assets, list) and len(assets) == 3, "evidence asset set must contain exactly three assets")
    observed = {asset["name"]: asset for asset in assets}
    require(set(observed) == set(EXPECTED_ASSETS), "evidence asset names mismatch")
    for name, expected_sha in EXPECTED_ASSETS.items():
        asset = observed[name]
        require(asset.get("state") == "uploaded", f"asset state mismatch for {name}")
        require(isinstance(asset.get("id"), int) and asset["id"] > 0, f"asset id invalid for {name}")
        require(isinstance(asset.get("size"), int) and asset["size"] > 0, f"asset size invalid for {name}")
        digest = asset.get("api_digest")
        require(isinstance(digest, str) and digest.startswith("sha256:"), f"asset API digest invalid for {name}")
        digest_sha = digest.split(":", 1)[1]
        require(asset.get("authenticated_download_sha256") == digest_sha, f"authenticated digest mismatch for {name}")
        require(asset.get("public_download_sha256") == digest_sha, f"public digest mismatch for {name}")
        if expected_sha is not None:
            require(digest_sha == expected_sha, f"fixed expected digest mismatch for {name}")
        else:
            require(digest_sha == manifest_sha256, "manifest asset digest mismatch")
    decisions = evidence.get("decisions")
    require(isinstance(decisions, dict), "decisions missing")
    require(decisions.get("exact_p1_a14_binding") == "conformant", "A14 binding decision mismatch")
    require(decisions.get("live_github_release") == "conformant-for-exact-public-fixture-release-scope", "live release decision mismatch")
    require(decisions.get("closed_asset_set") == "conformant", "closed asset decision mismatch")
    require(decisions.get("asset_identity") == "conformant-for-api-digest-and-authenticated-public-download-scope", "asset identity decision mismatch")
    require(decisions.get("api_readback") == "conformant-for-authenticated-and-public-github-rest-scope", "API readback decision mismatch")
    require(decisions.get("production_release_authorization") == "not-claimed", "production authorization boundary mismatch")
    require(decisions.get("external_registry_publication") == "not-claimed", "registry boundary mismatch")
    require(decisions.get("durable_retention") == "not-claimed", "retention boundary mismatch")
    require(decisions.get("overall_result") == "conformant", "overall result mismatch")
    immutable = release.get("immutable")
    expected_immutable = (
        "conformant-for-github-immutable-release-scope"
        if immutable is True
        else "not-enabled-for-this-release"
        if immutable is False
        else "not-established"
    )
    require(decisions.get("platform_immutability_enforcement") == expected_immutable, "immutable decision mismatch")
    validate_manifest(manifest, evidence)
    return portable_projection(evidence, manifest_sha256)


def validate_fixture(root: pathlib.Path = ROOT) -> dict[str, Any]:
    fixture_dir = root / "tests/fixtures/p1-a15"
    a14_dir = root / "tests/fixtures/p1-a14"
    evidence_path = fixture_dir / "live-release-evidence.json"
    manifest_path = fixture_dir / "live-release-manifest.json"
    capsule_path = fixture_dir / "capsule.json"
    public_key_path = fixture_dir / "evidence-registrar-public-key.pem"
    evidence = load_json(evidence_path)
    manifest = load_json(manifest_path)
    manifest_sha256 = sha256_file(manifest_path)
    projection = validate_evidence(evidence, manifest, manifest_sha256)
    require(sha256_file(a14_dir / "expected-report.json") == SOURCE_A14_REPORT_SHA256, "actual A14 report hash mismatch")
    require(sha256_file(a14_dir / "capsule.json") == SOURCE_A14_CAPSULE_SHA256, "actual A14 capsule hash mismatch")
    require(sha256_file(a14_dir / "fixed-release-archive.txt") == FIXED_ARCHIVE_SHA256, "actual A14 archive hash mismatch")
    require(sha256_file(a14_dir / "fixed-release-descriptor.json") == FIXED_DESCRIPTOR_SHA256, "actual A14 descriptor hash mismatch")
    capsule_payload = verify_signed_capsule(capsule_path, public_key_path)
    require(capsule_payload.get("sequence") == 50, "capsule sequence mismatch")
    require(capsule_payload.get("sourceP1A14Commit") == SOURCE_A14_COMMIT, "capsule A14 commit mismatch")
    require(capsule_payload.get("evidenceSha256") == sha256_file(evidence_path), "capsule evidence hash mismatch")
    require(capsule_payload.get("manifestSha256") == manifest_sha256, "capsule manifest hash mismatch")
    require(capsule_payload.get("releaseId") == projection["releaseId"], "capsule release id mismatch")
    require(capsule_payload.get("releaseTag") == RELEASE_TAG, "capsule release tag mismatch")
    require(capsule_payload.get("boundary") == BOUNDARY, "capsule boundary mismatch")
    report = {
        "standard": "EIGIIB-P1-A15-REPORT-1.0",
        "sourceP1A14Commit": SOURCE_A14_COMMIT,
        "sourceP1A14ReportSha256": SOURCE_A14_REPORT_SHA256,
        "sourceP1A14CapsuleSha256": SOURCE_A14_CAPSULE_SHA256,
        "evidenceSha256": sha256_file(evidence_path),
        "manifestSha256": manifest_sha256,
        "capsuleSha256": sha256_file(capsule_path),
        "evidenceRegistrarSpkiSha256": spki_sha256(public_key_path),
        "portable": projection,
        "overallResult": "conformant",
    }
    return report


def api_request_json(url: str, token: str | None = None) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "eigiib-p1-a15-live-readback",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            value = json.loads(response.read())
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"live API readback failed for {url}: {exc}") from exc
    require(isinstance(value, dict), "live API result must be an object")
    return value


def download_bytes(url: str, token: str | None = None, api_asset: bool = False) -> bytes:
    headers = {"User-Agent": "eigiib-p1-a15-live-readback"}
    if api_asset:
        headers["Accept"] = "application/octet-stream"
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = API_VERSION
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except urllib.error.URLError as exc:
        raise ConformanceError(f"live download failed for {url}: {exc}") from exc


def live_projection(token: str | None = None) -> dict[str, Any]:
    fixture_evidence = load_json(FIXTURE_DIR / "live-release-evidence.json")
    manifest_sha256 = sha256_file(FIXTURE_DIR / "live-release-manifest.json")
    release_url = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}"
    release = api_request_json(release_url, token)
    require(release.get("id") == fixture_evidence["release"]["id"], "live release id changed")
    require(release.get("tag_name") == RELEASE_TAG, "live release tag changed")
    require(release.get("name") == RELEASE_NAME, "live release name changed")
    require(release.get("draft") is False and release.get("prerelease") is True, "live release flags changed")
    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == 3, "live asset set changed")
    live_assets = []
    for asset in sorted(assets, key=lambda item: item["name"]):
        digest = asset.get("digest")
        require(isinstance(digest, str) and digest.startswith("sha256:"), "live asset digest missing")
        public_bytes = download_bytes(asset["browser_download_url"])
        require(sha256_bytes(public_bytes) == digest.split(":", 1)[1], f"live public digest mismatch for {asset['name']}")
        if token:
            auth_bytes = download_bytes(asset["url"], token, api_asset=True)
            require(auth_bytes == public_bytes, f"authenticated/public bytes differ for {asset['name']}")
        live_assets.append({"id": asset["id"], "name": asset["name"], "size": asset["size"], "digest": digest})
    projection = portable_projection(fixture_evidence, manifest_sha256)
    require(live_assets == projection["assets"], "live asset projection differs from frozen evidence")
    require(release.get("immutable") == projection["immutable"], "live immutable field changed")
    return projection
