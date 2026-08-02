#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OWNER = "nico59000"
REPOSITORY = "Nico59000/EIGIIB-norm"
SOURCE_COMMIT = "461412075d97d9b8a8202e89fc3a9da3b6743f1b"
SOURCE_RELEASE_ID = 363652216
SOURCE_RELEASE_TAG = "eigiib-p1-a15-live-fixture-v2"
REGISTRY = "ghcr.io"
REGISTRY_REPOSITORY = f"{OWNER}/eigiib-norm-p1-a16"
REGISTRY_TAG = "p1-a16-fixture-v1"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
ARTIFACT_TYPE = "application/vnd.eigiib.cross-registry-release-set.v1"
CONFIG_MEDIA_TYPE = "application/vnd.oci.empty.v1+json"

EXPECTED_ASSETS = {
    "eigiib-p1-a14-fixed-1.1.archive.txt": {
        "id": 498366947,
        "size": 190,
        "sha256": "14290ddd91cfcd07ba073424548568d0fc97cf8f0b6993cbc7ff5a3388268682",
        "mediaType": "application/vnd.eigiib.fixed-release.archive.v1+text",
    },
    "eigiib-p1-a14-fixed-1.1.descriptor.json": {
        "id": 498366952,
        "size": 776,
        "sha256": "762e8a347512baf53f50fec7e200d30b0ec4e9b77dd4a96a54ae89e57db686e1",
        "mediaType": "application/vnd.eigiib.fixed-release.descriptor.v1+json",
    },
    "eigiib-p1-a15-live-release-manifest.json": {
        "id": 498366956,
        "size": 1421,
        "sha256": "82e61dcf91be3cac21d93349e22829f27b1bdca057e813e584a1593c5a7d604b",
        "mediaType": "application/vnd.eigiib.github-release-manifest.v1+json",
    },
}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    expected: tuple[int, ...] = (200,),
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if body is not None and "Content-Length" not in (headers or {}):
        req.add_header("Content-Length", str(len(body)))
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            status = response.status
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            response_body = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = {k.lower(): v for k, v in exc.headers.items()}
        response_body = exc.read()
    if status not in expected:
        snippet = response_body[:500].decode("utf-8", "replace")
        raise RuntimeError(f"{method} {url} returned {status}, expected {expected}: {snippet}")
    return status, response_headers, response_body


def github_json(path: str, token: str) -> Any:
    _, _, body = request(
        "GET",
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "eigiib-p1-a16-probe",
        },
    )
    return json.loads(body)


def github_asset_bytes(asset_id: int, token: str) -> bytes:
    _, _, body = request(
        "GET",
        f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}",
        headers={
            "Accept": "application/octet-stream",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "eigiib-p1-a16-probe",
        },
    )
    return body


def public_release_asset_bytes(name: str) -> bytes:
    quoted = urllib.parse.quote(name)
    _, _, body = request(
        "GET",
        f"https://github.com/{REPOSITORY}/releases/download/{SOURCE_RELEASE_TAG}/{quoted}",
        headers={"User-Agent": "eigiib-p1-a16-probe"},
    )
    return body


def registry_token(scope: str, *, actor: str | None = None, token: str | None = None) -> str:
    query = urllib.parse.urlencode({"service": REGISTRY, "scope": scope})
    headers = {"User-Agent": "eigiib-p1-a16-probe"}
    if actor is not None and token is not None:
        basic = base64.b64encode(f"{actor}:{token}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {basic}"
    _, _, body = request("GET", f"https://{REGISTRY}/token?{query}", headers=headers)
    payload = json.loads(body)
    value = payload.get("token") or payload.get("access_token")
    if not isinstance(value, str) or not value:
        raise RuntimeError("registry token response did not contain a token")
    return value


def registry_headers(token: str, *, accept: str | None = None, content_type: str | None = None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "eigiib-p1-a16-probe",
    }
    if accept:
        headers["Accept"] = accept
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def append_query(url: str, key: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append((key, value))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


def upload_blob(data: bytes, media_type: str, token: str) -> dict[str, Any]:
    digest = f"sha256:{sha256_hex(data)}"
    base = f"https://{REGISTRY}/v2/{REGISTRY_REPOSITORY}"
    status, _, _ = request(
        "HEAD",
        f"{base}/blobs/{digest}",
        headers=registry_headers(token),
        expected=(200, 404),
    )
    if status == 404:
        _, start_headers, _ = request(
            "POST",
            f"{base}/blobs/uploads/",
            headers={**registry_headers(token), "Content-Length": "0"},
            body=b"",
            expected=(202,),
        )
        location = start_headers.get("location")
        if not location:
            raise RuntimeError("registry upload start omitted Location")
        upload_url = urllib.parse.urljoin(f"https://{REGISTRY}", location)
        upload_url = append_query(upload_url, "digest", digest)
        _, finish_headers, _ = request(
            "PUT",
            upload_url,
            headers=registry_headers(token, content_type="application/octet-stream"),
            body=data,
            expected=(201,),
        )
        returned = finish_headers.get("docker-content-digest")
        if returned and returned != digest:
            raise RuntimeError(f"registry returned blob digest {returned}, expected {digest}")
    _, head_headers, _ = request(
        "HEAD",
        f"{base}/blobs/{digest}",
        headers=registry_headers(token),
        expected=(200,),
    )
    if head_headers.get("docker-content-digest") not in (None, digest):
        raise RuntimeError("blob HEAD digest mismatch")
    if int(head_headers.get("content-length", "-1")) != len(data):
        raise RuntimeError("blob HEAD length mismatch")
    return {"mediaType": media_type, "digest": digest, "size": len(data)}


def get_manifest(reference: str, token: str) -> tuple[bytes, str, dict[str, str]]:
    _, headers, body = request(
        "GET",
        f"https://{REGISTRY}/v2/{REGISTRY_REPOSITORY}/manifests/{urllib.parse.quote(reference, safe=':')}",
        headers=registry_headers(token, accept=MANIFEST_MEDIA_TYPE),
    )
    computed = f"sha256:{sha256_hex(body)}"
    returned = headers.get("docker-content-digest")
    if returned and returned != computed:
        raise RuntimeError(f"manifest response digest mismatch: {returned} != {computed}")
    return body, computed, headers


def get_blob(digest: str, token: str) -> tuple[bytes, dict[str, str]]:
    _, headers, body = request(
        "GET",
        f"https://{REGISTRY}/v2/{REGISTRY_REPOSITORY}/blobs/{digest}",
        headers=registry_headers(token),
    )
    computed = f"sha256:{sha256_hex(body)}"
    if computed != digest:
        raise RuntimeError(f"blob body digest mismatch: {computed} != {digest}")
    returned = headers.get("docker-content-digest")
    if returned and returned != digest:
        raise RuntimeError(f"blob response digest mismatch: {returned} != {digest}")
    return body, headers


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    github_token = os.environ["GITHUB_TOKEN"]
    actor = os.environ["GITHUB_ACTOR"]

    release = github_json(f"/repos/{REPOSITORY}/releases/{SOURCE_RELEASE_ID}", github_token)
    if release.get("tag_name") != SOURCE_RELEASE_TAG:
        raise RuntimeError("source release tag mismatch")
    if release.get("draft") is not False or release.get("prerelease") is not True:
        raise RuntimeError("source release state mismatch")
    api_assets = {item["name"]: item for item in release.get("assets", [])}
    if set(api_assets) != set(EXPECTED_ASSETS):
        raise RuntimeError(f"source release asset set mismatch: {sorted(api_assets)}")

    source_bytes: dict[str, bytes] = {}
    source_observations: list[dict[str, Any]] = []
    for name in sorted(EXPECTED_ASSETS):
        expected = EXPECTED_ASSETS[name]
        metadata = api_assets[name]
        if metadata.get("id") != expected["id"]:
            raise RuntimeError(f"{name}: source asset id mismatch")
        if metadata.get("size") != expected["size"]:
            raise RuntimeError(f"{name}: source asset size mismatch")
        api_digest = metadata.get("digest")
        if api_digest not in (None, f"sha256:{expected['sha256']}"):
            raise RuntimeError(f"{name}: source API digest mismatch")
        authenticated = github_asset_bytes(expected["id"], github_token)
        public = public_release_asset_bytes(name)
        for label, data in (("authenticated", authenticated), ("public", public)):
            if len(data) != expected["size"]:
                raise RuntimeError(f"{name}: {label} source length mismatch")
            if sha256_hex(data) != expected["sha256"]:
                raise RuntimeError(f"{name}: {label} source digest mismatch")
        if authenticated != public:
            raise RuntimeError(f"{name}: authenticated and public source bytes differ")
        source_bytes[name] = authenticated
        source_observations.append(
            {
                "name": name,
                "assetId": expected["id"],
                "size": expected["size"],
                "sha256": expected["sha256"],
                "apiDigest": api_digest,
                "authenticatedDownloadSha256": sha256_hex(authenticated),
                "publicDownloadSha256": sha256_hex(public),
            }
        )

    write_scope = f"repository:{REGISTRY_REPOSITORY}:pull,push"
    auth_registry_token = registry_token(write_scope, actor=actor, token=github_token)

    config_bytes = b"{}"
    config_descriptor = upload_blob(config_bytes, CONFIG_MEDIA_TYPE, auth_registry_token)

    layers = []
    layer_by_name: dict[str, dict[str, Any]] = {}
    for name in sorted(source_bytes):
        descriptor = upload_blob(
            source_bytes[name],
            EXPECTED_ASSETS[name]["mediaType"],
            auth_registry_token,
        )
        descriptor["annotations"] = {"org.opencontainers.image.title": name}
        layers.append(descriptor)
        layer_by_name[name] = descriptor

    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": ARTIFACT_TYPE,
        "config": config_descriptor,
        "layers": layers,
        "annotations": {
            "org.opencontainers.image.source": f"https://github.com/{REPOSITORY}",
            "org.opencontainers.image.revision": SOURCE_COMMIT,
            "org.opencontainers.image.title": "EIGIIB P1-A16 external registry fixture",
            "org.opencontainers.image.description": "Exact P1-A15 GitHub Release assets republished as a closed OCI artifact set.",
            "org.opencontainers.image.version": REGISTRY_TAG,
        },
    }
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_digest = f"sha256:{sha256_hex(manifest_bytes)}"
    _, put_headers, _ = request(
        "PUT",
        f"https://{REGISTRY}/v2/{REGISTRY_REPOSITORY}/manifests/{REGISTRY_TAG}",
        headers=registry_headers(auth_registry_token, content_type=MANIFEST_MEDIA_TYPE),
        body=manifest_bytes,
        expected=(201,),
    )
    returned_manifest_digest = put_headers.get("docker-content-digest")
    if returned_manifest_digest and returned_manifest_digest != manifest_digest:
        raise RuntimeError("registry manifest PUT digest mismatch")

    auth_tag_body, auth_tag_digest, _ = get_manifest(REGISTRY_TAG, auth_registry_token)
    auth_digest_body, auth_digest_digest, _ = get_manifest(manifest_digest, auth_registry_token)
    if auth_tag_body != manifest_bytes or auth_digest_body != manifest_bytes:
        raise RuntimeError("authenticated manifest readback bytes differ")
    if auth_tag_digest != manifest_digest or auth_digest_digest != manifest_digest:
        raise RuntimeError("authenticated manifest readback digest differs")

    pull_scope = f"repository:{REGISTRY_REPOSITORY}:pull"
    public_registry_token = registry_token(pull_scope)
    public_tag_body, public_tag_digest, _ = get_manifest(REGISTRY_TAG, public_registry_token)
    public_digest_body, public_digest_digest, _ = get_manifest(manifest_digest, public_registry_token)
    if public_tag_body != manifest_bytes or public_digest_body != manifest_bytes:
        raise RuntimeError("public manifest readback bytes differ")
    if public_tag_digest != manifest_digest or public_digest_digest != manifest_digest:
        raise RuntimeError("public manifest readback digest differs")

    layer_observations = []
    for name in sorted(source_bytes):
        descriptor = layer_by_name[name]
        auth_blob, auth_headers = get_blob(descriptor["digest"], auth_registry_token)
        public_blob, public_headers = get_blob(descriptor["digest"], public_registry_token)
        if auth_blob != source_bytes[name] or public_blob != source_bytes[name]:
            raise RuntimeError(f"{name}: registry blob differs from GitHub Release asset")
        layer_observations.append(
            {
                "name": name,
                "mediaType": descriptor["mediaType"],
                "size": descriptor["size"],
                "digest": descriptor["digest"],
                "githubReleaseSha256": EXPECTED_ASSETS[name]["sha256"],
                "authenticatedRegistrySha256": sha256_hex(auth_blob),
                "publicRegistrySha256": sha256_hex(public_blob),
                "authenticatedRegistryContentDigest": auth_headers.get("docker-content-digest"),
                "publicRegistryContentDigest": public_headers.get("docker-content-digest"),
            }
        )

    _, _, tags_body = request(
        "GET",
        f"https://{REGISTRY}/v2/{REGISTRY_REPOSITORY}/tags/list",
        headers=registry_headers(public_registry_token),
    )
    tags = json.loads(tags_body).get("tags") or []
    if REGISTRY_TAG not in tags:
        raise RuntimeError("public tag listing does not contain the registered tag")

    evidence = {
        "standard": "EIGIIB-P1-A16",
        "capturedAt": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": {
            "repository": REPOSITORY,
            "commit": SOURCE_COMMIT,
            "releaseId": SOURCE_RELEASE_ID,
            "releaseTag": SOURCE_RELEASE_TAG,
            "assets": source_observations,
        },
        "registry": {
            "host": REGISTRY,
            "repository": REGISTRY_REPOSITORY,
            "tag": REGISTRY_TAG,
            "artifactType": ARTIFACT_TYPE,
            "manifestMediaType": MANIFEST_MEDIA_TYPE,
            "manifestDigest": manifest_digest,
            "manifestSize": len(manifest_bytes),
            "config": config_descriptor,
            "layers": layer_observations,
            "publicTagListing": sorted(tags),
        },
        "decisions": {
            "externalRegistryPublication": "conformant-for-named-ghcr-oci-repository-scope",
            "authenticatedRegistryReadback": "conformant",
            "publicRegistryReadback": "conformant",
            "crossRegistryDigestIdentity": "conformant-for-closed-three-asset-set",
            "tagToManifestBinding": "conformant-at-capture-time",
            "registryAdministrativeImmutability": "not-claimed",
            "durableRetention": "not-claimed",
            "productionAuthorization": "not-claimed",
            "universalInteroperability": "not-claimed",
        },
        "boundary": "named-ghcr-oci-publication-cross-registry-digest-readback-closure",
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
