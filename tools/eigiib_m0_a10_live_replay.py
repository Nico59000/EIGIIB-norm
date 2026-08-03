#!/usr/bin/env python3
"""Live M0-A10 readback and exact restore replay."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPOSITORY = "Nico59000/EIGIIB-norm"
RELEASE_TAG = "eigiib-m0-a10-e16-stable-v1"
RELEASE_ID = 364532554
OCI_REPOSITORY = "nico59000/eigiib-norm-p1-a16"
OCI_TAG = "m0-a10-e16-stable-v1"
OCI_DIGEST = "sha256:8d3fba5d596d668ea000a768d524e35003e08f95162b633d8af7922449b13c88"
EXPECTED = {
    "eigiib-e16-1.0-stable-bundle.tar.gz": (985664, "96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"),
    "eigiib-e16-1.0-stable-bundle-manifest.json": (1058, "25c04438df49d7261cf9814142dc0dd575b278ba65e05bc244b13b35d16407a9"),
    "eigiib-e16-1.0-stable-bundle-manifest.sig": (64, "90925a270871949faf2079eb74321200b0f2eae873a4bc22c9cfac6ccee0a4e4"),
    "eigiib-m0-a10-publisher-ed25519-public.pem": (113, "27116e2e7771cc300b2d2acbc205fd0992c23b8ebec4fe5b5b58023f0aa5382e"),
}
MEDIA = "application/vnd.oci.image.manifest.v1+json"


class ReplayError(RuntimeError):
    pass


def _request(url: str, *, headers: dict[str, str] | None = None, timeout: int = 90) -> tuple[bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            return response.read(), {k.lower(): v for k, v in response.headers.items()}
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ReplayError(f"request unavailable: {url}: {exc}") from exc


def _json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    payload, _ = _request(url, headers=headers)
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ReplayError(f"invalid JSON from {url}") from exc
    if not isinstance(value, dict):
        raise ReplayError(f"JSON object required from {url}")
    return value


def _identity(data: bytes) -> dict[str, Any]:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _check_object(name: str, data: bytes) -> dict[str, Any]:
    observed = _identity(data)
    expected = EXPECTED[name]
    if observed != {"bytes": expected[0], "sha256": expected[1]}:
        raise ReplayError(f"identity mismatch for {name}: {observed}")
    return observed


def _github_release(token: str | None) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    api = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}"
    base_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    public = _json(api, headers=base_headers)
    auth_headers = dict(base_headers)
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"
    authenticated = _json(api, headers=auth_headers)
    for doc in (public, authenticated):
        if doc.get("id") != RELEASE_ID or doc.get("tag_name") != RELEASE_TAG:
            raise ReplayError("GitHub Release identity mismatch")
        if doc.get("draft") is not False or doc.get("prerelease") is not True:
            raise ReplayError("GitHub Release state mismatch")
    if public.get("id") != authenticated.get("id"):
        raise ReplayError("GitHub authenticated/public API disagreement")
    public_assets = {item["name"]: item for item in public.get("assets", [])}
    auth_assets = {item["name"]: item for item in authenticated.get("assets", [])}
    if set(public_assets) != set(EXPECTED) or set(auth_assets) != set(EXPECTED):
        raise ReplayError("GitHub Release asset set mismatch")

    routes: dict[str, dict[str, Any]] = {"release-public": {}, "release-auth": {}}
    for name in sorted(EXPECTED):
        public_bytes, _ = _request(public_assets[name]["browser_download_url"])
        routes["release-public"][name] = _check_object(name, public_bytes)
        asset_url = auth_assets[name]["url"]
        download_headers = {
            "Accept": "application/octet-stream",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            download_headers["Authorization"] = f"Bearer {token}"
        auth_bytes, _ = _request(asset_url, headers=download_headers)
        routes["release-auth"][name] = _check_object(name, auth_bytes)
        if auth_bytes != public_bytes:
            raise ReplayError(f"GitHub authenticated/public bytes differ for {name}")
    return public, routes


def _registry_token(*, token: str | None, actor: str | None) -> str:
    query = urllib.parse.urlencode({
        "service": "ghcr.io",
        "scope": f"repository:{OCI_REPOSITORY}:pull",
    })
    headers = {}
    if token and actor:
        raw = f"{actor}:{token}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    doc = _json(f"https://ghcr.io/token?{query}", headers=headers)
    value = doc.get("token") or doc.get("access_token")
    if not isinstance(value, str):
        raise ReplayError("GHCR token missing")
    return value


def _oci_route(token: str) -> tuple[bytes, dict[str, dict[str, Any]]]:
    headers = {"Authorization": f"Bearer {token}", "Accept": MEDIA}
    tag_url = f"https://ghcr.io/v2/{OCI_REPOSITORY}/manifests/{OCI_TAG}"
    digest_url = f"https://ghcr.io/v2/{OCI_REPOSITORY}/manifests/{OCI_DIGEST}"
    manifest_tag, tag_headers = _request(tag_url, headers=headers)
    manifest_digest, _ = _request(digest_url, headers=headers)
    if manifest_tag != manifest_digest:
        raise ReplayError("OCI tag/digest manifest mismatch")
    if "sha256:" + hashlib.sha256(manifest_tag).hexdigest() != OCI_DIGEST:
        raise ReplayError("OCI manifest digest mismatch")
    header_digest = tag_headers.get("docker-content-digest")
    if header_digest and header_digest != OCI_DIGEST:
        raise ReplayError("OCI digest header mismatch")
    manifest = json.loads(manifest_tag)
    layers = manifest.get("layers", [])
    if len(layers) != 4:
        raise ReplayError("OCI layer count mismatch")
    route: dict[str, dict[str, Any]] = {}
    seen = set()
    for layer in layers:
        title = layer.get("annotations", {}).get("org.opencontainers.image.title")
        if title not in EXPECTED:
            raise ReplayError(f"unknown OCI layer title: {title}")
        digest = layer.get("digest")
        blob_url = f"https://ghcr.io/v2/{OCI_REPOSITORY}/blobs/{digest}"
        data, _ = _request(blob_url, headers={"Authorization": f"Bearer {token}"})
        route[title] = _check_object(title, data)
        if digest != "sha256:" + route[title]["sha256"]:
            raise ReplayError(f"OCI descriptor mismatch for {title}")
        if layer.get("size") != route[title]["bytes"]:
            raise ReplayError(f"OCI size mismatch for {title}")
        seen.add(title)
    if seen != set(EXPECTED):
        raise ReplayError("OCI layer set mismatch")
    return manifest_tag, route


def replay(root: Path) -> dict[str, Any]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    actor = os.environ.get("GITHUB_ACTOR")
    release, release_routes = _github_release(token)
    public_token = _registry_token(token=None, actor=None)
    auth_token = _registry_token(token=token, actor=actor) if token and actor else public_token
    public_manifest, public_route = _oci_route(public_token)
    auth_manifest, auth_route = _oci_route(auth_token)
    if public_manifest != auth_manifest:
        raise ReplayError("OCI authenticated/public manifest mismatch")
    local_manifest = (root / "conformance/m0-a10-oci-manifest.json").read_bytes()
    if local_manifest != public_manifest:
        raise ReplayError("captured OCI manifest differs from live manifest")
    routes = {
        **release_routes,
        "oci-public": public_route,
        "oci-auth": auth_route,
    }
    canonical = next(iter(routes.values()))
    for route_name, route in routes.items():
        if route != canonical:
            raise ReplayError(f"route projection mismatch: {route_name}")
    return {
        "standard": "EIGIIB-M0-A10-LIVE-REPLAY-1.0",
        "status": "bounded-external-publication-and-readback-verified",
        "github_release_id": release["id"],
        "github_release_tag": release["tag_name"],
        "oci_manifest_digest": OCI_DIGEST,
        "route_count": len(routes),
        "restored_object_observation_count": len(routes) * len(EXPECTED),
        "cross_channel_byte_identity": "conformant",
        "future_availability": "not-evaluated",
        "indefinite_durability": "not-evaluated",
        "routes": routes,
        "findings": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = replay(Path(args.root).resolve())
        code = 0
    except ReplayError as exc:
        report = {
            "standard": "EIGIIB-M0-A10-LIVE-REPLAY-1.0",
            "status": "unavailable",
            "findings": [str(exc)],
        }
        code = 1
    payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    if args.json or not args.output:
        sys.stdout.write(payload)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
