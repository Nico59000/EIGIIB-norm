#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from eigiib_p1_a15_common import (
    ConformanceError,
    RELEASE_NAME,
    RELEASE_TAG,
    REPOSITORY,
    SOURCE_A14_COMMIT,
    canonical_json_bytes,
    load_json,
    require,
    sha256_file,
    validate_fixture,
)


def gh_json(endpoint: str):
    process = subprocess.run(
        ["gh", "api", endpoint, "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10"],
        check=True,
        capture_output=True,
        env=os.environ,
    )
    return json.loads(process.stdout)


def gh_bytes(endpoint: str) -> bytes:
    process = subprocess.run(
        ["gh", "api", endpoint, "-H", "Accept: application/octet-stream", "-H", "X-GitHub-Api-Version: 2026-03-10"],
        check=True,
        capture_output=True,
        env=os.environ,
    )
    return process.stdout


def main() -> int:
    try:
        require(os.environ.get("GH_TOKEN") is not None, "GH_TOKEN is required")
        report = validate_fixture(ROOT)
        portable = report["portable"]
        release = gh_json(f"repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}")
        require(release.get("id") == portable["releaseId"], "gh release id changed")
        require(release.get("tag_name") == RELEASE_TAG, "gh release tag changed")
        require(release.get("name") == RELEASE_NAME, "gh release name changed")
        require(release.get("draft") is False and release.get("prerelease") is True, "gh release flags changed")
        require(release.get("immutable") == portable["immutable"], "gh immutable field changed")
        tag = gh_json(f"repos/{REPOSITORY}/git/ref/tags/{RELEASE_TAG}")
        require(tag["object"]["type"] == "commit" and tag["object"]["sha"] == SOURCE_A14_COMMIT, "gh tag target changed")
        expected_assets = {asset["name"]: asset for asset in portable["assets"]}
        require({asset["name"] for asset in release.get("assets", [])} == set(expected_assets), "gh asset set changed")
        for asset in release["assets"]:
            expected = expected_assets[asset["name"]]
            require(asset.get("id") == expected["id"], f"gh asset id changed for {asset['name']}")
            require(asset.get("size") == expected["size"], f"gh asset size changed for {asset['name']}")
            require(asset.get("digest") == expected["digest"], f"gh asset digest changed for {asset['name']}")
            authenticated = gh_bytes(f"repos/{REPOSITORY}/releases/assets/{asset['id']}")
            require("sha256:" + hashlib.sha256(authenticated).hexdigest() == expected["digest"], f"gh asset bytes changed for {asset['name']}")
            with urllib.request.urlopen(asset["browser_download_url"], timeout=60) as response:
                public = response.read()
            require(public == authenticated, f"gh/public bytes differ for {asset['name']}")
        result = {"route": "external-gh-cli", "portable": portable}
    except (ConformanceError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"P1-A15 gh route failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
