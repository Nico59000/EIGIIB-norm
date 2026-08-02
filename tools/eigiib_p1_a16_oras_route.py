#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

from eigiib_p1_a16_common import (
    EXPECTED_LAYERS,
    OCI_MANIFEST_DIGEST,
    OCI_MANIFEST_MEDIA_TYPE,
    REGISTRY_REFERENCE,
    REGISTRY_TAG,
    ROOT,
    sha256_bytes,
    validate_fixture,
    validate_manifest_bytes,
)


def run(*args: str, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args),
        check=True,
        capture_output=capture,
        text=False,
    )


def main() -> int:
    try:
        version = run("oras", "version").stdout.decode("utf-8", "replace")
        if "1.3.2" not in version:
            raise ValueError(f"unexpected ORAS version: {version.strip()}")
        expected = validate_fixture(ROOT)
        with tempfile.TemporaryDirectory(prefix="eigiib-p1-a16-oras-") as temp_dir:
            temp = pathlib.Path(temp_dir)
            tag_manifest_path = temp / "manifest-tag.json"
            digest_manifest_path = temp / "manifest-digest.json"
            run(
                "oras", "manifest", "fetch",
                "--media-type", OCI_MANIFEST_MEDIA_TYPE,
                "--output", str(tag_manifest_path),
                f"{REGISTRY_REFERENCE}:{REGISTRY_TAG}",
            )
            run(
                "oras", "manifest", "fetch",
                "--media-type", OCI_MANIFEST_MEDIA_TYPE,
                "--output", str(digest_manifest_path),
                f"{REGISTRY_REFERENCE}@{OCI_MANIFEST_DIGEST}",
            )
            tag_manifest = tag_manifest_path.read_bytes()
            digest_manifest = digest_manifest_path.read_bytes()
            fixture_manifest = (ROOT / "tests/fixtures/p1-a16/oci-manifest.json").read_bytes()
            if tag_manifest != fixture_manifest or digest_manifest != fixture_manifest:
                raise ValueError("ORAS manifest readback differs from fixture")
            validate_manifest_bytes(tag_manifest)
            live_layers = []
            for item in EXPECTED_LAYERS:
                blob_path = temp / item["name"]
                run(
                    "oras", "blob", "fetch",
                    "--output", str(blob_path),
                    f"{REGISTRY_REFERENCE}@{item['digest']}",
                )
                body = blob_path.read_bytes()
                if len(body) != item["size"]:
                    raise ValueError(f"{item['name']}: ORAS blob length mismatch")
                if "sha256:" + sha256_bytes(body) != item["digest"]:
                    raise ValueError(f"{item['name']}: ORAS blob digest mismatch")
                if body != (ROOT / item["sourcePath"]).read_bytes():
                    raise ValueError(f"{item['name']}: ORAS blob differs from source")
                live_layers.append({
                    "name": item["name"],
                    "mediaType": item["mediaType"],
                    "size": len(body),
                    "digest": "sha256:" + sha256_bytes(body),
                })
            tags_output = run(
                "oras", "repo", "tags", REGISTRY_REFERENCE, "--format", "json"
            ).stdout
            tags_value = json.loads(tags_output)
            if isinstance(tags_value, dict):
                tags = tags_value.get("tags") or []
            elif isinstance(tags_value, list):
                tags = tags_value
            else:
                raise ValueError("unexpected ORAS tag-list JSON")
            if REGISTRY_TAG not in tags:
                raise ValueError("ORAS public tag listing omitted registered tag")
        result = dict(expected)
        result["route"] = "external-oras-cli"
        result["layers"] = sorted(live_layers, key=lambda item: item["name"])
        result["publicTags"] = sorted(tags)
    except Exception as exc:
        print(f"P1-A16 ORAS route failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
