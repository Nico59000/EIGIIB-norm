"""Shared deterministic carriers for P1-A8."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

POLICY_STANDARD = "EIGIIB-P1-A8-POLICY-1.0"
BUNDLE_STANDARD = "EIGIIB-P1-A8-BUNDLE-1.0"
RELEASE_STANDARD = "EIGIIB-P1-A8-RELEASE-1.0"
REPLAY_STANDARD = "EIGIIB-P1-A8-REPLAY-1.0"
PROFILE = "exact-ustar-source-distribution-v1"
REPLAY_PROFILE = "independent-publication-replay-v1"
TOOL_VERSION = "0.1.0"


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def strict_object(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"duplicate JSON member in {label}: {key}")
            out[key] = value
        return out

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob_sha1(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def ensure_ascii_path(path: str, label: str) -> None:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise ValueError(f"unsafe {label}: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe {label}: {path!r}")
    try:
        path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"non-ASCII {label}: {path!r}") from exc


def source_tree_root(entries: Iterable[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"EIGIIB-P1-A8 source-tree-root v1\n")
    for entry in sorted(entries, key=lambda item: item["path"]):
        carrier = (
            f"{entry['path']}\0{entry['mode']}\0{entry['bytes']}\0"
            f"{entry['sha256']}\0{entry['gitBlobSha1']}\n"
        ).encode("ascii")
        digest.update(carrier)
    return digest.hexdigest()


def validate_policy(policy: dict[str, Any]) -> None:
    expected = {
        "standard", "profile", "releaseId", "sourceCommit", "authorityRoot",
        "archiveRoot", "bundleName", "manifestName", "releaseName", "checksumName",
        "requiredPublishers", "requiredPlatforms", "claimBoundary",
    }
    if set(policy) != expected:
        raise ValueError("P1-A8 policy fields differ from contract")
    if policy["standard"] != POLICY_STANDARD or policy["profile"] != PROFILE:
        raise ValueError("P1-A8 policy constants differ")
    for field in ("releaseId", "archiveRoot", "bundleName", "manifestName", "releaseName", "checksumName"):
        value = policy[field]
        if not isinstance(value, str):
            raise ValueError(f"P1-A8 policy {field} must be a string")
        ensure_ascii_path(value, field)
        if "/" in value and field != "archiveRoot":
            raise ValueError(f"P1-A8 policy {field} must be a basename")
    source = policy["sourceCommit"]
    authority = policy["authorityRoot"]
    if not isinstance(source, str) or len(source) != 40 or any(ch not in "0123456789abcdef" for ch in source):
        raise ValueError("P1-A8 source commit is not a lowercase SHA-1")
    if not isinstance(authority, str) or len(authority) != 64 or any(ch not in "0123456789abcdef" for ch in authority):
        raise ValueError("P1-A8 authority root is not a lowercase SHA-256")
    publishers = policy["requiredPublishers"]
    platforms = policy["requiredPlatforms"]
    if publishers != ["reference-python-stdlib", "independent-go-stdlib"]:
        raise ValueError("P1-A8 required publishers differ")
    if platforms != ["ubuntu-24.04", "macos-15", "windows-2025"]:
        raise ValueError("P1-A8 required platforms differ")
    boundary = policy["claimBoundary"]
    if not isinstance(boundary, dict) or set(boundary) != {"doesNotImply"}:
        raise ValueError("P1-A8 claim boundary differs")
    if not isinstance(boundary["doesNotImply"], list) or not boundary["doesNotImply"]:
        raise ValueError("P1-A8 claim boundary must be non-empty")
