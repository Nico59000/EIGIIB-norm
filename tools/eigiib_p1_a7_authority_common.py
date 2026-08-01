"""Shared contracts for the P1-A7.7 authority freeze."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-P1-A7.7-1.0"
PROFILE = "full-corpus-authority-freeze-v1"
TOOL = "eigiib-p1-a7-authority-freeze"
TOOL_VERSION = "0.1.0"
ROOT_PREFIX = b"EIGIIB-P1-A7 authority-root v1\n"
CONTENT_PREFIX = b"EIGIIB-P1-A7 content-sha256-root v1\n"
ROUTES = ["reference-python-openssl", "independent-go-stdlib", "external-go-cose"]
PLATFORMS = ["ubuntu-24.04", "macos-15", "windows-2025"]


def strict_json_bytes(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label}: invalid UTF-8") from exc

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"{label}: duplicate JSON member {key!r}")
            out[key] = value
        return out

    try:
        return json.loads(text, object_pairs_hook=pairs_hook, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"{label}: non-finite JSON number {value}")))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label}: invalid JSON") from exc


def load_json(path: Path, label: str) -> Any:
    return strict_json_bytes(path.read_bytes(), label)


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()


def authority_root(entries: list[dict[str, str]]) -> str:
    h = hashlib.sha256(ROOT_PREFIX)
    for entry in sorted(entries, key=lambda item: item["path"]):
        h.update(entry["path"].encode("utf-8"))
        h.update(b"\0")
        h.update(entry["gitBlobSha1"].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def content_root(rows: list[dict[str, Any]]) -> str:
    h = hashlib.sha256(CONTENT_PREFIX)
    for row in sorted(rows, key=lambda item: item["path"]):
        h.update(row["path"].encode("utf-8"))
        h.update(b"\0")
        h.update(str(row["bytes"]).encode("ascii"))
        h.update(b"\0")
        h.update(row["sha256"].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def confined_file(root: Path, rel: str) -> Path:
    if not isinstance(rel, str) or not rel or rel.startswith(("/", "\\")) or "\\" in rel:
        raise ValueError(f"unsafe authority path: {rel!r}")
    parts = Path(rel).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe authority path: {rel!r}")
    resolved_root = root.resolve()
    path = (root / rel).resolve()
    if resolved_root not in path.parents:
        raise ValueError(f"authority path escapes repository: {rel}")
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"authority path is not a regular file: {rel}")
    return path
