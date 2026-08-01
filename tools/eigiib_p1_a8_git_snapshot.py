"""Read an exact regular-file snapshot directly from a Git commit."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from eigiib_p1_a8_common import ensure_ascii_path, sha256_hex


def _run(command: list[str], root: Path) -> bytes:
    completed = subprocess.run(command, cwd=root, check=True, capture_output=True)
    return completed.stdout


def git_snapshot(root: Path, source_commit: str) -> list[dict[str, Any]]:
    subprocess.run(["git", "cat-file", "-e", f"{source_commit}^{{commit}}"], cwd=root, check=True)
    raw = _run(["git", "ls-tree", "-rz", "--full-tree", source_commit], root)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            meta, path_raw = record.split(b"\t", 1)
            mode_raw, type_raw, object_raw = meta.split(b" ", 2)
            path = path_raw.decode("ascii")
            mode = mode_raw.decode("ascii")
            object_id = object_raw.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Git tree record is not in the closed P1-A8 profile") from exc
        ensure_ascii_path(path, "Git path")
        if path in seen:
            raise ValueError(f"duplicate Git path: {path}")
        seen.add(path)
        if type_raw != b"blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"unsupported Git entry for distribution: {mode} {type_raw!r} {path}")
        data = _run(["git", "cat-file", "blob", object_id], root)
        entries.append({
            "path": path,
            "mode": "0755" if mode == "100755" else "0644",
            "bytes": len(data),
            "sha256": sha256_hex(data),
            "gitBlobSha1": object_id,
            "data": data,
        })
    entries.sort(key=lambda item: item["path"])
    return entries
