#!/usr/bin/env python3
"""Exact historical M0-A14 authority materialization and replay."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from eigiib_m0_a15_f1_canonical import bytes_digest, digest_hex, safe_repo_path

A14_HEAD = "5936ed072187cd7fe72db2c33119c8db92d06570"
A14_TREE = "8b77cadd56e5d51a08b94bbeee603d994ca7a5d2"
A14_FREEZE = "conformance/m0-a14-authority-freeze.json"
A14_REPLAY_TOOL = "tools/eigiib_m0_a14_replay.py"


def _git(root: Path, *args: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def _git_file(root: Path, commit: str, path: str) -> bytes:
    return _git(root, "show", f"{commit}:{path}", binary=True)  # type: ignore[return-value]


def verify_exact_a14_source(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    try:
        tree = _git(root, "rev-parse", f"{A14_HEAD}^{{tree}}")
        if tree != A14_TREE:
            errors.append("a14-source-tree-mismatch")
        freeze_raw = _git_file(root, A14_HEAD, A14_FREEZE)
        freeze = json.loads(freeze_raw.decode("utf-8"))
    except Exception:
        return None, ["a14-source-materialization-failed"]

    entries = freeze.get("authorities", []) if isinstance(freeze, dict) else []
    if freeze.get("authorityCount") != len(entries):
        errors.append("a14-source-freeze-count-mismatch")
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if len(paths) != len(entries) or len(paths) != len(set(paths)):
        errors.append("a14-source-freeze-path-inventory-invalid")
    if paths != sorted(paths):
        errors.append("a14-source-freeze-path-order-invalid")
    if A14_REPLAY_TOOL not in paths:
        errors.append("a14-replay-tool-not-frozen")
    for entry in entries:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not safe_repo_path(path):
            errors.append("a14-source-freeze-path-invalid")
            continue
        try:
            raw = _git_file(root, A14_HEAD, path)
        except Exception:
            errors.append("a14-source-authority-missing")
            continue
        if len(raw) != entry.get("bytes") or bytes_digest(raw) != entry.get("sha256"):
            errors.append("a14-source-authority-digest-mismatch")
    return ({"freeze": freeze, "freezeDigest": bytes_digest(freeze_raw)} if not errors else None), sorted(set(errors))


def verify_a14_replay(root: Path, case: Any) -> dict[str, Any]:
    source, errors = verify_exact_a14_source(root)
    if errors:
        return {
            "verified": False,
            "sourceHead": A14_HEAD,
            "sourceTree": A14_TREE,
            "errors": errors,
        }
    if not isinstance(case, dict):
        return {
            "verified": False,
            "sourceHead": A14_HEAD,
            "sourceTree": A14_TREE,
            "errors": ["a14-case-invalid"],
        }
    try:
        replay_raw = _git_file(root, A14_HEAD, A14_REPLAY_TOOL)
        with tempfile.TemporaryDirectory() as temporary:
            module_path = Path(temporary) / "eigiib_m0_a14_replay.py"
            module_path.write_bytes(replay_raw)
            spec = importlib.util.spec_from_file_location("eigiib_m0_a14_replay_exact", module_path)
            if spec is None or spec.loader is None:
                raise RuntimeError("historical-module-loader-unavailable")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            result = module.verify_case(case)
    except Exception as exc:
        return {
            "verified": False,
            "sourceHead": A14_HEAD,
            "sourceTree": A14_TREE,
            "errors": [f"a14-exact-replay-failed:{type(exc).__name__}"],
        }
    artifact = {
        "sourceHead": A14_HEAD,
        "sourceTree": A14_TREE,
        "sourceFreezeDigest": source["freezeDigest"],
        "caseDigest": digest_hex(case),
        "replayResult": result,
    }
    return {
        "verified": bool(result.get("verified")),
        **artifact,
        "replayDigest": digest_hex(artifact),
        "errors": list(result.get("errors", [])),
    }
